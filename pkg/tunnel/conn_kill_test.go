package tunnel

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jumpserver-dev/sdk-go/model"
	"github.com/jumpserver-dev/sdk-go/service"

	"lion/pkg/config"
	"lion/pkg/guacd"
	"lion/pkg/session"
)

// fakeGuacd answers the guacd handshake, then streams nop until the tunnel
// side closes the TCP connection. closed is closed when that happens.
type fakeGuacd struct {
	addr   string
	closed chan struct{}
}

func startFakeGuacd(t *testing.T) *fakeGuacd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeGuacd{addr: ln.Addr().String(), closed: make(chan struct{})}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer close(f.closed)
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			ins, err := reader.ReadString(';')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(ins, "6.select,"):
				_, _ = conn.Write([]byte("4.args,13.VERSION_1_3_0;"))
			case strings.HasPrefix(ins, "7.connect,"):
				_, _ = conn.Write([]byte("5.ready,9.fake-uuid;"))
				go func() {
					for {
						if _, err := conn.Write([]byte("3.nop;")); err != nil {
							return
						}
						time.Sleep(20 * time.Millisecond)
					}
				}()
			}
		}
	}()
	return f
}

type testConn struct {
	conn      *Connection
	runDone   chan error
	guacd     *fakeGuacd
	client    *websocket.Conn
	clientErr chan error
}

// newTestConn wires a real websocket (httptest) and a fake guacd through
// Connection.Run exactly as GuacamoleTunnelServer.Connect does.
func newTestConn(t *testing.T, id string, jms *service.JMService, cache GuaTunnelCache) *testConn {
	t.Helper()
	fake := startFakeGuacd(t)
	tc := &testConn{runDone: make(chan error, 1), guacd: fake, clientErr: make(chan error, 1)}
	ready := make(chan *Connection, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer ws.Close()
		conf := guacd.NewConfiguration()
		conf.Protocol = "rdp"
		tunnel, err := guacd.NewTunnel(fake.addr, conf, guacd.NewClientInformation())
		if err != nil {
			t.Errorf("guacd tunnel: %v", err)
			return
		}
		defer tunnel.Close()
		sess := session.TunnelSession{
			ID:             id,
			Protocol:       "rdp",
			User:           &model.User{ID: "u1", Name: "alice", Username: "alice"},
			TerminalConfig: &model.TerminalConfig{MaxIdleTime: 30, MaxSessionTime: 1},
			ExpireInfo:     model.ExpireInfo(time.Now().Add(time.Hour).Unix()),
		}
		conn := Connection{
			guacdAddr:          fake.addr,
			Sess:               &sess,
			guacdTunnel:        tunnel,
			Service:            &session.Server{JmsService: jms},
			ws:                 ws,
			done:               make(chan struct{}),
			Cache:              cache,
			meta:               &MetaShareUserMessage{ShareId: "u1", UserId: "u1", User: "alice", Primary: true},
			currentOnlineUsers: make(map[string]MetaShareUserMessage),
		}
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = r
		ready <- &conn
		tc.runDone <- conn.Run(ctx)
	}))
	t.Cleanup(srv.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	tc.client = client
	tc.conn = <-ready
	return tc
}

// readUntilClosed drains the client websocket; it reports the first error
// instruction seen and sends the read error once the server closes.
func (tc *testConn) readUntilClosed(t *testing.T, sawError *bool, sawErrorCode *string) {
	t.Helper()
	go func() {
		for {
			_, msg, err := tc.client.ReadMessage()
			if err != nil {
				tc.clientErr <- err
				return
			}
			if strings.HasPrefix(string(msg), "5.error,") {
				*sawError = true
				parts := strings.Split(strings.TrimSuffix(string(msg), ";"), ",")
				*sawErrorCode = parts[len(parts)-1]
			}
		}
	}()
}

func setupJMS(t *testing.T) *service.JMService {
	t.Helper()
	gin.SetMode(gin.TestMode)
	if config.GlobalConfig == nil {
		config.GlobalConfig = &config.Config{}
	}
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(core.Close)
	jms, err := service.NewAuthJMService(service.JMSCoreHost(core.URL), service.JMSAccessKey("k", "s"))
	if err != nil {
		t.Fatal(err)
	}
	return jms
}

func waitClosed(t *testing.T, what string, ch <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(within):
		t.Fatalf("%s not closed within %s", what, within)
		return nil
	}
}

func TestKillSessionTaskClosesTransportsServerSide(t *testing.T) {
	jms := setupJMS(t)
	tc := newTestConn(t, "s-kill", jms, NewLocalTunnelLocalCache())
	var sawError bool
	var code string
	tc.readUntilClosed(t, &sawError, &code)
	time.Sleep(100 * time.Millisecond) // stream is flowing

	task := model.TerminalTask{Name: model.TaskKillSession, Args: "s-kill",
		Kwargs: model.TaskKwargs{TerminatedBy: "admin"}}
	if err := tc.conn.HandleTask(&task); err != nil {
		t.Fatal(err)
	}
	// Run must return by itself: no client cooperation.
	if err := waitClosed(t, "Run", tc.runDone, 2*time.Second); err != nil {
		t.Fatalf("Run returned err %v, want nil", err)
	}
	waitClosed(t, "client websocket", tc.clientErr, 2*time.Second)
	select {
	case <-tc.guacd.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("guacd connection not closed within 2s")
	}
	if !sawError || code != "4.1005" {
		t.Fatalf("client saw error=%v code=%q, want 1005 before close", sawError, code)
	}
}

func TestKillIsIdempotentAndSafeAfterRunReturned(t *testing.T) {
	jms := setupJMS(t)
	tc := newTestConn(t, "s-idem", jms, NewLocalTunnelLocalCache())
	var sawError bool
	var code string
	tc.readUntilClosed(t, &sawError, &code)

	tc.conn.Kill()
	tc.conn.Kill()
	waitClosed(t, "Run", tc.runDone, 2*time.Second)
	waitClosed(t, "client websocket", tc.clientErr, 2*time.Second)
	// A second kill task after teardown must not panic (double close / nil ws write).
	task := model.TerminalTask{Name: model.TaskKillSession, Args: "s-idem"}
	if err := tc.conn.HandleTask(&task); err != nil {
		t.Fatal(err)
	}
	tc.conn.Kill()
}

func TestKillRacingClientDisconnectDoesNotPanic(t *testing.T) {
	jms := setupJMS(t)
	tc := newTestConn(t, "s-race", jms, NewLocalTunnelLocalCache())
	var sawError bool
	var code string
	tc.readUntilClosed(t, &sawError, &code)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tc.conn.Kill()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = tc.client.Close()
	}()
	wg.Wait()
	waitClosed(t, "Run", tc.runDone, 2*time.Second)
	select {
	case <-tc.guacd.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("guacd connection not closed within 2s")
	}
}

func TestKillOnlyAffectsTargetSession(t *testing.T) {
	jms := setupJMS(t)
	cache := NewLocalTunnelLocalCache()
	victim := newTestConn(t, "s-victim", jms, cache)
	other := newTestConn(t, "s-other", jms, cache)
	var vErr, oErr bool
	var vCode, oCode string
	victim.readUntilClosed(t, &vErr, &vCode)
	other.readUntilClosed(t, &oErr, &oCode)

	task := model.TerminalTask{Name: model.TaskKillSession, Args: "s-victim"}
	if err := victim.conn.HandleTask(&task); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "victim Run", victim.runDone, 2*time.Second)
	waitClosed(t, "victim websocket", victim.clientErr, 2*time.Second)

	select {
	case err := <-other.runDone:
		t.Fatalf("unrelated session Run returned (%v) after killing another session", err)
	case err := <-other.clientErr:
		t.Fatalf("unrelated client websocket closed (%v) after killing another session", err)
	case <-other.guacd.closed:
		t.Fatal("unrelated guacd connection closed after killing another session")
	case <-time.After(500 * time.Millisecond):
	}
	if oErr {
		t.Fatalf("unrelated client received error instruction %s", oCode)
	}
	// Now tear the other one down cleanly exactly once.
	other.conn.Kill()
	waitClosed(t, "other Run", other.runDone, 2*time.Second)
	select {
	case err := <-other.runDone:
		t.Fatalf("Run returned twice: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestKillOnZeroValueConnectionDoesNotPanic(t *testing.T) {
	var c Connection
	c.Kill()
	c.Kill()
}
