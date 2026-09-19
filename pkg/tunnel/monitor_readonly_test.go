package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jumpserver-dev/sdk-go/model"

	"lion/pkg/guacd"
)

// fakeMonitorTunnel stands in for the joined guacd connection of a monitor.
// It records what the monitor wrote and streams nop until closed.
type fakeMonitorTunnel struct {
	mu      sync.Mutex
	written []string
	closed  chan struct{}
	once    sync.Once
}

func newFakeMonitorTunnel() *fakeMonitorTunnel {
	return &fakeMonitorTunnel{closed: make(chan struct{})}
}

func (f *fakeMonitorTunnel) UUID() string { return "fake-monitor-uuid" }

func (f *fakeMonitorTunnel) WriteAndFlush(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, string(p))
	return len(p), nil
}

func (f *fakeMonitorTunnel) ReadInstruction() (guacd.Instruction, error) {
	select {
	case <-f.closed:
		return guacd.Instruction{}, errors.New("guacd closed")
	case <-time.After(20 * time.Millisecond):
		return guacd.NewInstruction(guacd.InstructionClientNop), nil
	}
}

func (f *fakeMonitorTunnel) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeMonitorTunnel) opcodes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.written))
	for _, raw := range f.written {
		ins, err := guacd.ParseInstructionString(raw)
		if err != nil {
			out = append(out, "<unparsed>")
			continue
		}
		out = append(out, ins.Opcode)
	}
	return out
}

type monitorHarness struct {
	tunnel  *fakeMonitorTunnel
	client  *websocket.Conn
	runDone chan error
}

// newMonitorHarness runs MonitorCon.Run behind a real websocket exactly as
// GuacamoleTunnelServer.Monitor does, with the guacd side faked.
func newMonitorHarness(t *testing.T, readOnly bool) *monitorHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := &monitorHarness{tunnel: newFakeMonitorTunnel(), runDone: make(chan error, 1)}
	svc := &GuacamoleTunnelServer{Cache: &GuaTunnelCacheManager{GuaTunnelCache: NewLocalTunnelLocalCache()}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upGrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer ws.Close()
		con := MonitorCon{
			Id:          "s-monitor",
			guacdTunnel: h.tunnel,
			ws:          ws,
			Service:     svc,
			User:        &model.User{ID: "admin", Username: "admin"},
			readOnly:    readOnly,
		}
		h.runDone <- con.Run(context.Background())
	}))
	t.Cleanup(srv.Close)
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	h.client = client
	return h
}

func (h *monitorHarness) send(t *testing.T, ins string) {
	t.Helper()
	if err := h.client.WriteMessage(websocket.TextMessage, []byte(ins)); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyPassthroughAllowsOnlyKeepAlive(t *testing.T) {
	allowed := []string{guacd.InstructionClientSync, guacd.InstructionClientNop, guacd.InstructionStreamingAck}
	for _, op := range allowed {
		if !readOnlyPassthrough(op) {
			t.Errorf("%s must pass through a read-only monitor", op)
		}
	}
	blocked := []string{"key", "mouse", "size", "clipboard", "blob", "end", "put", "pipe", "audio", "disconnect", "argv", ""}
	for _, op := range blocked {
		if readOnlyPassthrough(op) {
			t.Errorf("%s must be dropped by a read-only monitor", op)
		}
	}
}

func TestReadOnlyMonitorDropsInputButKeepsSync(t *testing.T) {
	h := newMonitorHarness(t, true)
	// Drain server->client frames so writes never block.
	go func() {
		for {
			if _, _, err := h.client.ReadMessage(); err != nil {
				return
			}
		}
	}()
	h.send(t, "3.key,5.65515,1.1;")
	h.send(t, "5.mouse,3.100,3.100,1.1;")
	h.send(t, "4.size,4.1024,3.768;")
	h.send(t, "9.clipboard,1.0,10.text/plain;")
	h.send(t, "this is not an instruction")
	h.send(t, "4.sync,5.12345;")
	h.send(t, "3.ack,1.0,2.OK,1.0;")
	h.send(t, "3.nop;")

	// Keep-alives must arrive (poll: goroutine scheduling), input must never.
	deadline := time.Now().Add(3 * time.Second)
	var got []string
	for {
		got = h.tunnel.opcodes()
		for _, op := range got {
			if !readOnlyPassthrough(op) {
				t.Fatalf("guacd received forbidden opcode %q from read-only monitor: %v", op, got)
			}
		}
		seen := map[string]bool{}
		for _, op := range got {
			seen[op] = true
		}
		if seen["sync"] && seen["ack"] && seen["nop"] {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("keep-alives were not all forwarded: %v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Input sent after the keep-alives is still dropped (no ordering luck).
	h.send(t, "3.key,5.65515,1.0;")
	time.Sleep(150 * time.Millisecond)
	for _, op := range h.tunnel.opcodes() {
		if !readOnlyPassthrough(op) {
			t.Fatalf("guacd received forbidden opcode %q after keep-alives", op)
		}
	}
}

func TestWritableMonitorStillForwardsInput(t *testing.T) {
	// Guards the default: only the Monitor handler opts into readOnly; a
	// share/writable MonitorCon keeps upstream behaviour.
	h := newMonitorHarness(t, false)
	go func() {
		for {
			if _, _, err := h.client.ReadMessage(); err != nil {
				return
			}
		}
	}()
	h.send(t, "3.key,5.65515,1.1;")
	time.Sleep(100 * time.Millisecond)
	for _, op := range h.tunnel.opcodes() {
		if op == "key" {
			return
		}
	}
	t.Fatalf("writable monitor did not forward key: %v", h.tunnel.opcodes())
}

func TestMonitorCloseEndsRunAndOwnerCloseEndsMonitor(t *testing.T) {
	// Monitor closes its websocket: Run returns, fake guacd join is closed.
	h := newMonitorHarness(t, true)
	go func() {
		for {
			if _, _, err := h.client.ReadMessage(); err != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	_ = h.client.Close()
	select {
	case <-h.runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after monitor websocket closed")
	}
	select {
	case <-h.tunnel.closed:
	default:
		t.Fatal("monitor guacd join was not closed after websocket close")
	}

	// Owner side goes away (guacd read error): monitor gets a disconnect and Run returns.
	h2 := newMonitorHarness(t, true)
	gotDisconnect := make(chan struct{}, 1)
	go func() {
		for {
			_, msg, err := h2.client.ReadMessage()
			if err != nil {
				return
			}
			if strings.HasPrefix(string(msg), "10.disconnect") || strings.HasPrefix(string(msg), "5.error,") {
				select {
				case gotDisconnect <- struct{}{}:
				default:
				}
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	_ = h2.tunnel.Close()
	select {
	case <-h2.runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after guacd side closed")
	}
	select {
	case <-gotDisconnect:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor client did not receive disconnect after owner closed")
	}
}
