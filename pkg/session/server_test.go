package session

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jumpserver-dev/sdk-go/model"

	"lion/pkg/config"
)

// Create must copy the connection token id into the Core session payload so
// the session is exactly correlatable via
// GET /api/v1/terminal/sessions/by-connection-token/{id}/.
func TestCreatePersistsConnectionTokenId(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if config.GlobalConfig == nil {
		config.GlobalConfig = &config.Config{}
	}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("GET", "/lion/connect/", nil)

	const tokenId = "0b3f2b6e-1f2d-4c8a-9d2e-2b6d0f4a9c11"
	token := &model.ConnectToken{
		Id:       tokenId,
		Protocol: TypeRDP,
		User:     model.User{ID: "u1", Name: "alice", Username: "alice"},
		Asset:    model.Asset{ID: "a1", Name: "win", Address: "10.0.0.5"},
		Account:  model.Account{BaseAccount: model.BaseAccount{Name: "adm", Username: "adm"}},
	}
	s := &Server{}
	sess, err := s.Create(ctx,
		ConnectTokenAuthInfo(token),
		WithProtocol(token.Protocol),
		WithUser(&token.User),
		WithActions(token.Actions),
		WithAsset(&token.Asset),
		WithAccount(&token.Account),
		WithPlatform(&token.Platform),
	)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.ModelSession == nil {
		t.Fatal("ModelSession nil")
	}
	if sess.ModelSession.TokenId != tokenId {
		t.Fatalf("TokenId = %q, want %q", sess.ModelSession.TokenId, tokenId)
	}

	// Outbound payload as sent by JMService.CreateSession (JSON body).
	body, err := json.Marshal(sess.ModelSession)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"token_id":"`+tokenId+`"`) {
		t.Fatalf("session-create payload lacks token_id: %s", body)
	}
}
