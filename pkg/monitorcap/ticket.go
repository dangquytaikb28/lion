// Session-scoped monitor capability tickets (RDP-A6 / RDP-07).
//
// PAM Adapter mints a short-lived HMAC ticket bound to one JumpServer user
// and one exact session id. Lion admits /lion/monitor and /lion/ws/monitor
// only when that ticket matches the authenticated viewer and the requested
// session. A Core cookie with terminal.monitor_session is not enough to
// substitute a different session id.
package monitorcap

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	PurposeMonitor = "monitor"
	EnvSecret      = "MONITOR_TICKET_SECRET"
	CookieName     = "pim_monitor_cap"
	QueryName      = "ticket"
	Version        = 1
)

var (
	ErrMissingSecret = errors.New("monitor ticket secret is not configured")
	ErrInvalidTicket = errors.New("monitor ticket is invalid")
	ErrExpired       = errors.New("monitor ticket expired")
	ErrSessionBind   = errors.New("monitor ticket session mismatch")
	ErrViewerBind    = errors.New("monitor ticket viewer mismatch")
)

type Claims struct {
	V   int    `json:"v"`
	P   string `json:"p"`
	SID string `json:"sid"`
	UID string `json:"uid"`
	Exp int64  `json:"exp"`
	N   string `json:"n"`
}

func SecretFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvSecret))
}

func Sign(secret, sessionID, userID, nonce string, exp time.Time) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", ErrMissingSecret
	}
	if sessionID == "" || userID == "" || nonce == "" || exp.IsZero() {
		return "", ErrInvalidTicket
	}
	// Map marshal is key-sorted, matching Python json.dumps(sort_keys=True).
	payload, err := json.Marshal(map[string]any{
		"v":   Version,
		"p":   PurposeMonitor,
		"sid": sessionID,
		"uid": userID,
		"exp": exp.UTC().Unix(),
		"n":   nonce,
	})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	sig := hex.EncodeToString(mac.Sum(nil))
	return body + "." + sig, nil
}

func Verify(secret, token, sessionID, userID string, now time.Time) (*Claims, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, ErrMissingSecret
	}
	token = strings.TrimSpace(token)
	dot := strings.LastIndex(token, ".")
	if dot <= 0 || dot == len(token)-1 {
		return nil, ErrInvalidTicket
	}
	body, sigHex := token[:dot], token[dot+1:]
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.ToLower(sigHex)), []byte(strings.ToLower(expected))) {
		return nil, ErrInvalidTicket
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, ErrInvalidTicket
	}
	var claims Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, ErrInvalidTicket
	}
	if claims.V != Version || claims.P != PurposeMonitor || claims.SID == "" || claims.UID == "" || claims.N == "" {
		return nil, ErrInvalidTicket
	}
	if now.UTC().Unix() > claims.Exp {
		return nil, ErrExpired
	}
	if !strings.EqualFold(claims.SID, sessionID) {
		return nil, ErrSessionBind
	}
	if claims.UID != userID {
		return nil, ErrViewerBind
	}
	return &claims, nil
}

func RemainingTTL(claims *Claims, now time.Time) int {
	if claims == nil {
		return 0
	}
	left := int(claims.Exp - now.UTC().Unix())
	if left < 0 {
		return 0
	}
	return left
}
