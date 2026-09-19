package monitorcap

import (
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := "unit-test-monitor-ticket-secret-key!!"
	exp := time.Unix(1_800_000_000, 0).UTC()
	token, err := Sign(secret, "sess-a", "user-1", "nonce-1", exp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, "secret") {
		t.Fatal("token leaked secret")
	}
	claims, err := Verify(secret, token, "sess-a", "user-1", exp.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.SID != "sess-a" || claims.UID != "user-1" || claims.P != PurposeMonitor {
		t.Fatalf("unexpected claims %+v", claims)
	}
}

func TestSessionSubstitutionIsDenied(t *testing.T) {
	secret := "unit-test-monitor-ticket-secret-key!!"
	exp := time.Unix(1_800_000_000, 0).UTC()
	token, err := Sign(secret, "sess-b", "user-1", "nonce-1", exp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(secret, token, "sess-a", "user-1", exp.Add(-time.Second))
	if err != ErrSessionBind {
		t.Fatalf("got %v want session bind", err)
	}
}

func TestViewerMismatchIsDenied(t *testing.T) {
	secret := "unit-test-monitor-ticket-secret-key!!"
	exp := time.Unix(1_800_000_000, 0).UTC()
	token, err := Sign(secret, "sess-a", "user-1", "nonce-1", exp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(secret, token, "sess-a", "user-2", exp.Add(-time.Second))
	if err != ErrViewerBind {
		t.Fatalf("got %v want viewer bind", err)
	}
}

func TestExpiredAndTamperedAreDenied(t *testing.T) {
	secret := "unit-test-monitor-ticket-secret-key!!"
	exp := time.Unix(1_800_000_000, 0).UTC()
	token, err := Sign(secret, "sess-a", "user-1", "nonce-1", exp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(secret, token, "sess-a", "user-1", exp.Add(time.Second))
	if err != ErrExpired {
		t.Fatalf("got %v want expired", err)
	}
	tampered := token[:len(token)-2] + "00"
	_, err = Verify(secret, tampered, "sess-a", "user-1", exp.Add(-time.Second))
	if err != ErrInvalidTicket {
		t.Fatalf("got %v want invalid", err)
	}
	_, err = Verify("", token, "sess-a", "user-1", exp.Add(-time.Second))
	if err != ErrMissingSecret {
		t.Fatalf("got %v want missing secret", err)
	}
}

func TestPythonCompatibleEncoding(t *testing.T) {
	// Locked encoding: raw-url-safe body + hex HMAC. Python mint_monitor_ticket
	// must emit the same token for these inputs.
	secret := "unit-test-monitor-ticket-secret-key!!"
	exp := time.Unix(1_800_000_000, 0).UTC()
	token, err := Sign(secret, "3c151a29-aab0-4266-ae06-4048d3d8a597", "b3f89f34-d522-4c02-97ee-7ae7defc9461", "11111111-1111-4111-8111-111111111111", exp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(token, ".") != 1 {
		t.Fatalf("token shape %q", token)
	}
	_, err = Verify(secret, token, "3c151a29-aab0-4266-ae06-4048d3d8a597", "b3f89f34-d522-4c02-97ee-7ae7defc9461", time.Unix(1_799_999_000, 0))
	if err != nil {
		t.Fatal(err)
	}
}
