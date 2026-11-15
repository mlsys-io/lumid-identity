package common

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"lumid_identity/internal/config"
)

// Browser logins (lm_session) live jwt.session_ttl_sec; every other JWT keeps
// jwt.access_ttl_sec. A month-long session must not quietly turn OAuth access
// tokens handed to other clients into month-long bearers too.

func withTestKeyAndConfig(t *testing.T, accessSec, sessionSec int) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	prevKeys, prevG := Keys, config.G
	Keys = &Keyring{keys: map[string]*SigningKey{"test": {Kid: "test", Private: k, Public: &k.PublicKey, Active: true}}, active: "test"}
	c := &config.Config{}
	c.App.Issuer = "https://lum.id"
	c.JWT.AccessTTLSec = accessSec
	c.JWT.SessionTTLSec = sessionSec
	config.G = c
	t.Cleanup(func() { Keys, config.G = prevKeys, prevG })
}

func within(t *testing.T, got time.Time, want time.Duration) {
	t.Helper()
	if d := time.Until(got) - want; d > 5*time.Second || d < -5*time.Second {
		t.Fatalf("exp is %v from now, want %v", time.Until(got).Round(time.Second), want)
	}
}

func TestSessionJWTUsesSessionTTL(t *testing.T) {
	withTestKeyAndConfig(t, 86400, 30*86400)
	tok, _, exp, err := IssueSessionJWT("u1", "u1@example.com", "user", []string{"lumid:profile:read"})
	if err != nil {
		t.Fatal(err)
	}
	within(t, exp, 30*24*time.Hour)
	claims, err := VerifyJWT(tok)
	if err != nil {
		t.Fatalf("session JWT does not verify: %v", err)
	}
	within(t, claims.ExpiresAt.Time, 30*24*time.Hour)
}

func TestAccessJWTKeepsAccessTTL(t *testing.T) {
	withTestKeyAndConfig(t, 86400, 30*86400)
	_, _, exp, err := IssueJWT("u1", "u1@example.com", "user", nil)
	if err != nil {
		t.Fatal(err)
	}
	within(t, exp, 24*time.Hour)
	_, idExp, err := IssueIDToken("u1", "u1@example.com", "U", "user", "argocd", true)
	if err != nil {
		t.Fatal(err)
	}
	within(t, idExp, 24*time.Hour)
}

func TestSessionTTLFallsBackToAccessTTL(t *testing.T) {
	withTestKeyAndConfig(t, 3600, 0)
	if got := SessionTTL(); got != time.Hour {
		t.Fatalf("SessionTTL with session_ttl_sec unset = %v, want the access TTL (1h)", got)
	}
}
