package common

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"lumid_identity/internal/config"
)

func withTestKeys(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	prevKeys, prevG := Keys, config.G
	Keys = &Keyring{keys: map[string]*SigningKey{"test": {Kid: "test", Private: k, Public: &k.PublicKey, Active: true}}, active: "test"}
	if config.G == nil {
		config.G = &config.Config{}
	}
	t.Cleanup(func() { Keys, config.G = prevKeys, prevG })
}

func bridge(t *testing.T, aud string) string {
	t.Helper()
	tok, _, _, err := IssueBridgeJWT("u1", "u1@example.com", "admin", aud, []string{"x:y"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestVerifyIdentityJWTRefusesOtherServices(t *testing.T) {
	withTestKeys(t)
	session, _, _, err := IssueJWT("u1", "u1@example.com", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	idTok, _, err := IssueIDToken("u1", "u1@example.com", "U", "admin", "harbor", true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tok  string
		ok   bool
	}{
		{"session (lumid-ecosystem)", session, true},
		{"claude-proxy forward (lumid-identity)", bridge(t, "lumid-identity"), true},
		{"service-account recipe (lumid)", bridge(t, "lumid"), true},
		{"flowmesh session-bearer", bridge(t, "flowmesh"), false},
		{"runmesh session-bearer", bridge(t, "runmesh"), false},
		{"lum.id/data dispatch (lumilake)", bridge(t, "lumilake"), false},
		{"OIDC id_token for harbor", idTok, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyIdentityJWT(tc.tok)
			if (err == nil) != tc.ok {
				t.Fatalf("VerifyIdentityJWT ok=%v, want %v (err=%v)", err == nil, tc.ok, err)
			}
			// Signature-only verification still passes for all of them:
			// the refusal is the audience, nothing else.
			if _, err := VerifyJWT(tc.tok); err != nil {
				t.Fatalf("VerifyJWT should pass, got %v", err)
			}
		})
	}
}

func TestIntrospectAudienceVerdict(t *testing.T) {
	withTestKeys(t)
	t.Setenv("INTROSPECT_UNBOUND_AUDIENCES", "flowmesh,runmesh")
	resetUnboundForTest()
	t.Cleanup(resetUnboundForTest)

	session, _, _, _ := IssueJWT("u1", "u1@example.com", "user", nil)
	idTok, _, _ := IssueIDToken("u1", "u1@example.com", "U", "user", "argocd", true)
	claims := func(tok string) *JWTClaims {
		c, err := VerifyJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cases := []struct {
		name        string
		tok         string
		want        string
		ok, unbound bool
	}{
		{"session, bound caller", session, "lumid-data", true, false},
		{"session, unbound caller", session, "", true, false},
		{"own audience, bound", bridge(t, "lumid-data"), "lumid-data", true, false},
		{"other service, bound -> refused", bridge(t, "flowmesh"), "lumid-data", false, false},
		{"allowance aud, unbound -> accepted+flagged", bridge(t, "flowmesh"), "", true, true},
		{"aud outside allowance, unbound -> refused", bridge(t, "lumilake"), "", false, false},
		{"OIDC id_token, unbound -> refused", idTok, "", false, false},
		{"OIDC id_token, bound elsewhere -> refused", idTok, "flowmesh", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, unbound := IntrospectAudienceVerdict(claims(tc.tok), tc.want)
			if ok != tc.ok || unbound != tc.unbound {
				t.Fatalf("got ok=%v unbound=%v, want ok=%v unbound=%v", ok, unbound, tc.ok, tc.unbound)
			}
		})
	}
}

func TestUnboundAllowanceEnv(t *testing.T) {
	t.Cleanup(resetUnboundForTest)

	resetUnboundForTest()
	t.Setenv("INTROSPECT_UNBOUND_AUDIENCES", "")
	if n := len(UnboundIntrospectAudiences()); n != 0 {
		t.Fatalf("set-but-empty must mean none, got %d", n)
	}

	resetUnboundForTest()
	// Unset -> the measured default (os.Unsetenv after t.Setenv is restored by t).
	t.Setenv("INTROSPECT_UNBOUND_AUDIENCES", "x")
	resetUnboundForTest()
	if !UnboundIntrospectAudiences()["x"] || len(UnboundIntrospectAudiences()) != 1 {
		t.Fatalf("explicit list not honoured")
	}
}
