package handler

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"lumid_identity/models"
)

// allow_onprem is the restrictive verdict when false, and `false` is also the
// JSON zero value — so omitempty would erase exactly the answer that matters
// and leave the consumer unable to tell "denied" from "old identity server".
func TestIntrospectAlwaysEmitsAllowOnprem(t *testing.T) {
	b, err := json.Marshal(IntrospectResponse{Active: true, Sub: "u1", AllowOnprem: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"allow_onprem":false`) {
		t.Fatalf("a denial did not reach the wire: %s", b)
	}
}

// An inactive verdict has no identity to resolve a pool for, and enriching it
// would run two DB queries per bad token — a free amplifier for anyone
// spraying garbage at introspect.
func TestEnrichClaudePolicySkipsInactiveTokens(t *testing.T) {
	got := enrichClaudePolicy(IntrospectResponse{Active: false, Reason: "unknown token"})
	if got.AllowOnprem {
		t.Fatal("an inactive token was given a policy verdict")
	}
	if got.Reason != "unknown token" {
		t.Fatalf("enrichment altered an inactive response: %+v", got)
	}
}

// The hint must be read from the token's OWN scopes: a PAT scoped to a
// non-primary pool draws on that pool, so judging it against the user's
// primary pool would apply the wrong policy to every request it makes.
func TestClaudePoolHintFromScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		want   string
	}{
		{"no pool scope", []string{"claude:proxy"}, ""},
		{"pool scope present", []string{"claude:proxy", "claude-pool:rsi"}, "rsi"},
		{"pool scope alone", []string{"claude-pool:default"}, "default"},
		{"prefix must anchor", []string{"not-claude-pool:rsi"}, ""},
		{"empty id is not a hint", []string{"claude-pool:"}, ""},
		{"nil scopes", nil, ""},
	}
	for _, tc := range cases {
		if got := ClaudePoolHintFromScopes(tc.scopes); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// No user_sub means no pool to consult — a legacy/service caller must not be
// locked out of the fleet by a policy that cannot be evaluated for it.
func TestOnpremFailsOpenWithoutASubject(t *testing.T) {
	if !ClaudeOnpremAllowedFor("", []string{"claude:proxy"}) {
		t.Fatal("a subject-less identity was denied on-prem — this must fail open")
	}
}

// The default has to survive a migration: on-prem is open to every role today,
// so a pool row that predates the column must read as allowed.
func TestClaudePoolDefaultsToOnpremAllowed(t *testing.T) {
	f, ok := reflectGormTag(models.ClaudePool{}, "AllowOnprem")
	if !ok {
		t.Fatal("AllowOnprem field missing from ClaudePool")
	}
	if !strings.Contains(f, "default:true") {
		t.Fatalf("AllowOnprem gorm tag %q lacks default:true — existing rows would migrate to DENIED", f)
	}
}

// reflectGormTag returns the gorm struct tag of a named field.
func reflectGormTag(v interface{}, field string) (string, bool) {
	t := reflect.TypeOf(v)
	f, ok := t.FieldByName(field)
	if !ok {
		return "", false
	}
	return f.Tag.Get("gorm"), true
}
