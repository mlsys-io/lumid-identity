package handler

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"

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

// The two flags default in OPPOSITE directions, and each default encodes
// today's behaviour: on-prem is open to everyone, externally billed models are
// refused to everyone. Flipping either is a silent estate-wide change, and for
// openrouter it is one that spends money.
func TestPoolFlagDefaultsAreOpposites(t *testing.T) {
	onprem, ok := reflectGormTag(models.ClaudePool{}, "AllowOnprem")
	if !ok {
		t.Fatal("AllowOnprem missing")
	}
	if !strings.Contains(onprem, "default:true") {
		t.Errorf("AllowOnprem tag %q must default true — on-prem is open today", onprem)
	}
	or, ok := reflectGormTag(models.ClaudePool{}, "AllowOpenrouter")
	if !ok {
		t.Fatal("AllowOpenrouter missing")
	}
	if !strings.Contains(or, "default:false") {
		t.Errorf("AllowOpenrouter tag %q must default false — externally billed models are denied today", or)
	}
}

// Both verdicts must reach the wire unconditionally. For openrouter the
// dangerous omission is the true case going missing (access silently lost);
// for onprem it is the false case (denial silently lost).
func TestIntrospectAlwaysEmitsBothPoolVerdicts(t *testing.T) {
	b, err := json.Marshal(IntrospectResponse{Active: true, Sub: "u1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{`"allow_onprem"`, `"allow_openrouter"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("%s missing from the wire: %s", k, b)
		}
	}
}

// A subject-less caller gets the status quo on both axes: keep the fleet,
// no spend path.
func TestSubjectlessIdentityGetsStatusQuoOnBothAxes(t *testing.T) {
	if !ClaudeOnpremAllowedFor("", nil) {
		t.Error("on-prem must fail open for a subject-less identity")
	}
	if ClaudeOpenrouterAllowedFor("", nil) {
		t.Error("openrouter must fail closed for a subject-less identity")
	}
}

// Introspection is the auth path for EVERY service on the platform, not just
// claude-proxy. Resolving each verdict independently cost up to nine queries
// per introspection, all re-reading the same claude_pools row — this counts
// the real ones so a fourth flag cannot quietly restore that.
func TestEnrichClaudePolicyResolvesThePoolOnce(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-policy-cost"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode, allow_onprem, allow_openrouter, allow_fable)
	         VALUES (?, 'C', 'distributed', TRUE, TRUE, TRUE)`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "polcost")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at) VALUES (?, ?, TRUE, NOW())`, pool, sub)

	var queries int
	cb := func(tx *gorm.DB) { queries++ }
	if err := db.Callback().Query().After("gorm:query").Register("cptest:count", cb); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Query().Remove("cptest:count") })

	got := enrichClaudePolicy(IntrospectResponse{Active: true, Sub: sub, Scopes: []string{"claude:proxy"}})

	// One membership lookup (no hint -> primary) + one pool read. The ceiling
	// is what matters: three independent resolutions would be 6-9.
	if queries > 3 {
		t.Errorf("enrichClaudePolicy issued %d queries — the per-verdict resolution is back", queries)
	}
	if !got.AllowOnprem || !got.AllowOpenrouter || !got.AllowFable {
		t.Errorf("consolidation lost a verdict: %+v", got)
	}
}

// Both spend-granting fields sit at super_admin; the admin-level fields must
// stay reachable by a plain admin. Asserted on the BODY STRUCT + gate pairing
// rather than through HTTP, because the gate reads the caller's role from the
// bearer and this package's role helper needs a real session.
func TestSpendGrantingFieldsAreNamedInTheDenial(t *testing.T) {
	// The denial must name the field(s) actually attempted — a caller PATCHing
	// name+allow_openrouter needs to know which half was refused, or they will
	// retry the whole thing and be denied again.
	src, err := os.ReadFile("claude_pool_admin.go")
	if err != nil {
		t.Fatalf("read handler: %v", err)
	}
	h := string(src)
	for _, want := range []string{
		`spendFields = append(spendFields, "allow_openrouter")`,
		`spendFields = append(spendFields, "allow_fable")`,
		`"super_admin required to change "+strings.Join(spendFields, " and ")`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("the spend gate no longer names its fields — missing: %s", want)
		}
	}
	// allow_onprem must NOT be in the spend gate: it grants access to hardware
	// we own at no marginal cost, and gating it at super_admin would put the
	// safe control out of an admin's reach while leaving the risky ones in it.
	if strings.Contains(h, `spendFields = append(spendFields, "allow_onprem")`) {
		t.Error("allow_onprem was pulled into the super_admin spend gate — it costs nothing marginal")
	}
}
