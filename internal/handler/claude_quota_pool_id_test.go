package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"lumid_identity/models"
)

// quotaResult carried no pool_id at all, so GET /admin/claude-quota answered
// without one and the /code accounts table — which renders
// `acc.pool_id || 'default'` — showed EVERY account as "Default Pool"
// regardless of its real pool. Worse, the pool <select>'s change handler
// compares the chosen id against that same `acc.pool_id || 'default'`, so
// picking "Default Pool" on an account actually in another pool matched the
// undefined fallback and silently no-op'd. Pin that the field is on the wire.
func TestQuotaResultCarriesPoolIDOnTheWire(t *testing.T) {
	b, err := json.Marshal(quotaResult{Email: "a@x", PoolID: "rsi"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := got["pool_id"]
	if !ok {
		t.Fatal("pool_id absent from the response — the dashboard cannot tell pools apart")
	}
	if v != "rsi" {
		t.Fatalf("pool_id = %v, want rsi", v)
	}
}

// Deliberately NOT omitempty: an omitted key is exactly the state that caused
// the bug, and the UI's `|| 'default'` fallback would hide its return.
func TestQuotaResultPoolIDIsNeverOmitted(t *testing.T) {
	b, err := json.Marshal(quotaResult{Email: "a@x"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"pool_id"`) {
		t.Fatalf("pool_id omitted when empty (%s) — the field must always be present", b)
	}
}

// Rows predating the pool feature can hold "" where every reader means
// "default" (AdminClaudeAccountUsers spells it COALESCE(t.pool_id, ?)).
// Normalise, so the select matches an option by statement, not by accident.
func TestPoolIDOrDefaultNormalisesLegacyBlank(t *testing.T) {
	if got := poolIDOrDefault(""); got != models.DefaultClaudePoolID {
		t.Fatalf("poolIDOrDefault(%q) = %q, want %q", "", got, models.DefaultClaudePoolID)
	}
	if got := poolIDOrDefault("rsi"); got != "rsi" {
		t.Fatalf("poolIDOrDefault(%q) = %q — a real pool must pass through untouched", "rsi", got)
	}
}
