package common

import "testing"

// The pre-request gate in claude-proxy is a dry-run with NO model and zero
// tokens: gateUser -> chargeUser(sub, "", "", 0, 0, true). The non-Anthropic
// bypass tested `!strings.HasPrefix(req.Model, "claude")`, and "" is not
// claude-prefixed — so the gate fell through the bypass and returned
// Allowed=true for everyone, leaving the per-user pool quota UNENFORCED while
// still reporting success.
//
// These tests lock the classification, which is the part that regressed. They
// deliberately avoid a DB: the bug was in which models are gated at all, not in
// the window arithmetic.
func TestPoolGateClassification(t *testing.T) {
	cases := []struct {
		name  string
		model string
		gated bool
	}{
		// The gate itself. This is the case that broke.
		{"empty model (the pre-request gate)", "", true},
		{"claude alias", "claude-sonnet-5", true},
		{"claude full id", "claude-opus-4-8-20250101", true},
		// Named non-Anthropic models ride separate API keys and must skip.
		{"kimi", "kimi-k3", false},
		{"glm", "z-ai/glm-5.2", false},
		{"in-house qwen", "qwen3.6-35b-a3b", false},
	}
	for _, c := range cases {
		got := poolCapApplies(c.model)
		if got != c.gated {
			t.Errorf("%s: poolCapApplies(%q) = %v, want %v", c.name, c.model, got, c.gated)
		}
	}
}

// Doubling the caps must not accidentally leave them env-shadowed or zero —
// a zero cap would divide-by-zero in the percentage math.
func TestClaudePoolLimitsSane(t *testing.T) {
	five, seven := ClaudePoolLimits()
	if five <= 0 || seven <= 0 {
		t.Fatalf("caps must be positive, got 5h=%d 7d=%d", five, seven)
	}
	if seven < five {
		t.Errorf("7d cap (%d) must be >= 5h cap (%d)", seven, five)
	}
	if five != DefaultClaudeShortTokens || seven != DefaultClaude7dTokens {
		t.Logf("caps are env-overridden: 5h=%d 7d=%d (defaults %d/%d)",
			five, seven, DefaultClaudeShortTokens, DefaultClaude7dTokens)
	}
}
