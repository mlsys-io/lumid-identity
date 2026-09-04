package common

import "testing"

// The pre-request gate in claude-proxy is a dry-run with NO model and zero
// tokens: gateUser -> chargeUser(sub, "", "", 0, 0, true). The ORIGINAL
// non-Anthropic bypass tested `!strings.HasPrefix(req.Model, "claude")`, and ""
// is not claude-prefixed — so the gate fell through the bypass and returned
// Allowed=true for everyone, leaving the per-user pool quota UNENFORCED while
// still reporting success. That regression is why poolCapApplies must gate "".
//
// Between 2026-08-23 and 2026-09-04, every named model — Claude or not — drew
// on the same shared 5h/7d window (poolCapApplies was constant-true), closing
// the unlimited-non-Claude-usage gap above. That in turn opened a DIFFERENT
// one: the CLI's native usage warning and /me/claude-usage summed all models
// while /code's own dashboard bar intentionally showed Claude-only, so a heavy
// deepseek user saw the CLI cross 100% while the dashboard read a comfortable
// 17% (see [[project_claude_proxy_cli_vs_dashboard_pct_split]]). Reverted back
// to Claude-only on 2026-09-04 (operator decision) so every surface — gate,
// CLI header rewrite, /me, /code — agrees on one number again. Non-Claude
// usage is simply unbounded by THIS gate now; it needs its own cap if a
// runaway non-Claude consumer needs bounding again.
//
// These tests lock the classification, which has regressed in both directions
// now. They deliberately avoid a DB: the bug was in which models are gated at
// all, not in the window arithmetic.
func TestPoolGateClassification(t *testing.T) {
	cases := []struct {
		name  string
		model string
		gated bool
	}{
		// The gate itself. This is the case that broke ("" must stay gated).
		{"empty model (the pre-request gate)", "", true},
		// Claude models.
		{"claude alias", "claude-sonnet-5", true},
		{"claude full id", "claude-opus-4-8-20250101", true},
		// Non-Anthropic models draw on our own compute, not the Anthropic
		// subscription seats this window protects — ungated.
		{"kimi", "kimi-k3", false},
		{"glm", "z-ai/glm-5.2", false},
		{"self-hosted deepseek", "deepseek-v4-flash", false},
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
