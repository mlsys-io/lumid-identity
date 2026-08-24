package handler

import (
	"testing"

	"lumid_identity/internal/common"
)

// The whole feature rests on ClassifyProvider telling the LOCALLY SERVED id
// apart from the OVERFLOW id. If these ever collapse to one bucket, the
// dashboard reports money spent on OpenRouter as money saved by on-prem — the
// exact inversion this is meant to surface. Before claude-proxy b72cd43 that
// was the live behaviour, so this is a regression guard, not a tautology.
func TestOnPremAndOverflowAreDifferentBuckets(t *testing.T) {
	if got := common.ClassifyProvider("deepseek-v4-flash"); got != common.ProviderOnPrem {
		t.Fatalf("locally served id classified %q, want %q", got, common.ProviderOnPrem)
	}
	if got := common.ClassifyProvider("deepseek/deepseek-v4-flash-0731"); got != common.ProviderOpenRouter {
		t.Fatalf("overflow id classified %q, want %q — savings would double-count real spend", got, common.ProviderOpenRouter)
	}
	// Claude must never land in either bucket: it is a subscription, and
	// valuing it as "saved" or "spent" here would swamp both figures.
	if got := common.ClassifyProvider("claude-opus-5"); got != common.ProviderClaude {
		t.Fatalf("claude classified %q, want %q", got, common.ProviderClaude)
	}
}

// Claude Code appends a [N] context marker to the model id. If that defeated
// classification, on-prem turns would fall through to the OpenRouter bucket and
// the savings figure would silently read zero while spend looked inflated.
func TestContextMarkerDoesNotBreakClassification(t *testing.T) {
	if got := common.ClassifyProvider("deepseek-v4-flash[1m]"); got != common.ProviderOnPrem {
		t.Fatalf("marked id classified %q, want %q", got, common.ProviderOnPrem)
	}
}
