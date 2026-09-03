package handler

import "testing"

// Secrets are keyed on app_slug, so the lqt-mailbox -> quant-research rename
// orphaned every credential a user had set: the cycle then failed at its own
// credential check as though none was configured. Measured 2026-09-04: 127
// users carried a cached credential under the OLD slug while cycles looked it
// up under the new one.
func TestAppSecretsFetchSpansRenames(t *testing.T) {
	got := appAliases("quant-research")
	if len(got) < 2 {
		t.Fatalf("quant-research must alias its pre-rename slug, got %v", got)
	}
	seen := map[string]bool{}
	for _, a := range got {
		seen[a] = true
	}
	if !seen["lqt-mailbox"] || !seen["quant-research"] {
		t.Errorf("both slugs must resolve to the same secret store, got %v", got)
	}
	// Symmetric: a legacy install asking under the old name must reach the
	// same rows, or fixing the new name just moves the outage.
	if len(appAliases("lqt-mailbox")) != len(got) {
		t.Errorf("aliasing must be symmetric: %v vs %v", appAliases("lqt-mailbox"), got)
	}
	// Unrelated apps must NOT be merged — a wrong entry here silently joins
	// two apps' credentials, which is worse than the bug it fixes.
	if other := appAliases("mbb-consultant"); len(other) != 1 || other[0] != "mbb-consultant" {
		t.Errorf("unrelated app must not alias, got %v", other)
	}
}
