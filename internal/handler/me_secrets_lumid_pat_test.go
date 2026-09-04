package handler

import "testing"

// A tenant cycle has no LUMID_PAT: _run_loop_cycle pops it so a tenant never
// borrows the operator's credential, and HOME is the tenant root so the
// operator's mounted pat file is off its path. Every scheduled harvest died on
// "No LUMID_PAT env var and ~/.lumilake/pat not found" until the per-tenant
// token was injected for both keys.
func TestLQTStrategyAppsCoverBothInstallNames(t *testing.T) {
	// The injection is gated on isLQTStrategyApp. A rename that slips past this
	// gate silently returns tenants to the no-credential state — which is how
	// the deploy PAT broke once already (v0.7.0, 42 of 53 rejections).
	for _, app := range []string{"quant-research", "lqt-mailbox"} {
		if !isLQTStrategyApp(app) {
			t.Errorf("%q must receive the per-tenant credential injection", app)
		}
	}
	for _, app := range []string{"mbb-consultant", "venue-link-matcher", ""} {
		if isLQTStrategyApp(app) {
			t.Errorf("%q must NOT be handed an LQT credential", app)
		}
	}
	// Both names must resolve to ONE secret store, or a legacy install reads a
	// different row than the credential was cached under.
	if len(appAliases("quant-research")) != len(appAliases("lqt-mailbox")) {
		t.Error("alias groups must be symmetric across the rename")
	}
}
