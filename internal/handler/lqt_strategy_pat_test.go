package handler

import "testing"

// The mint is a SIDE EFFECT, so the predicate that gates it is the part worth
// pinning: it must fire for an lqt-mailbox deploy and for nothing else.
func TestLQTIntentNeedsStrategyPAT(t *testing.T) {
	cases := []struct {
		name    string
		action  string
		payload map[string]any
		want    bool
	}{
		{"quant-research run_loop", "run_loop", map[string]any{"app": "quant-research"}, true},
		{"lqt-mailbox run_loop (legacy name)", "run_loop", map[string]any{"app": "lqt-mailbox"}, true},
		{"quant-research install never deploys", "install", map[string]any{"app": "quant-research"}, false},
		{"slug is trimmed", "run_loop", map[string]any{"app": "  quant-research "}, true},
		{"install never deploys", "install", map[string]any{"app": "lqt-mailbox"}, false},
		{"update never deploys", "update", map[string]any{"app": "lqt-mailbox"}, false},
		{"a different app", "run_loop", map[string]any{"app": "venue-link-matcher"}, false},
		{"no app key", "run_loop", map[string]any{}, false},
		{"app is not a string", "run_loop", map[string]any{"app": 7}, false},
		{"nil payload", "run_loop", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := lqtIntentNeedsStrategyPAT(c.action, c.payload); got != c.want {
				t.Errorf("lqtIntentNeedsStrategyPAT(%q, %v) = %v, want %v",
					c.action, c.payload, got, c.want)
			}
		})
	}
}

// attachLQTStrategyPAT must never panic on a nil map and must not invent a key
// for an intent that does not deploy — a stray credential in a payload that
// gets logged is exactly the leak this design avoids.
func TestAttachLQTStrategyPATLeavesNonDeployAlone(t *testing.T) {
	p := map[string]any{"app": "mbb-ai"}
	attachLQTStrategyPAT("run_loop", "some-user", p)
	if _, ok := p["lqt_strategy_pat"]; ok {
		t.Fatal("minted a deploy PAT for an app that never deploys")
	}
	attachLQTStrategyPAT("run_loop", "some-user", nil) // must not panic
}

// THE RENAME REGRESSION.
//
// This gate matched only "lqt-mailbox". The app was renamed to
// "quant-research" at v0.7.0 and the UI's Deploy action posts the new slug, so
// every Studio deploy silently lost its scoped PAT and the consumer rejected it
// with `no bearer credential in payload.auth.{pat,jwt}` — 42 of 53 rejected
// submissions on the live mailbox, measured 2026-08-28.
//
// The old table-test stayed GREEN throughout, because it pinned the old name
// and nothing asserted the name the app actually ships under. This test asserts
// against the manifest's real slug so a future rename fails here first.
func TestLQTStrategyAppMatchesTheShippedManifestSlug(t *testing.T) {
	// `name:` in the app bundle's .xpcloud.yaml. If the app is renamed again,
	// change it HERE and in lqtStrategyApps together — that coupling is the
	// whole point of this test.
	const shippedSlug = "quant-research"

	if !isLQTStrategyApp(shippedSlug) {
		t.Fatalf("isLQTStrategyApp(%q) = false — a Deploy from the xpio page "+
			"gets no lqt:strategy PAT and the consumer will reject it with "+
			"'no bearer credential in payload.auth.{pat,jwt}'", shippedSlug)
	}
	// The legacy slug must keep working: installs predating the rename still
	// run under it, and fixing the new name by breaking the old one would only
	// move the outage.
	if !isLQTStrategyApp("lqt-mailbox") {
		t.Error("legacy slug lqt-mailbox must stay matched for pre-rename installs")
	}
	// The gate must stay narrow — minting is a side effect.
	if isLQTStrategyApp("venue-link-matcher") || isLQTStrategyApp("") {
		t.Error("gate is too wide: only strategy-deploying apps may mint a deploy PAT")
	}
}
