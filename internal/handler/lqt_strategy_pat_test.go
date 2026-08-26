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
		{"lqt-mailbox run_loop", "run_loop", map[string]any{"app": "lqt-mailbox"}, true},
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
