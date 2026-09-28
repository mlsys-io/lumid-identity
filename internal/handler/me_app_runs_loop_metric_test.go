package handler

import "testing"

// A loop feeding two experiments must resolve the SAME metric on every call —
// the first one it declares — not whichever a Go map range yielded.
func TestLoopMetricNameFromIsDeclarationOrdered(t *testing.T) {
	spec := []byte(`
loops:
- name: backtest
  engine:
    type: command
    experiment:
    - backtest_evidence
    - backtest_performance
- name: harvest_outbox
  engine: {type: command}
experiments:
- id: backtest_evidence
  metric: {name: all_axes_real}
- id: backtest_performance
  metric: {name: realized_pnl_ticks_per_lot}
`)
	m := parseExpManifestBytes(spec)
	for i := 0; i < 200; i++ {
		if got := loopMetricNameFrom(m, "backtest"); got != "all_axes_real" {
			t.Fatalf("call %d: got %q, want all_axes_real", i, got)
		}
	}
	if got := loopMetricNameFrom(m, "harvest_outbox"); got != "" {
		t.Fatalf("loop with no experiment: got %q, want \"\"", got)
	}
}
