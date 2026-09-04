package handler

import "testing"

// A loop may attach SEVERAL experiments (engine.experiment as a list). The
// rawLoop parser typed it as string, so a list attachment failed the whole
// spec unmarshal and every loop in the app vanished from /me/workflows — the
// Workflows tab rendered its empty state for an app with nine loops
// (quant-research, observed live 2026-09-04). Fifth instance of the
// scalar-attachment bug.
func TestReadYamlLoopsListExperimentAttachment(t *testing.T) {
	spec := []byte(`
loops:
  - name: backtest
    schedule: "@trigger"
    engine:
      type: command
      module: backtest
      experiment:
        - backtest_evidence
        - backtest_performance
  - name: interview
    schedule: "@trigger"
    engine:
      type: command
      module: interview
      experiment: judge_panel_parity
`)
	loops, err := readYamlLoopsBytes(spec)
	if err != nil {
		t.Fatalf("list attachment must not fail the parse: %v", err)
	}
	if len(loops) != 2 {
		t.Fatalf("want 2 loops, got %d", len(loops))
	}
	if got := len(loops[0].Engine.Experiment); got != 2 {
		t.Fatalf("want 2 attached experiments on backtest, got %d", got)
	}
	if got := loops[1].Engine.Experiment; len(got) != 1 || got[0] != "judge_panel_parity" {
		t.Fatalf("scalar attachment must still work, got %v", got)
	}
}
