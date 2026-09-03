package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An arm dispatch must resolve against the app's OWN manifest. If it trusted
// the caller's arm id instead, an invented arm would run the baseline and be
// recorded under a label nobody declared — indistinguishable in the ledger from
// a real result, which is exactly the failure the run-a-variant break produced
// for months (unapplied variants landing as "current").
const armSpec = `
name: mbb-consultant
experiments:
  - id: judge_panel_parity
    hypothesis: A median-of-3 panel is more stable than a single seat.
    kind: arms
    metric: {name: avg_question_score, higher_is_better: true}
    compare_within: [panel]
    arms:
      - id: panel_single
        description: one seat
        judge_model: qwen3.8-27b
      - id: panel_median3
        description: three seats, median-scored
        judge_panel: [deepseek-v4-flash, qwen3.8-27b]
loops:
  - name: interview
    engine:
      experiment: judge_panel_parity
`

func writeArmSpec(t *testing.T, spec string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestResolveExperimentArm(t *testing.T) {
	dir := writeArmSpec(t, armSpec)

	t.Run("declared arm resolves with its config and loop", func(t *testing.T) {
		hyp, cfg, loop, err := resolveExperimentArm(dir, "judge_panel_parity", "panel_median3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if loop != "interview" {
			t.Errorf("loop = %q, want interview", loop)
		}
		if !strings.Contains(hyp, "median") {
			t.Errorf("hypothesis not carried through: %q", hyp)
		}
		if _, ok := cfg["judge_panel"]; !ok {
			t.Errorf("arm config lost: %v", cfg)
		}
		// id/description are metadata, not config to apply to the run.
		if _, ok := cfg["id"]; ok {
			t.Errorf("id leaked into the applied config: %v", cfg)
		}
		if _, ok := cfg["description"]; ok {
			t.Errorf("description leaked into the applied config: %v", cfg)
		}
	})

	t.Run("an invented arm is refused and names the real ones", func(t *testing.T) {
		_, _, _, err := resolveExperimentArm(dir, "judge_panel_parity", "panel_of_seven")
		if err == nil {
			t.Fatal("an undeclared arm was accepted — it would run the baseline under a fake label")
		}
		for _, want := range []string{"panel_of_seven", "panel_single", "panel_median3"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name %q so the user can correct it; got: %v", want, err)
			}
		}
	})

	t.Run("an unknown experiment is refused and names the real ones", func(t *testing.T) {
		_, _, _, err := resolveExperimentArm(dir, "no_such_study", "panel_single")
		if err == nil || !strings.Contains(err.Error(), "judge_panel_parity") {
			t.Errorf("want a refusal naming the declared experiments, got: %v", err)
		}
	})

	t.Run("an app with no experiments says so plainly", func(t *testing.T) {
		bare := writeArmSpec(t, "name: quant-research\n")
		_, _, _, err := resolveExperimentArm(bare, "anything", "any")
		if err == nil || !strings.Contains(err.Error(), "no experiments") {
			t.Errorf("want 'declares no experiments', got: %v", err)
		}
	})

	t.Run("an unattached experiment yields no loop rather than a wrong one", func(t *testing.T) {
		unattached := writeArmSpec(t, `
name: x
experiments:
  - id: orphan
    arms: [{id: a}]
loops:
  - name: some_loop
`)
		_, _, loop, err := resolveExperimentArm(unattached, "orphan", "a")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if loop != "" {
			t.Errorf("loop = %q, want empty — nothing declares this experiment", loop)
		}
	})
}

func TestSplitCasesAndRepeatVariant(t *testing.T) {
	got := splitCases(" Case_001 , ,Case_002 ")
	if len(got) != 2 || got[0] != "Case_001" || got[1] != "Case_002" {
		t.Errorf("splitCases = %v", got)
	}
	if n := len(repeatVariant(map[string]any{"arm": "a"}, 3)); n != 3 {
		t.Errorf("repeatVariant produced %d entries, want 3", n)
	}
}

// A loop may attach ONE experiment or SEVERAL. The list form used to unmarshal
// into a bare string field and vanish, leaving the second experiment with
// `loops: null` — never attached, so never passed to refresh_for_cycle, so
// permanently n=0 no matter how many rows it accumulated. That reads as
// "declared but idle" rather than "broken", which is the whole failure class
// this work exists to remove.
func TestExperimentAttachmentAcceptsScalarOrList(t *testing.T) {
	cases := []struct {
		name string
		spec string
		want map[string][]string
	}{
		{"scalar", `
loops:
  - name: interview
    engine: {experiment: judge_panel_parity}
`, map[string][]string{"judge_panel_parity": {"interview"}}},
		{"list", `
loops:
  - name: backtest
    engine: {experiment: [backtest_evidence, backtest_performance]}
`, map[string][]string{
			"backtest_evidence":    {"backtest"},
			"backtest_performance": {"backtest"},
		}},
		{"steps form", `
loops:
  - name: sweep
    steps:
      - {experiment: [a, b]}
      - {experiment: c}
`, map[string][]string{"a": {"sweep"}, "b": {"sweep"}, "c": {"sweep"}}},
		{"none", "loops:\n  - name: plain\n", map[string][]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expLoops(parseExpManifestBytes([]byte(tc.spec)))
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for id, loops := range tc.want {
				if len(got[id]) != len(loops) || (len(loops) > 0 && got[id][0] != loops[0]) {
					t.Errorf("experiment %q attached to %v, want %v", id, got[id], loops)
				}
			}
		})
	}
}
