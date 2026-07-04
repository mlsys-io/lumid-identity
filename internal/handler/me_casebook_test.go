package handler

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCasebookFixture lays down a minimal app bundle: an .xpcloud.yaml with the
// given loops block + an experiment results.jsonl that scores one case. Returns
// the app dir.
func writeCasebookFixture(t *testing.T, loopsYAML string) string {
	t.Helper()
	appDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(appDir, ".xpcloud.yaml"), []byte(loopsYAML), 0644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	expDir := filepath.Join(appDir, "data", "experiments", "casebook_regression")
	if err := os.MkdirAll(expDir, 0755); err != nil {
		t.Fatalf("mkdir exp: %v", err)
	}
	// state.json declares the primary metric; results.jsonl scores one case
	// across two cycles (≥2 points so the metric trajectory also materializes).
	// These are per-case AGGREGATE rows (dims.case_id, NO q_id): the scorer
	// intentionally skips per-question sub-score rows (those carry q_id) so the
	// case score + metric trajectory use only the aggregate primary metric — see
	// casebookScoresFromExperiments' perQuestion filter.
	if err := os.WriteFile(filepath.Join(expDir, "state.json"), []byte(`{"metric":"avg_question_score"}`), 0644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	results := `{"ts":"2026-06-01T00:00:00Z","cycle_ts":"20260601T000000Z","variant_id":"current","metrics":{"avg_question_score":0.6},"dims":{"case_id":"Case_001"}}
{"ts":"2026-06-02T00:00:00Z","cycle_ts":"20260602T000000Z","variant_id":"current","metrics":{"avg_question_score":0.8},"dims":{"case_id":"Case_001"}}
`
	if err := os.WriteFile(filepath.Join(expDir, "results.jsonl"), []byte(results), 0644); err != nil {
		t.Fatalf("write results: %v", err)
	}
	return appDir
}

// TestCasebookFallbackNoExperimentLoop is the WS-4b regression: a loop that
// declares NO experiment used to return silent-empty scores (the bug behind
// "mbb-ai cases run but show no score"). It must now fall back to the app's
// experiment results and tag the provenance "app_fallback".
func TestCasebookFallbackNoExperimentLoop(t *testing.T) {
	// case_cycle declares no experiment; regression_sweep declares one.
	spec := `name: mbb-ai
loops:
  - name: case_cycle
  - name: regression_sweep
    engine:
      experiment: casebook_regression
`
	appDir := writeCasebookFixture(t, spec)

	// Sanity: the no-experiment loop indeed resolves to an empty experiment set.
	if got := loopExperiments(appDir, "case_cycle"); len(got) != 0 {
		t.Fatalf("loopExperiments(case_cycle) = %v, want empty", got)
	}

	// Mirror MeCasebook's call for ?loop=case_cycle (strict, empty allowed).
	expAllow := map[string]bool{}
	for _, x := range loopExperiments(appDir, "case_cycle") {
		expAllow[x] = true
	}
	scores, _, scoredVia := casebookScoresFromExperiments(appDir, expAllow, true /* strict: loop given */)

	if scoredVia != "app_fallback" {
		t.Errorf("scored_via = %q, want %q", scoredVia, "app_fallback")
	}
	hist, ok := scores["Case_001"]
	if !ok || len(hist) == 0 {
		t.Fatalf("expected Case_001 to carry scores via fallback, got scores=%v", scores)
	}
	// The roster must surface the case with a latest score (the user-visible fix).
	cases := casebookRoster(appDir, scores)
	var found *casebookCase
	for i := range cases {
		if cases[i].ID == "Case_001" {
			found = &cases[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("Case_001 missing from roster %v", cases)
	}
	if found.LatestScore == nil {
		t.Fatalf("Case_001 has no latest_score after fallback")
	}
	if *found.LatestScore != 0.8 {
		t.Errorf("Case_001 latest_score = %v, want 0.8 (newest cycle)", *found.LatestScore)
	}
}

// TestCasebookLoopExperimentProvenance confirms the non-fallback paths keep
// their distinct provenance tags: a loop WITH a declared experiment →
// "loop_experiment"; no loop filter (back-compat) → "all_experiments".
func TestCasebookLoopExperimentProvenance(t *testing.T) {
	spec := `name: mbb-ai
loops:
  - name: regression_sweep
    engine:
      experiment: casebook_regression
`
	appDir := writeCasebookFixture(t, spec)

	// Loop declaring its own experiment → strict, allowed populated.
	allow := map[string]bool{}
	for _, x := range loopExperiments(appDir, "regression_sweep") {
		allow[x] = true
	}
	if len(allow) == 0 {
		t.Fatalf("regression_sweep should declare casebook_regression")
	}
	scores, _, via := casebookScoresFromExperiments(appDir, allow, true)
	if via != "loop_experiment" {
		t.Errorf("scored_via = %q, want loop_experiment", via)
	}
	if len(scores["Case_001"]) == 0 {
		t.Errorf("expected Case_001 scored under its loop experiment")
	}

	// No loop filter (back-compat app-wide view) → all_experiments.
	_, _, viaAll := casebookScoresFromExperiments(appDir, map[string]bool{}, false)
	if viaAll != "all_experiments" {
		t.Errorf("scored_via (non-strict) = %q, want all_experiments", viaAll)
	}
}
