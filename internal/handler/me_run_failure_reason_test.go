package handler

// A failed run must say WHY.
//
// It said "failed" and nothing else, which is where the reader already was. The
// explanation existed the whole time — the runtime writes it to
// .lumid/journal.jsonl and self-reports it into me_app_runs.metrics — and both
// row builders dropped it:
//
//   - journalRowToRun read only a top-level `reason` the runtime never writes;
//   - runRowFromStore found a step error and then OVERWROTE it with the terse
//     `outcome` code, replacing the cause with its category.
//
// Measured 2026-09-16. Four scoped runs died with
//
//	metrics.command_engine.error =
//	  "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']"
//
// — a stringified list, i.e. a platform bug, not a bad id. The user saw a run
// that silently did nothing, four times, and reported it as "跑不起来" (won't
// run). It ran, it said why, and nothing displayed it. That cost about a day.

import (
	"encoding/json"
	"testing"

	"lumid_identity/models"
)

func TestTheRealFailureIsReported(t *testing.T) {
	// Verbatim from the live row that went unreported.
	metrics := map[string]any{
		"arm":             "panel_median3",
		"cases_evaluated": float64(0),
		"command_engine": map[string]any{
			"error": "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']",
		},
	}
	got := runFailureReason(metrics, "bad_cases")
	if got != "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']" {
		t.Errorf("the cause was not surfaced, got %q", got)
	}
}

func TestSpecificBeatsTerse(t *testing.T) {
	// `outcome` names a category; the error names the cause. Returning the
	// category is what made a failed run indistinguishable from any other.
	m := map[string]any{"error": "boom: the real thing"}
	if got := runFailureReason(m, "bad_cases"); got != "boom: the real thing" {
		t.Errorf("outcome won over the error: %q", got)
	}
}

func TestOutcomeIsTheFallbackNotTheAnswer(t *testing.T) {
	if got := runFailureReason(map[string]any{}, "bad_cases"); got != "bad_cases" {
		t.Errorf("want the outcome when nothing better exists, got %q", got)
	}
	if got := runFailureReason(nil, ""); got != "" {
		t.Errorf("want empty when the row explains nothing, got %q", got)
	}
}

func TestNestedEngineMetricsAreReached(t *testing.T) {
	// The other shape the runtime emits: command_engine.metrics.error.
	m := map[string]any{"command_engine": map[string]any{
		"metrics": map[string]any{"error": "deeper cause"},
	}}
	if got := runFailureReason(m, "bad_cases"); got != "deeper cause" {
		t.Errorf("nested engine error not reached, got %q", got)
	}
}

// The store builder is the DB-backed half. Both builders must agree — this
// file's sibling warns that a run both sources know about otherwise "appears
// twice with the two rows disagreeing about what it is called".
func TestStoreRowCarriesTheCause(t *testing.T) {
	metrics, _ := json.Marshal(map[string]any{
		"outcome": "bad_cases",
		"command_engine": map[string]any{
			"error": "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']",
		},
	})
	row, ok := runRowFromStore(models.MeAppRun{
		App: "mbb-consultant", Loop: "case_eval",
		RunTs: 1789572305, Ok: false, Metrics: string(metrics),
	})
	if !ok {
		t.Fatal("row rejected")
	}
	if row.State != "failed" {
		t.Errorf("state = %q, want failed", row.State)
	}
	if row.Reason != "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']" {
		t.Errorf("store row reports %q, not the cause", row.Reason)
	}
}

// Regression on the overwrite: a step error must not be replaced by `outcome`.
func TestAStepErrorSurvivesTheOutcomeCode(t *testing.T) {
	events := `{"step_errors":["judge seat timed out"],"outcome":"bad_cases"}`
	metrics, _ := json.Marshal(map[string]any{"outcome": "bad_cases"})
	row, ok := runRowFromStore(models.MeAppRun{
		App: "a", Loop: "l", RunTs: 1789572305, Ok: false,
		Events: &events, Metrics: string(metrics),
	})
	if !ok {
		t.Fatal("row rejected")
	}
	if row.Reason != "judge seat timed out" {
		t.Errorf("the specific step error was replaced by %q", row.Reason)
	}
}

func TestASucceededRunNeedsNoReason(t *testing.T) {
	metrics, _ := json.Marshal(map[string]any{"avg_question_score": 0.678})
	row, ok := runRowFromStore(models.MeAppRun{
		App: "a", Loop: "l", RunTs: 1789573389, Ok: true, Metrics: string(metrics),
	})
	if !ok {
		t.Fatal("row rejected")
	}
	if row.State != "succeeded" {
		t.Errorf("state = %q", row.State)
	}
	if row.Reason != "" {
		t.Errorf("a successful run invented a reason: %q", row.Reason)
	}
}
