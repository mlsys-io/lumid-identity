package handler

// LQ-20261030 — "a generic `no results yet` does not reveal which condition
// applies."
//
// Measured against production on 2026-10-30: study `qa_custom_coverage_20261030`
// stayed at 0 results after two SUCCESSFUL runs of the loop attached to it,
// `qa_custom_analyze_20261030`, each of which recorded
//
//	"strategies_analyzed": 3,
//	"primary_metric": {"name": "strategies_analyzed", "value": 3}
//
// in its own run blob — while the study's state, recomputed at the very
// instant of that run, said n_results: 0 with n_zero_reason: null. The card
// therefore rendered the waiting message, which is the one thing the report
// says is not good enough.
//
// The cause is not metric nesting (Backtest's working output nests the same
// way) and not staleness (state was written at 14:29:24.047, the run is
// 2026-10-30T14:29:24Z — same second). It is that commands/analyze.py never
// calls experiments.record_result, so the ledger evaluate() reads is empty by
// construction. Nothing in the state can distinguish that from "has not run";
// the run store can, and that is what these tests pin.

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/models"
)

// The production row: fresh state, empty ledger, one successful run whose blob
// carries the declared metric.
func TestUnrecordedZeroNamesTheLoopThatRan(t *testing.T) {
	runTs := time.Date(2026, 10, 30, 14, 29, 24, 0, time.UTC).Unix()
	runs := []models.MeAppRun{{
		Loop: "qa_custom_analyze_20261030", RunTs: runTs, Ok: true,
		Metrics: `{"strategies_analyzed":3,"primary_metric":{"name":"strategies_analyzed","value":3}}`,
	}}
	row := gin.H{
		"experiment_id": "qa_custom_coverage_20261030",
		"n_results":     0,
		// exactly what json.Unmarshal into map[string]any produces
		"metric_keys_seen": []any{},
		"n_zero_reason":    nil,
		"state_updated_at": "2026-10-30T14:29:24Z",
	}
	markUnrecorded(row, runs, []string{"qa_custom_analyze_20261030"}, "strategies_analyzed")

	reason, _ := row["n_zero_reason"].(string)
	if reason == "" {
		t.Fatal("a study whose loop ran and recorded nothing must say so; the card falls back to `no results yet`")
	}
	if row["unrecorded"] != true {
		t.Error("flag missing — the card renders any n_zero_reason as `metric mismatch`, and this is not one")
	}
	for _, want := range []string{
		"qa_custom_analyze_20261030",
		"2026-10-30T14:29:24Z",
		"strategies_analyzed=3", // the measurement that exists but is invisible
		"record_result",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}

// ...and it must reach the row through the real assembly, not only when called
// by hand: the guard that used to sit in front of this (markStarved's ok-run
// early return) is the reason the card stayed silent.
func TestStarvedReasonStillOwnsFailedRuns(t *testing.T) {
	// A failed run is starvation, not non-recording — the two must not be
	// told with the same sentence.
	runTs := time.Date(2026, 10, 30, 14, 29, 24, 0, time.UTC).Unix()
	failed := models.MeAppRun{Loop: "l", RunTs: runTs, Ok: false,
		Metrics: `{"command_engine":{"error":"boom"}}`}
	st, reason := starvedReason([]models.MeAppRun{failed}, []string{"l"})
	if !st || !strings.Contains(reason, "failed its last 1 run(s)") {
		t.Fatalf("failed runs are starved: %v %q", st, reason)
	}
	row := gin.H{"n_results": 0, "metric_keys_seen": []any{}, "state_updated_at": "2026-10-30T14:29:24Z"}
	markUnrecorded(row, []models.MeAppRun{failed}, []string{"l"}, "m")
	if r, _ := row["n_zero_reason"].(string); r != "" {
		t.Errorf("a failed run already has a reason; got %q", r)
	}
}

func TestUnrecordedStaysQuiet(t *testing.T) {
	runTs := time.Date(2026, 10, 30, 14, 29, 24, 0, time.UTC).Unix()
	ok := models.MeAppRun{Loop: "l", RunTs: runTs, Ok: true,
		Metrics: `{"strategies_analyzed":3}`}
	cases := []struct {
		name string
		row  gin.H
		runs []models.MeAppRun
		why  string
	}{
		{
			// A ledger with rows that lack the metric is n_zero_reason's own
			// fact (the SDK writes it), and must keep its sharper wording.
			"rows exist", gin.H{"n_results": 0, "metric_keys_seen": []any{"other"},
				"state_updated_at": "2026-10-30T14:29:24Z"}, []models.MeAppRun{ok},
			"the SDK already explains a dropped-rows zero",
		},
		{
			"has results", gin.H{"n_results": 3, "metric_keys_seen": []any{"strategies_analyzed"},
				"state_updated_at": "2026-10-30T14:29:24Z"}, []models.MeAppRun{ok},
			"a study with results has nothing to explain",
		},
		{
			// evaluate() runs AFTER the cycle, so a state older than the run
			// means evaluate had not seen it yet: that IS staleness, and
			// markStaleState's business rather than this one.
			"state predates the run", gin.H{"n_results": 0, "metric_keys_seen": []any{},
				"state_updated_at": "2026-10-30T14:00:00Z"}, []models.MeAppRun{ok},
			"an older state is a stale snapshot, not a non-recording loop",
		},
		{
			"no state at all", gin.H{"n_results": 0, "metric_keys_seen": []any{}}, []models.MeAppRun{ok},
			"evaluate has never run — this one really is `not yet`",
		},
		{
			"no runs", gin.H{"n_results": 0, "metric_keys_seen": []any{},
				"state_updated_at": "2026-10-30T14:29:24Z"}, nil,
			"markStarved already says the loop never ran",
		},
		{
			"SDK reason present", gin.H{"n_results": 0, "metric_keys_seen": []any{},
				"n_zero_reason":    "1 row(s) present but none carries metric 'm'",
				"state_updated_at": "2026-10-30T14:29:24Z"}, []models.MeAppRun{ok},
			"a sharper reason must not be overwritten",
		},
	}
	for _, c := range cases {
		before, _ := c.row["n_zero_reason"].(string)
		markUnrecorded(c.row, c.runs, []string{"l"}, "strategies_analyzed")
		if after, _ := c.row["n_zero_reason"].(string); after != before {
			t.Errorf("%s: should stay silent (%s), got %q", c.name, c.why, after)
		}
	}
}

// A loop that ran fine but computes something else entirely: the study will
// never fill, and the reason must say that rather than blaming recording.
func TestUnrecordedSaysWhenTheLoopDoesNotComputeTheMetric(t *testing.T) {
	runTs := time.Date(2026, 10, 30, 14, 29, 24, 0, time.UTC).Unix()
	row := gin.H{"n_results": 0, "metric_keys_seen": []any{},
		"state_updated_at": "2026-10-30T14:29:24Z"}
	markUnrecorded(row, []models.MeAppRun{{Loop: "l", RunTs: runTs, Ok: true,
		Metrics: `{"something_else":1}`}}, []string{"l"}, "strategies_analyzed")
	reason, _ := row["n_zero_reason"].(string)
	if !strings.Contains(reason, "carries no strategies_analyzed") {
		t.Fatalf("got %q, want the missing-metric sentence", reason)
	}
	if strings.Contains(reason, "record_result") {
		t.Errorf("got %q — its output has no such value, so recording is not the fault", reason)
	}
}

// quant-research/forward_evidence: forward_test DOES call record_result, but
// only for a scoped read. An unscoped run skips on purpose and says why in
// metrics.experiment_skip_reason. The card must carry that sentence — not the
// generic "forward_test does not call record_result", which would be false —
// and it must do so even when the study has no state yet (a study whose only
// runs skipped never gets a ledger row for evaluate() to summarise).
func TestUnrecordedPrefersTheLoopsOwnSkipReason(t *testing.T) {
	runTs := time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC).Unix()
	runs := []models.MeAppRun{{
		Loop: "forward_test", RunTs: runTs, Ok: true,
		Metrics: `{"forward_submit_rate":1,"experiment_rows":0,` +
			`"experiment_skip_reason":"unscoped read (no strategy_id) mixes strategies, so it is evidence for none — run with args.strategy_id to record a row"}`,
	}}
	for name, row := range map[string]gin.H{
		"no state": {"n_results": 0, "metric_keys_seen": []any{}, "n_zero_reason": nil},
		"fresh state": {"n_results": 0, "metric_keys_seen": []any{}, "n_zero_reason": nil,
			"state_updated_at": "2026-11-02T03:00:00Z"},
	} {
		markUnrecorded(row, runs, []string{"forward_test"}, "forward_submit_rate")
		reason, _ := row["n_zero_reason"].(string)
		if !strings.Contains(reason, "unscoped read") || !strings.Contains(reason, "forward_test") {
			t.Errorf("%s: reason %q does not carry the loop's own skip reason", name, reason)
		}
		if strings.Contains(reason, "does not.") {
			t.Errorf("%s: reason %q claims the loop never records — false for forward_test", name, reason)
		}
		if row["unrecorded"] != true {
			t.Errorf("%s: unrecorded flag missing", name)
		}
	}
}

// The skip reason must not override a sharper existing reason, nor fire on a
// failed run (that is starvation's sentence).
func TestSkipReasonRespectsExistingReasonAndFailedRuns(t *testing.T) {
	runTs := time.Date(2026, 11, 2, 3, 0, 0, 0, time.UTC).Unix()
	blob := `{"experiment_skip_reason":"x"}`
	row := gin.H{"n_results": 0, "metric_keys_seen": []any{}, "n_zero_reason": "state is stale"}
	markUnrecorded(row, []models.MeAppRun{{Loop: "l", RunTs: runTs, Ok: true, Metrics: blob}}, []string{"l"}, "m")
	if row["n_zero_reason"] != "state is stale" {
		t.Errorf("existing reason overwritten: %v", row["n_zero_reason"])
	}
	row = gin.H{"n_results": 0, "metric_keys_seen": []any{}}
	markUnrecorded(row, []models.MeAppRun{{Loop: "l", RunTs: runTs, Ok: false, Metrics: blob}}, []string{"l"}, "m")
	if _, set := row["n_zero_reason"]; set {
		t.Errorf("failed run produced an unrecorded reason: %v", row["n_zero_reason"])
	}
}

func TestStringFromBlob(t *testing.T) {
	for blob, want := range map[string]string{
		`{"experiment_skip_reason":" top "}`:                   "top",
		`{"command_engine":{"experiment_skip_reason":"deep"}}`: "deep",
		`{"experiment_skip_reason":3}`:                         "",
		`{"experiment_skip_reason":"  "}`:                      "",
		`not json`:                                             "",
		``:                                                     "",
	} {
		if got := stringFromBlob(blob, "experiment_skip_reason"); got != want {
			t.Errorf("stringFromBlob(%q) = %q, want %q", blob, got, want)
		}
	}
}
