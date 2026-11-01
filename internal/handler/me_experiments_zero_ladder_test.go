package handler

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// The zero-marker ladder used to be written out twice — the disk path and the
// cross-node fallback in MeAppExperiments — and the copies drifted: the
// fallback ran markStarved and markUndispatched but not markUnfed, so an
// unfed experiment on a tenant install whose ledger identity cannot read
// rendered as the bare "no results yet" the markers exist to replace.
//
// This pins the shared helper, which is what both paths now call. It is
// deliberately written against a row with NO state: the fallback has none, and
// the bug was that a missing state quietly skipped a marker that never reads
// state.
func TestZeroLadderRunsEveryMarkerWithoutState(t *testing.T) {
	d := &expDecl{ID: "unfed_arm", Metric: map[string]any{"name": "avg_question_score"}}
	row := gin.H{"n_results": 0}
	markZeroReasons(row, "user-sub", "some-app", d, nil, nil)
	if row["unfed"] != true {
		t.Fatalf("an unfed experiment lost its reason when state was absent: %v", row)
	}
	if _, ok := row["starved"]; ok {
		t.Fatalf("a marker that needs a feeding loop fired with none: %v", row)
	}
}

// The dispatch-only shape must still say "nothing has dispatched it" — the
// case markUndispatched was written for (mbb-consultant/analyst_local_gpu).
func TestZeroLadderExplainsUndispatched(t *testing.T) {
	d := &expDecl{ID: "analyst_local_gpu", Metric: map[string]any{"name": "avg_question_score"},
		Dispatch: map[string]any{"ask": "which arm?"}}
	row := gin.H{"n_results": 0}
	markZeroReasons(row, "", "", d, nil, nil)
	if row["starved"] != true {
		t.Fatalf("a dispatch-only experiment nobody dispatched says nothing: %v", row)
	}
	if _, ok := row["unfed"]; ok {
		t.Fatalf("a dispatched experiment was called unfed: %v", row)
	}
}

// An experiment that HAS rows must be left alone by every marker.
func TestZeroLadderLeavesAFedExperimentAlone(t *testing.T) {
	d := &expDecl{ID: "with_rows", Metric: map[string]any{"name": "m"}}
	row := gin.H{"n_results": 12, "verdict": "v"}
	markZeroReasons(row, "", "", d, nil, []string{"a_loop"})
	for _, k := range []string{"unfed", "starved", "unrecorded"} {
		if _, ok := row[k]; ok {
			t.Fatalf("%s fired on an experiment with results: %v", k, row)
		}
	}
	if row["verdict"] != "v" {
		t.Fatalf("the row was altered: %v", row)
	}
}

// A dispatch that names a loop the experiment is NOT declared under still has
// runs that explain the zero. Before feederLoops, feeding stayed empty (the
// loop lists a different experiment), so markStarved returned immediately,
// markUnfed abstained on the dispatch, and markUndispatched abstained on the
// loop name — every marker passed and the card said only "no results yet".
func TestDispatchLoopRunsExplainTheZero(t *testing.T) {
	d := &expDecl{ID: "analyst_local_gpu", Metric: map[string]any{"name": "avg_question_score"},
		Dispatch: map[string]any{"loop": "case_eval"}}
	got := feederLoops(d, nil)
	if len(got) != 1 || got[0] != "case_eval" {
		t.Fatalf("the dispatch loop's runs were not reachable: %v", got)
	}
	// Declared feeder and dispatch agreeing must not duplicate the loop.
	both := feederLoops(d, []string{"case_eval"})
	if len(both) != 1 {
		t.Fatalf("a loop named twice was listed twice: %v", both)
	}
}

// The reason must carry the CAUSE, not just the fact. case_eval reports its
// failures as command_engine.failures[] with error/flags/error all null, so
// the card read "failed its last 5 run(s)" and stopped.
func TestRunErrorTextReadsPerItemFailures(t *testing.T) {
	blob := `{"command_engine":{"failures":[
		{"case":"a","error":"analyst call failed: HTTP Error 503: Service Unavailable"},
		{"case":"b","error":"analyst call failed: HTTP Error 503: Service Unavailable"},
		{"case":"c","error":"judge returned no scores"}]}}`
	got := runErrorText(blob)
	if !strings.Contains(got, "503") || !strings.Contains(got, "judge returned no scores") {
		t.Fatalf("per-item failures were not distilled: %q", got)
	}
	if strings.Count(got, "503") != 1 {
		t.Fatalf("the same error was repeated once per case: %q", got)
	}
}
