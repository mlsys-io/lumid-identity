package handler

// One run, two surfaces, one id.
//
// The `runs` app-data tool feeds a surface's table, and a surface links a row
// with `row_href: …?cycle={cycle_id}`. The cycle inspector, cycle-log and
// cycle-detail handlers all key on the cycle-dir id. The tool used to publish
// only `run_ts` — UNIX SECONDS — so quant-research's "Backtests for this
// strategy" table produced `?cycle=1788663446`, which matches no cycle: the
// deep link fell back to the NEWEST run, and a backtest's submit run was
// indistinguishable from its poll run. Reported 2026-09-06.
//
// The invariant is cross-surface, so assert it across the two producers rather
// than restating either one's output: whatever the runs tool offers as a link
// key must be exactly what the cycles list calls the same run.

import (
	"testing"
	"time"

	"lumid_identity/models"
)

func TestRunsToolLinkKeyMatchesTheCyclesListID(t *testing.T) {
	run := models.MeAppRun{
		App:   "quant-research",
		Loop:  "backtest",
		RunTs: time.Date(2026, 9, 6, 10, 57, 26, 0, time.UTC).Unix(),
		Ok:    true,
	}

	// What the cycles list (and therefore the run tree, the log and the detail
	// drill-in) calls this run.
	listItem, ok := cycleRowFromStore(run)
	if !ok {
		t.Fatalf("cycleRowFromStore rejected a valid run")
	}

	// What a surface's row_href would interpolate for the same run.
	linkKey := runTsToCycleID(run.RunTs)

	if linkKey != listItem.Ts {
		t.Fatalf("a row links to cycle=%q but the cycles list calls that run %q — "+
			"the deep link cannot resolve", linkKey, listItem.Ts)
	}
	// Pin the shape too: an epoch here is the original defect, and it compares
	// unequal to every cycle id rather than failing loudly.
	if linkKey != "20260906T105726Z" {
		t.Fatalf("link key = %q, want the cycle-dir id 20260906T105726Z", linkKey)
	}
}

// A run the store cannot place in time must not be linked at all. Emitting a
// 1970 cycle_id would render a confidently wrong link instead of degrading to
// the workflow's newest run.
func TestUnplaceableRunYieldsNoLinkKey(t *testing.T) {
	for _, bad := range []int64{0, -1, 12345} {
		if got := runTsToCycleID(bad); got != "" {
			t.Errorf("runTsToCycleID(%d) = %q, want empty so the row omits cycle_id", bad, got)
		}
	}
}
