package handler

// Reconstructing cycles and runs from the run store.
//
// Identity mounts one volume (the signing keys), so every walk of data/cycles
// or data/journal.jsonl returns empty for every app and every user — measured
// 2026-09-13: cycle-log total 0, /me/cycles 0, /me/runs 0. `tenantHasRuns` is
// derived from /me/cycles and gates the FailureCard, the step-error pill,
// StageDetail and `lastRan`, and health() short-circuits to "Not run yet"
// without it. So a FAILED cycle was indistinguishable from one that never
// happened.

import (
	"strings"
	"testing"
	"time"

	"lumid_identity/models"
)

func TestRunTsToCycleIDIsTheShapeEveryParserExpects(t *testing.T) {
	// The UI's date parsers understand the cycle-dir id and return null for a
	// decimal epoch, which is why DB-reconstructed trajectory nodes rendered
	// with no timestamp at all.
	got := runTsToCycleID(time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC).Unix())
	if got != "20260914T010203Z" {
		t.Errorf("runTsToCycleID = %q, want 20260914T010203Z", got)
	}
	for _, bad := range []int64{0, -1, 12345} {
		if s := runTsToCycleID(bad); s != "" {
			// 12345 is not a unix second; inventing a 1970 date would put a
			// fake run at the top of a descending list forever.
			t.Errorf("runTsToCycleID(%d) = %q, want empty", bad, s)
		}
	}
}

func TestMergeCycleRowsPrefersDiskAndAddsTheRest(t *testing.T) {
	disk := []cycleListItem{
		{App: "a", Loop: "l", Ts: "20260914T010000Z", OK: true, StepCount: 4},
	}
	db := []cycleListItem{
		{App: "a", Loop: "l", Ts: "20260914T010000Z", OK: true},  // same cycle
		{App: "a", Loop: "l", Ts: "20260914T020000Z", OK: false}, // only in the store
		{App: "b", Loop: "l", Ts: "20260914T010000Z", OK: true},  // another app
	}
	got := mergeCycleRows(disk, db)
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3 (1 disk + 2 store)", len(got))
	}
	// Disk wins the collision: it is the richer record of the SAME cycle, with
	// a step count the store cannot have.
	if got[0].StepCount != 4 {
		t.Errorf("the store row overwrote the disk row: %+v", got[0])
	}
	var failed bool
	for _, r := range got {
		if r.Ts == "20260914T020000Z" && !r.OK {
			failed = true
		}
	}
	if !failed {
		t.Error("the failed cycle the store knows about was dropped")
	}
}

func TestMergeRunRowsDeduplicatesByRunID(t *testing.T) {
	disk := []RunRow{{RunID: "scheduled:a:l:20260914T010000Z", State: "succeeded", CycleDir: "/x"}}
	db := []RunRow{
		{RunID: "scheduled:a:l:20260914T010000Z", State: "succeeded"},
		{RunID: "scheduled:a:l:20260914T020000Z", State: "failed"},
	}
	got := mergeRunRows(disk, db)
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0].CycleDir != "/x" {
		t.Error("the disk row lost its cycle_dir to a store row for the same run")
	}
	if got[1].State != "failed" {
		t.Errorf("second row state = %q, want failed", got[1].State)
	}
}

// The two sources must agree field-for-field about the SAME cycle, or a run
// both of them know about appears twice, with the two rows disagreeing about
// what it is called. Built by calling the REAL journal converter rather than
// restating its shape — restating it is how they would drift.
func TestBothSourcesDescribeACycleTheSameWay(t *testing.T) {
	when := time.Date(2026, 9, 14, 1, 2, 3, 0, time.UTC)
	ts := runTsToCycleID(when.Unix())

	fromDisk := journalRowToRun("demo", map[string]any{
		"loop": "case_eval", "ts": when.Format(time.RFC3339),
		"ok": true, "cycle_dir": "/anywhere/data/cycles/case_eval/" + ts,
	})
	if fromDisk.RunID == "" {
		t.Fatal("journalRowToRun produced no row; the fixture no longer matches a cycle row")
	}

	// The store's version of the same cycle, from the REAL producer.
	fromDB, ok := runRowFromStore(models.MeAppRun{
		UserSub: "sub-1", App: "demo", Loop: "case_eval",
		RunTs: when.Unix(), Ok: true, Metrics: "{}",
	})
	if !ok {
		t.Fatal("runRowFromStore rejected a well-formed row")
	}
	for _, f := range []struct{ name, a, b string }{
		{"RunID", fromDisk.RunID, fromDB.RunID},
		{"WorkflowSlug", fromDisk.WorkflowSlug, fromDB.WorkflowSlug},
		{"Kind", fromDisk.Kind, fromDB.Kind},
		{"Name", fromDisk.Name, fromDB.Name},
		{"State", fromDisk.State, fromDB.State},
		{"StartedISO", fromDisk.StartedISO, fromDB.StartedISO},
	} {
		if f.a != f.b {
			t.Errorf("%s diverges: journal=%q store=%q", f.name, f.a, f.b)
		}
	}
}

// Neither reconstruction may claim detail the store does not carry.
func TestReconstructionDoesNotInventDetail(t *testing.T) {
	db := cycleRowsFromDB("", "", "") // no DB configured in unit tests
	if db != nil {
		t.Errorf("expected nil without a user/DB, got %v", db)
	}
	if r := runRowsFromDB("", time.Now(), time.Now()); r != nil {
		t.Errorf("expected nil without a user/DB, got %v", r)
	}
}

// A run the store recorded as NOT ok must read as failed. This is the whole
// reason the reconstruction exists: before it, a failed cycle and a cycle that
// never happened were the same thing at every surface but the Home rail.
func TestAFailedCycleReadsAsFailed(t *testing.T) {
	row, ok := runRowFromStore(models.MeAppRun{
		App: "demo", Loop: "case_eval", RunTs: 1789000000, Ok: false,
		Metrics: `{"outcome":"engine crashed"}`,
	})
	if !ok {
		t.Fatal("rejected a well-formed row")
	}
	if row.State != "failed" {
		t.Errorf("state = %q, want failed", row.State)
	}
	if row.Reason != "engine crashed" {
		t.Errorf("reason = %q, want the outcome the app recorded", row.Reason)
	}
	item, _ := cycleRowFromStore(models.MeAppRun{
		App: "demo", Loop: "case_eval", RunTs: 1789000000, Ok: false, Metrics: "{}",
	})
	if item.OK {
		t.Error("the cycle list shows a failed cycle as ok")
	}
}

func TestStoreRowsCarryCostAndDuration(t *testing.T) {
	d := 42.5
	item, _ := cycleRowFromStore(models.MeAppRun{
		App: "demo", Loop: "l", RunTs: 1789000000, Ok: true, DurationS: &d,
		Metrics: `{"cost":{"cost_usd":0.25,"total_tokens":1234},"branch_label":"gemma4_local"}`,
	})
	if item.Duration != 42.5 || item.CostUSD != 0.25 || item.TotalTokens != 1234 {
		t.Errorf("lost cost/duration: %+v", item)
	}
	if item.BranchLabel != "gemma4_local" {
		t.Errorf("branch label = %q", item.BranchLabel)
	}
	// Never invented: the store has no per-step rows.
	if item.StepCount != 0 || item.Running {
		t.Errorf("invented detail the store does not carry: %+v", item)
	}
}

// TestComputeEngineFailureIsLegibleOnTheSurface pins the 2026-09-21 case: a
// Pattern-C loop (body = a compute DAG) refused by Lumilake surfaced as
// reason "ran". runFailureReason knew command_engine but not compute_engine,
// so it fell through to the outcome string — which reads like a success word
// and tells the researcher nothing.
func TestComputeEngineFailureIsLegibleOnTheSurface(t *testing.T) {
	metrics := map[string]any{
		"rows": 0,
		"compute_engine": map[string]any{
			"ok":          false,
			"error":       "ComputeError: submit rejected (403): write on object-prefix/lumilake-runs/ denied",
			"engine_type": "lumilake",
		},
	}
	got := runFailureReason(metrics, "ran")
	if got == "ran" {
		t.Fatal("a compute failure must not surface as its outcome string")
	}
	if !strings.Contains(got, "403") {
		t.Fatalf("reason must carry what actually failed, got %q", got)
	}
}

// TestCommandEngineStillWins guards the older Pattern-B path, which was fixed
// first and must not regress behind the new branch.
func TestCommandEngineStillWins(t *testing.T) {
	metrics := map[string]any{
		"command_engine": map[string]any{"error": "unknown case id(s)"},
	}
	if got := runFailureReason(metrics, "ran"); got != "unknown case id(s)" {
		t.Fatalf("command_engine reason lost, got %q", got)
	}
}
