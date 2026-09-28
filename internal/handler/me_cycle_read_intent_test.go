package handler

// Per-step cycle detail for the owner, read on the scheduler (cycle_read), and
// one `ok` for a cycle across the run list, /me/cycles and the drill-down.
// DB-backed tests skip without TEST_MYSQL_DSN (see setupStaleReadsDB).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"lumid_identity/models"
)

// A Pattern-A cycle as the runner writes it: summary["ok"] was initialised
// True and never lowered, the failure is in step_errors (and its sidecar).
var patternACycle = map[string]string{
	"cycle.json":         `{"ok": true, "outcome": "ran", "step_errors": [{"step": "s2", "error": "boom"}]}`,
	"step_errors.json":   `[{"step": "s2", "error": "boom"}]`,
	"s1.json":            `{"skill": "observe", "ok": true, "output": {"summary": "saw 3"}}`,
	"s2.json":            `{"skill": "act", "ok": false, "error": "boom"}`,
	"step_log.json":      `[{"step": "s1"}, {"step": "s2"}]`,
	"observations.json":  `{"best_accuracy_so_far": 0.5}`,
	"prompt_audit.jsonl": `{"step_id": "s1", "prompt_sha256": "abc", "instructions_preview": "look"}` + "\n",
}

func writeCycle(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCycleOutcomeOKFollowsTheRunStoreRule(t *testing.T) {
	for _, c := range []struct {
		name    string
		summary string
		sidecar string
		want    bool
	}{
		{"clean", `{"ok": true}`, "", true},
		{"no ok key", `{}`, "", true},
		{"ok false", `{"ok": false}`, "", false},
		{"ok true beside step errors", `{"ok": true, "step_errors": [{"step": "s"}]}`, "", false},
		{"ok true, errors only in the sidecar", `{"ok": true}`, `[{"step": "s"}]`, false},
		{"empty step errors", `{"ok": true, "step_errors": []}`, `[]`, true},
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(c.summary), &m)
		if got := cycleOutcomeOK(m, []byte(c.sidecar)); got != c.want {
			t.Errorf("%s: cycleOutcomeOK = %v, want %v", c.name, got, c.want)
		}
	}
}

// The drill-down, the disk list and the run store must say the same thing
// about one cycle. cycle.json alone said ok:true; the store said failed.
func TestCycleDetailOKAgreesWithRunList(t *testing.T) {
	dir := t.TempDir()
	writeCycle(t, dir, patternACycle)
	d := cycleDetailFromFiles("a", "l", "20260928T010203Z", readCycleDirFiles(dir))
	if d["ok"] != false {
		t.Fatalf("detail ok = %v, want false", d["ok"])
	}
	sum := d["summary"].(map[string]any)
	if sum["ok"] != false || sum["ok_as_written"] != true {
		t.Fatalf("summary ok = %v, ok_as_written = %v; want false / true", sum["ok"], sum["ok_as_written"])
	}
	// The store row the runner self-reports for the same cycle
	// (`ok: not step_errors and summary.ok is not False`).
	row, _ := runRowFromStore(models.MeAppRun{App: "a", Loop: "l", RunTs: 1790557323, Ok: false})
	if row.State != "failed" {
		t.Fatalf("store row state = %q", row.State)
	}
}

// Disk and scheduler must yield the same drill-down for the same files.
func TestCycleDetailFromFilesMatchesTheDiskShape(t *testing.T) {
	dir := t.TempDir()
	writeCycle(t, dir, patternACycle)
	d := cycleDetailFromFiles("a", "l", "t", readCycleDirFiles(dir))
	steps := d["steps"].([]cycleStep)
	ids := []string{}
	for _, s := range steps {
		ids = append(ids, s.StepID)
	}
	// step_log.json and step_errors.json are lists, not step records.
	if want := []string{"observations", "s1", "s2"}; !reflect.DeepEqual(ids, want) {
		t.Fatalf("step ids = %v, want %v", ids, want)
	}
	if steps[1].PromptSHA != "abc" || steps[1].OutputSummary != "saw 3" {
		t.Fatalf("s1 = %+v", steps[1])
	}
	if steps[2].OK || steps[2].Error != "boom" {
		t.Fatalf("s2 = %+v", steps[2])
	}
	if _, ok := d["files"].(map[string]any)["observations"]; !ok {
		t.Fatalf("sidecar observations missing: %v", d["files"])
	}
	// The same bytes, delivered as the picker's string map, parse the same.
	viaIntent := cycleFiles{}
	for n, c := range patternACycle {
		viaIntent[n] = []byte(c)
	}
	d2 := cycleDetailFromFiles("a", "l", "t", viaIntent)
	if !reflect.DeepEqual(d["steps"], d2["steps"]) || !reflect.DeepEqual(d["summary"], d2["summary"]) {
		t.Fatal("scheduler-read files parse differently from the same files on disk")
	}
}

// ── via the scheduler (DB-backed) ────────────────────────────────────────────

func cycleReadEnvelope(t *testing.T, data map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"ok": true, "action": cycleReadAction, "data": data})
	return string(b)
}

func TestCycleDetailViaSchedulerForTheOwner(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "user-C", "c-app")
	got := fakePicker(t, db, "user-C", cycleReadAction, "done", cycleReadEnvelope(t, map[string]any{
		"ok": true, "exists": true, "running": false, "files": patternACycle, "skipped": []string{"huge.json"},
	}))
	d, found, why := cycleDetailResolved(context.Background(), "user-C", "c-app", "l", "20260928T010203Z")
	if !found || why != "" {
		t.Fatalf("found=%v why=%q", found, why)
	}
	if p := <-got; p["app"] != "c-app" || p["loop"] != "l" || p["ts"] != "20260928T010203Z" {
		t.Fatalf("picker payload = %v", p)
	}
	if d["source"] != "scheduler" || d["ok"] != false || len(d["steps"].([]cycleStep)) != 3 {
		t.Fatalf("detail = %v", d)
	}
	if sk, _ := d["skipped_files"].([]string); len(sk) != 1 {
		t.Fatalf("skipped_files = %v", d["skipped_files"])
	}
	// A finished cycle is served from cache: no second intent.
	if _, found, _ := cycleDetailResolved(context.Background(), "user-C", "c-app", "l", "20260928T010203Z"); !found {
		t.Fatal("cached read lost the cycle")
	}
	if n := countIntents(db, cycleReadAction); n != 0 {
		t.Fatalf("%d cycle_read rows left, want 0 (read once, row deleted, then cached)", n)
	}
}

func TestCycleDetailViaSchedulerMissingAndFailed(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "user-D", "d-app")

	fakePicker(t, db, "user-D", cycleReadAction, "done", cycleReadEnvelope(t, map[string]any{
		"ok": true, "exists": false, "files": map[string]any{}}))
	if _, found, why := cycleDetailResolved(context.Background(), "user-D", "d-app", "l", "20200101T000000Z"); found || why != "" {
		t.Fatalf("missing cycle: found=%v why=%q; want a plain not-found", found, why)
	}

	// An older scheduler without cycle_read answers "unknown action".
	fakePicker(t, db, "user-D", cycleReadAction, "failed", `{"ok":false,"error":"unknown action: cycle_read"}`)
	_, found, why := cycleDetailResolved(context.Background(), "user-D", "d-app", "l", "20260101T000000Z")
	if found || !strings.Contains(why, "unknown action: cycle_read") {
		t.Fatalf("failed read: found=%v why=%q; want the scheduler's error", found, why)
	}
}

// Never across tenants: an app the caller has not installed is not read on the
// scheduler at all.
func TestCycleDetailNotReadForAnotherTenantsApp(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "user-owner", "o-app")
	_, found, why := cycleDetailResolved(context.Background(), "user-stranger", "o-app", "l", "20260928T010203Z")
	if found {
		t.Fatal("a stranger resolved another tenant's cycle")
	}
	if n := countIntents(db, cycleReadAction); n != 0 {
		t.Fatalf("%d cycle_read intents queued for a non-owner", n)
	}
	if !strings.Contains(why, "not available on this deployment") {
		t.Fatalf("why = %q", why)
	}
}

func TestCycleSurfacesRouteThroughTheScheduler(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_cycle.go", "MeCycleDetail", `cycleDetailResolved(`},
		{"me_agent_tools_observability.go", "toolCycleDetail", `cycleDetailResolved(`},
		{"me_runs.go", "MeRunDetail", `cycleFilesViaScheduler(`},
		{"me_cycle_log.go", "MeCycleLog", `cycleTranscriptViaScheduler(`},
		{"me_cycle.go", "MeCyclesList", `cycleOutcomeOK(`},
	} {
		if !strings.Contains(uncommentedGo(fnBlock(t, c.file, c.fn)), c.marker) {
			t.Errorf("%s no longer calls %s", c.fn, c.marker)
		}
	}
	if !isReadIntentAction(cycleReadAction) {
		t.Error("cycle_read is not a read intent: it would be listed as history and not claimed first")
	}
}

// The run list's id is when the run REPORTED (its end); the dir is named for
// its start. identity sends the start from the store row, and surfaces the dir
// the scheduler resolved.
func TestCycleDetailSendsTheRunStartAndSurfacesTheDir(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "user-H", "h-app")
	end := time.Date(2026, 9, 28, 9, 42, 37, 0, time.UTC)
	dur := 32.372
	if err := db.Create(&models.MeAppRun{UserSub: "user-H", App: "h-app", Loop: "harvest",
		RunTs: end.Unix(), Ok: true, DurationS: &dur}).Error; err != nil {
		t.Fatal(err)
	}
	got := fakePicker(t, db, "user-H", cycleReadAction, "done", cycleReadEnvelope(t, map[string]any{
		"ok": true, "exists": true, "resolved_ts": "20260928T094205Z",
		"files": map[string]any{"cycle.json": `{"ok": true}`}}))
	d, found, _ := cycleDetailResolved(context.Background(), "user-H", "h-app", "harvest", "20260928T094237Z")
	if !found || d["cycle_dir_ts"] != "20260928T094205Z" || d["ts"] != "20260928T094237Z" {
		t.Fatalf("found=%v detail=%v", found, d)
	}
	p := <-got
	if h, _ := p["start_hint"].(float64); h < float64(end.Unix())-33 || h > float64(end.Unix())-32 {
		t.Fatalf("start_hint = %v, want run_ts - duration_s", p["start_hint"])
	}
}
