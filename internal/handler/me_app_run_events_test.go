package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// The exact shape the LumidOS runner sends (sdk/apps/run_events.py).
func sampleRunEvents() map[string]any {
	return map[string]any{
		"reason":      "HTTP 500: internal server error",
		"step_errors": []any{"x"},
		"steps": []any{
			map[string]any{"step_id": "observe", "stage": "observe", "kind": "tool",
				"started_at": 1764000000.5, "ended_at": 1764000002.0, "ok": true, "summary": "returned rows"},
			map[string]any{"step_id": "engine_command", "stage": nil, "kind": "command",
				"started_at": 1764000002.0, "ended_at": 1764000063.9, "ok": false,
				"summary": "HTTP 500: internal server error"},
		},
	}
}

func decodeEventsCol(t *testing.T, s *string) map[string]any {
	t.Helper()
	if s == nil {
		t.Fatal("events column is nil")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(*s), &m); err != nil {
		t.Fatalf("stored events is not a JSON object: %v (%s)", err, *s)
	}
	return m
}

func TestNormalizeRunEventsKeepsLegacyKeysAndSteps(t *testing.T) {
	col := normalizeRunEvents(sampleRunEvents())
	m := decodeEventsCol(t, col)
	if m["reason"] != "HTTP 500: internal server error" {
		t.Errorf("reason lost: %v", m["reason"])
	}
	steps, _ := m["steps"].([]any)
	if len(steps) != 2 {
		t.Fatalf("steps = %v", m["steps"])
	}
	// The run-row reader still finds the failure reason in the same column.
	row, _ := runRowFromStore(models.MeAppRun{App: "a", Loop: "l", RunTs: 1764000064, Events: col})
	if row.Reason != "x" {
		t.Errorf("runRowFromStore reason = %q, want the step error", row.Reason)
	}
	evs := runStepEventsFromColumn(col)
	if len(evs) != 2 || evs[1].StepID != "engine_command" || evs[1].OK || evs[1].Kind != "command" {
		t.Fatalf("read back = %#v", evs)
	}
	if evs[0].Stage == nil || *evs[0].Stage != "observe" || evs[1].Stage != nil {
		t.Errorf("stages = %v / %v", evs[0].Stage, evs[1].Stage)
	}
	if evs[1].StartedAt == nil || *evs[1].StartedAt != 1764000002.0 {
		t.Errorf("started_at = %v", evs[1].StartedAt)
	}
}

func TestNormalizeRunEventsWithoutStepsIsUnchanged(t *testing.T) {
	in := map[string]any{"reason": "r", "offers": []any{map[string]any{"k": "v"}}}
	want, _ := json.Marshal(in)
	got := normalizeRunEvents(in)
	if got == nil || *got != string(want) {
		t.Errorf("got %v, want %s", got, want)
	}
	if normalizeRunEvents(nil) != nil || normalizeRunEvents(map[string]any{}) != nil {
		t.Error("empty events must store nothing (so an earlier value is kept)")
	}
	if runStepEventsFromColumn(got) != nil {
		t.Error("no steps reported must read back as nil, not []")
	}
}

func TestNormalizeRunEventsSanitizesFields(t *testing.T) {
	col := normalizeRunEvents(map[string]any{"steps": []any{
		map[string]any{"step_id": "a", "stage": "Analyze", "kind": "banana", "ok": true,
			"summary": strings.Repeat("é", 500) + "\nsecond line", "extra": "dropped"},
		map[string]any{"step_id": "", "ok": true}, // no id — not a step
		"not-an-object",
		map[string]any{"step_id": "b", "stage": "execute", "started_at": "yesterday"},
	}})
	evs := runStepEventsFromColumn(col)
	if len(evs) != 2 {
		t.Fatalf("got %d events: %#v", len(evs), evs)
	}
	if evs[0].Kind != "tool" || evs[0].Stage == nil || *evs[0].Stage != "analyze" {
		t.Errorf("kind/stage not normalised: %#v", evs[0])
	}
	if n := len([]rune(evs[0].Summary)); n != runStepSummaryMaxRunes {
		t.Errorf("summary runes = %d, want %d", n, runStepSummaryMaxRunes)
	}
	if strings.Contains(*col, "second line") || strings.Contains(*col, "extra") {
		t.Error("only the first summary line and whitelisted fields may be stored")
	}
	if evs[1].Stage != nil || evs[1].StartedAt != nil || !evs[1].OK {
		t.Errorf("bad stage/timestamp must be null, missing ok reads ok: %#v", evs[1])
	}
}

func TestNormalizeRunEventsCapsAnOversizedPayload(t *testing.T) {
	steps := make([]any, 0, 450)
	for i := 0; i < 450; i++ {
		steps = append(steps, map[string]any{"step_id": fmt.Sprintf("s%03d", i), "kind": "tool",
			"started_at": float64(1764000000 + i), "ended_at": float64(1764000001 + i),
			"ok": i != 449, "summary": strings.Repeat("y", 300)})
	}
	big := strings.Repeat("z", 20*1024) // legacy part alone over its 16 KiB ceiling
	col := normalizeRunEvents(map[string]any{"reason": big, "steps": steps, "steps_dropped": float64(3)})
	if len(*col) > runEventsMaxBytes {
		t.Fatalf("stored %d bytes, ceiling %d", len(*col), runEventsMaxBytes)
	}
	m := decodeEventsCol(t, col)
	if m["_truncated"] != true {
		t.Error("an oversized legacy part keeps its truncation marker")
	}
	evs := runStepEventsFromColumn(col)
	if len(evs) == 0 || len(evs) > runStepEventsMax {
		t.Fatalf("kept %d steps", len(evs))
	}
	if evs[0].StepID != "s000" || evs[len(evs)-1].StepID != "s449" || evs[len(evs)-1].OK {
		t.Errorf("head and the failing last step must survive: first=%s last=%s",
			evs[0].StepID, evs[len(evs)-1].StepID)
	}
	if evs[len(evs)-1].Summary == "" {
		t.Error("a failed step keeps its summary when trimming")
	}
	if d, _ := m["steps_dropped"].(float64); int(d) != 450-len(evs)+3 {
		t.Errorf("steps_dropped = %v, want %d", m["steps_dropped"], 450-len(evs)+3)
	}
}

func TestComposeCycleDetailWithEvents(t *testing.T) {
	evs := runStepEventsFromColumn(normalizeRunEvents(sampleRunEvents()))
	jobs := []computeJobRef{}

	// Unreadable cycle dir: events returned AND mapped into steps.
	got := composeCycleDetail("app", "loop", "20261124T141001Z", nil, false, "no volume", jobs, evs)
	if got["unavailable"] != "no volume" {
		t.Errorf("unavailable = %v", got["unavailable"])
	}
	steps, ok := got["steps"].([]cycleStep)
	if !ok || len(steps) != 2 {
		t.Fatalf("steps = %#v", got["steps"])
	}
	if steps[0].StepID != "observe" || steps[0].Stage != "observe" || !steps[0].OK ||
		steps[0].OutputSummary != "returned rows" || steps[0].Duration != 1.5 {
		t.Errorf("step 0 = %#v", steps[0])
	}
	if steps[1].OK || steps[1].Error != "HTTP 500: internal server error" {
		t.Errorf("failed step = %#v", steps[1])
	}
	if e, _ := got["events"].([]runStepEvent); len(e) != 2 {
		t.Errorf("events = %#v", got["events"])
	}
	if got["steps_source"] != "run_store" {
		t.Errorf("steps_source = %v", got["steps_source"])
	}

	// Cycle dir read with real steps: steps untouched, events added beside.
	diskSteps := []cycleStep{{StepID: "engine_command", OK: true}}
	got = composeCycleDetail("app", "loop", "ts", gin.H{"steps": diskSteps}, true, "", jobs, evs)
	if s := got["steps"].([]cycleStep); len(s) != 1 || s[0].StepID != "engine_command" {
		t.Errorf("disk steps replaced: %#v", got["steps"])
	}
	if _, has := got["events"]; !has {
		t.Error("events missing beside disk steps")
	}
	if _, has := got["steps_source"]; has {
		t.Error("steps_source set although the disk steps were kept")
	}

	// Cycle dir read but empty: filled from events.
	got = composeCycleDetail("app", "loop", "ts", gin.H{"steps": []cycleStep{}}, true, "", jobs, evs)
	if s := got["steps"].([]cycleStep); len(s) != 2 {
		t.Errorf("empty disk steps not filled: %#v", got["steps"])
	}

	// Scheduler said "no such dir" but the store recorded the run: served.
	got = composeCycleDetail("app", "loop", "ts", nil, false, "", jobs, evs)
	if got == nil || got["source"] != "run_store" {
		t.Fatalf("store-recorded run 404'd: %#v", got)
	}
}

func TestComposeCycleDetailWithoutEventsIsUnchanged(t *testing.T) {
	jobs := []computeJobRef{}
	got := composeCycleDetail("app", "loop", "ts", nil, false, "why", jobs, nil)
	want := gin.H{"app": "app", "loop": "loop", "ts": "ts", "steps": []any{},
		"unavailable": "why", "compute_jobs": jobs}
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Errorf("unavailable shape changed:\n got %s\nwant %s", a, b)
	}
	if composeCycleDetail("app", "loop", "ts", nil, false, "", jobs, nil) != nil {
		t.Error("no dir, no reason, no store timeline must stay a 404")
	}
	data := gin.H{"steps": []cycleStep{}, "ok": true}
	got = composeCycleDetail("app", "loop", "ts", data, true, "", jobs, nil)
	if _, has := got["events"]; has {
		t.Error("events key added with no events")
	}
	if s := got["steps"].([]cycleStep); len(s) != 0 {
		t.Error("steps invented with no events")
	}
}

// Against a real store: POST /internal/app-runs persists the timeline and the
// detail lookup returns it, owner-scoped. Skips without TEST_MYSQL_DSN.
func TestAppRunEventsRoundTripThroughTheStore(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping run-store integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.MeAppRun{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	prev := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = prev })

	owner := fmt.Sprintf("ev-%d", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() { db.Where("user_sub = ?", owner).Delete(&models.MeAppRun{}) })
	runTs := time.Date(2026, 11, 24, 14, 10, 1, 0, time.UTC).Unix()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/app-runs", InternalAppRunRecord)
	post := func(body map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/internal/app-runs", bytes.NewReader(raw)))
		if w.Code != http.StatusOK {
			t.Fatalf("POST = %d %s", w.Code, w.Body.String())
		}
	}
	base := map[string]any{"user_sub": owner, "app": "app-ev", "loop": "l", "run_ts": runTs, "ok": false}

	// absent → nothing stored, detail lookup has nothing
	post(base)
	ts := runTsToCycleID(runTs)
	if got := cycleRunStepEvents(owner, "app-ev", "l", ts); got != nil {
		t.Errorf("no events reported, got %#v", got)
	}

	// present → stored and returned
	withEv := map[string]any{}
	for k, v := range base {
		withEv[k] = v
	}
	withEv["events"] = sampleRunEvents()
	post(withEv)
	got := cycleRunStepEvents(owner, "app-ev", "l", ts)
	if len(got) != 2 || got[1].StepID != "engine_command" || got[1].OK {
		t.Fatalf("owner got %#v", got)
	}
	if cycleRunStepEvents(owner+"x", "app-ev", "l", ts) != nil {
		t.Error("another user read the timeline — must be owner-scoped")
	}

	// a later report with no events keeps the timeline (append-only)
	post(base)
	if got := cycleRunStepEvents(owner, "app-ev", "l", ts); len(got) != 2 {
		t.Errorf("re-report without events blanked the timeline: %#v", got)
	}

	// oversized → capped, still a valid object
	steps := make([]any, 0, 600)
	for i := 0; i < 600; i++ {
		steps = append(steps, map[string]any{"step_id": fmt.Sprintf("s%d", i), "ok": true,
			"summary": strings.Repeat("q", 400)})
	}
	withEv["events"] = map[string]any{"steps": steps}
	post(withEv)
	var row models.MeAppRun
	if err := db.Where("user_sub = ?", owner).Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Events == nil || len(*row.Events) > runEventsMaxBytes {
		t.Fatalf("stored events not capped: %d bytes", len(*row.Events))
	}
	if got := runStepEventsFromColumn(row.Events); len(got) == 0 || len(got) > runStepEventsMax {
		t.Errorf("capped read-back = %d steps", len(got))
	}
}
