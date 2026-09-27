package handler

// Reads of a cloud install go through the DB, not a local tenant tree:
// trajectory signals (me_app_signals + the runner's claim/ack), synchronous
// read intents (next-actions, lineage, the improvements ledger), and the
// "latest" cycle for feedback. DB-backed tests skip without TEST_MYSQL_DSN.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func setupStaleReadsDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping DB-backed read test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.MeAppIntent{}, &models.MeAppSignal{}, &models.MeAppRun{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MeAppIntent{})
	db.Where("1 = 1").Delete(&models.MeAppSignal{})
	db.Where("1 = 1").Delete(&models.MeAppRun{})
	prev := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = prev })
	// No tenant tree is visible: an empty operator home.
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	resetReadIntentCache()
	pe, pt := readIntentPollEvery, readIntentDefaultTimeout
	readIntentPollEvery = 20 * time.Millisecond
	t.Cleanup(func() { readIntentPollEvery, readIntentDefaultTimeout = pe, pt })
	return db
}

// installFor records a completed install so ownerWriteTarget answers viaIntent.
func installFor(t *testing.T, db *gorm.DB, user, app string) {
	t.Helper()
	now := time.Now()
	if err := db.Create(&models.MeAppIntent{
		ID: "install-" + user + "-" + app, Action: "install", UserSub: user,
		Payload: `{"slug":"owner/` + app + `"}`, Status: "done", CompletedAt: &now,
	}).Error; err != nil {
		t.Fatalf("seed install: %v", err)
	}
	if _, direct, via, _ := ownerWriteTarget(user, app); direct || !via {
		t.Fatalf("precondition: want viaIntent for %s/%s, got direct=%v via=%v", user, app, direct, via)
	}
}

// fakePicker completes the first `action` intent it sees for user with result.
func fakePicker(t *testing.T, db *gorm.DB, user, action, status, result string) (payload chan map[string]any) {
	t.Helper()
	payload = make(chan map[string]any, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var row models.MeAppIntent
			if db.Where("user_sub = ? AND action = ? AND status = ?", user, action, "pending").
				Take(&row).Error == nil {
				var p map[string]any
				_ = json.Unmarshal([]byte(row.Payload), &p)
				now := time.Now()
				db.Model(&models.MeAppIntent{}).Where("id = ?", row.ID).
					Updates(map[string]any{"status": status, "result": result, "completed_at": now})
				payload <- p
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(payload)
	}()
	return payload
}

func countIntents(db *gorm.DB, action string) int64 {
	var n int64
	db.Model(&models.MeAppIntent{}).Where("action = ?", action).Count(&n)
	return n
}

// ── signals ──────────────────────────────────────────────────────────────────

func signalRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/internal", RequireBridge())
	g.POST("/app-signals/claim", InternalAppSignalsClaim)
	g.POST("/app-signals/ack", InternalAppSignalsAck)
	return r
}

func postBridge(t *testing.T, r *gin.Engine, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d %s", path, w.Code, w.Body.String())
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: decode: %v", path, err)
	}
	return out.Data
}

func claimedIDs(t *testing.T, data map[string]any) []string {
	t.Helper()
	sigs, _ := data["signals"].([]any)
	var ids []string
	for _, s := range sigs {
		m, _ := s.(map[string]any)
		if _, ok := m["rec"].(map[string]any); !ok {
			t.Fatalf("claimed signal without an object rec: %v", m)
		}
		ids = append(ids, m["id"].(string))
	}
	return ids
}

func TestAppSignalsClaimAckRoundTrip(t *testing.T) {
	db := setupStaleReadsDB(t)
	t.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	r := signalRouter()

	mk := func(user, app, loop, note string) string {
		id, err := insertAppSignal(user, app, signalRecord{Ts: "t", Action: "branch", Loop: loop, Note: note, By: user, Status: "pending"})
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		time.Sleep(5 * time.Millisecond) // distinct created_at for ordering
		return id
	}
	a1 := mk("user-A", "app-x", "l1", "first")
	a2 := mk("user-A", "app-x", "l2", "second")
	b1 := mk("user-B", "app-x", "l1", "other user")
	mk("user-A", "app-y", "l1", "other app")

	if n := appSignalPendingCount("user-A", "app-x"); n != 2 {
		t.Fatalf("pending count = %d, want 2", n)
	}

	ids := claimedIDs(t, postBridge(t, r, "/api/v1/internal/app-signals/claim", map[string]any{"user_sub": "user-A", "app": "app-x"}))
	if len(ids) != 2 || ids[0] != a1 || ids[1] != a2 {
		t.Fatalf("claim = %v, want [%s %s] oldest-first, scoped to user+app", ids, a1, a2)
	}
	if again := claimedIDs(t, postBridge(t, r, "/api/v1/internal/app-signals/claim", map[string]any{"user_sub": "user-A", "app": "app-x"})); len(again) != 0 {
		t.Fatalf("second claim re-delivered fresh claims: %v", again)
	}
	// Claimed-but-unacked still counts as pending for the writer's answer.
	if n := appSignalPendingCount("user-A", "app-x"); n != 2 {
		t.Fatalf("pending after claim = %d, want 2", n)
	}

	// Ack a1 — and try to ack user-B's row under user-A: must be ignored.
	ack := postBridge(t, r, "/api/v1/internal/app-signals/ack", map[string]any{"user_sub": "user-A", "ids": []string{a1, b1}})
	if n, _ := ack["acked"].(float64); n != 1 {
		t.Fatalf("acked = %v, want 1 (b1 belongs to user-B)", ack["acked"])
	}
	var b models.MeAppSignal
	db.Where("id = ?", b1).Take(&b)
	if b.Status != "pending" {
		t.Fatalf("user-B's signal status = %q after user-A's ack, want pending", b.Status)
	}

	// a2 was claimed by a cycle that died: re-delivered once stale.
	db.Model(&models.MeAppSignal{}).Where("id = ?", a2).
		Update("claimed_at", time.Now().Add(-appSignalStaleClaim-time.Minute))
	re := claimedIDs(t, postBridge(t, r, "/api/v1/internal/app-signals/claim", map[string]any{"user_sub": "user-A", "app": "app-x"}))
	if len(re) != 1 || re[0] != a2 {
		t.Fatalf("stale re-claim = %v, want [%s]", re, a2)
	}
	var row models.MeAppSignal
	db.Where("id = ?", a2).Take(&row)
	if row.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", row.Attempts)
	}

	// Reader view: a1 delivered, a2 (claimed) still pending; loop filter.
	all := appSignalsFromDB("user-A", "app-x", "")
	if len(all) != 2 || all[0].Note != "first" || all[0].Status != "delivered" || all[1].Status != "pending" {
		t.Fatalf("appSignalsFromDB = %+v", all)
	}
	if l2 := appSignalsFromDB("user-A", "app-x", "l2"); len(l2) != 1 || l2[0].Note != "second" {
		t.Fatalf("loop filter = %+v", l2)
	}
}

func TestBranchRunRecordsSignalWithDBPendingCount(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-S", "sig-app")
	for i, want := range []float64{1, 2} {
		out, ok := toolBranchRun("user-S", "sig-app", map[string]any{
			"loop": "main", "from_ts": "20260901T000000Z", "note": "try smaller batches",
		})
		if !ok {
			t.Fatalf("call %d: %v", i, out)
		}
		if got, _ := out["pending"].(int64); float64(got) != want {
			t.Fatalf("call %d: pending = %v, want %v", i, out["pending"], want)
		}
		if out["branched"] != true {
			t.Fatalf("call %d: branched = %v", i, out["branched"])
		}
	}
	if n := countIntents(db, appFileWriteAction); n != 0 {
		t.Fatalf("branch_run still queued %d app_file_write intents", n)
	}
}

// ── runReadIntent ────────────────────────────────────────────────────────────

func TestRunReadIntentSuccessDeletesRowAndCaches(t *testing.T) {
	db := setupStaleReadsDB(t)
	got := fakePicker(t, db, "user-R", "trajectory_query", "done",
		`{"ok":true,"action":"trajectory_query","data":{"ok":true,"actions":[{"kind":"run"}]}}`)
	payload := map[string]any{"verb": "next-actions", "app": "r-app"}
	data, err := runReadIntent(context.Background(), "user-R", "trajectory_query", payload, 3*time.Second)
	if err != nil {
		t.Fatalf("runReadIntent: %v", err)
	}
	if p := <-got; p["verb"] != "next-actions" || p["app"] != "r-app" {
		t.Fatalf("picker saw payload %v", p)
	}
	if a, _ := data["actions"].([]any); len(a) != 1 {
		t.Fatalf("data = %v", data)
	}
	if n := countIntents(db, "trajectory_query"); n != 0 {
		t.Fatalf("read row not deleted after read: %d left", n)
	}
	// Cache hit: no picker is running, so an enqueue would time out.
	data["mutated"] = true
	again, err := runReadIntent(context.Background(), "user-R", "trajectory_query", payload, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("cached read: %v", err)
	}
	if _, leaked := again["mutated"]; leaked {
		t.Fatal("cache handed out a shared map the caller mutated")
	}
	if n := countIntents(db, "trajectory_query"); n != 0 {
		t.Fatalf("cache hit still enqueued %d intents", n)
	}
}

func TestRunReadIntentFailure(t *testing.T) {
	db := setupStaleReadsDB(t)
	fakePicker(t, db, "user-F", "app_file_read", "failed",
		`{"ok":false,"action":"app_file_read","error":"app 'x' not installed for this user"}`)
	_, err := runReadIntent(context.Background(), "user-F", "app_file_read", map[string]any{"app": "x", "path": improvementsRel}, 3*time.Second)
	var rf *readIntentFailed
	if !errors.As(err, &rf) || !strings.Contains(rf.msg, "not installed") {
		t.Fatalf("err = %v, want readIntentFailed carrying the picker error", err)
	}
	if n := countIntents(db, "app_file_read"); n != 0 {
		t.Fatalf("failed read row not deleted: %d left", n)
	}
	// Failures are not cached: the next call enqueues again (and times out).
	if _, err := runReadIntent(context.Background(), "user-F", "app_file_read", map[string]any{"app": "x", "path": improvementsRel}, 150*time.Millisecond); !errors.Is(err, errReadIntentTimeout) {
		t.Fatalf("second call err = %v, want a fresh (timed-out) read", err)
	}
}

func TestRunReadIntentTimeoutLeavesRow(t *testing.T) {
	db := setupStaleReadsDB(t)
	start := time.Now()
	_, err := runReadIntent(context.Background(), "user-T", "trajectory_query", map[string]any{"verb": "lineage", "app": "a", "loop": "l"}, 200*time.Millisecond)
	if !errors.Is(err, errReadIntentTimeout) {
		t.Fatalf("err = %v, want errReadIntentTimeout", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout not honoured: %v", time.Since(start))
	}
	if n := countIntents(db, "trajectory_query"); n != 1 {
		t.Fatalf("timed-out row count = %d, want 1 (left for the picker / sweep)", n)
	}
	// The sweep deletes read rows past retention, and nothing else.
	db.Model(&models.MeAppIntent{}).Where("action = ?", "trajectory_query").
		Update("created_at", time.Now().Add(-readIntentRetention-time.Minute))
	old := time.Now().Add(-2 * readIntentRetention)
	db.Create(&models.MeAppIntent{ID: "keep-install", Action: "install", UserSub: "user-T", Payload: "{}", Status: "done", CreatedAt: old})
	sweepReadIntents()
	if n := countIntents(db, "trajectory_query"); n != 0 {
		t.Fatalf("sweep left %d stale read rows", n)
	}
	if n := countIntents(db, "install"); n != 1 {
		t.Fatalf("sweep touched a non-read intent")
	}
}

// ── next-actions / lineage / improvements via the scheduler ──────────────────

func TestTrajectoryQueryViaSchedulerMapsResult(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-Q", "q-app")
	fakePicker(t, db, "user-Q", "trajectory_query", "done",
		`{"ok":true,"action":"trajectory_query","data":{"ok":true,"nodes":[],"roots":["r1"]}}`)
	obj, status, msg, routed := trajectoryQueryViaScheduler(context.Background(), "user-Q", "lineage", "q-app", "main")
	if !routed || msg != "" || status != http.StatusOK {
		t.Fatalf("routed=%v status=%d msg=%q", routed, status, msg)
	}
	if _, has := obj["ok"]; has {
		t.Fatalf("`ok` not stripped: %v", obj)
	}
	if r, _ := obj["roots"].([]any); len(r) != 1 {
		t.Fatalf("obj = %v", obj)
	}

	// CLI failure on the scheduler → 502, like the local path.
	fakePicker(t, db, "user-Q", "trajectory_query", "failed",
		`{"ok":false,"action":"trajectory_query","data":{"ok":false,"error":"no such loop"}}`)
	_, status, msg, _ = trajectoryQueryViaScheduler(context.Background(), "user-Q", "next-actions", "q-app", "")
	if status != http.StatusBadGateway || !strings.Contains(msg, "no such loop") {
		t.Fatalf("failure: status=%d msg=%q", status, msg)
	}

	// No answer → 504.
	readIntentDefaultTimeout = 150 * time.Millisecond
	_, status, _, _ = trajectoryQueryViaScheduler(context.Background(), "user-Q", "lineage", "q-app", "other")
	if status != http.StatusGatewayTimeout {
		t.Fatalf("timeout status = %d, want 504", status)
	}

	// Not the caller's install → not routed (the local CLI path runs as before).
	if _, _, _, routed := trajectoryQueryViaScheduler(context.Background(), "user-Q", "lineage", "not-installed", "main"); routed {
		t.Fatal("routed an app the caller does not have")
	}
}

func TestReadImprovementsViaScheduler(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-I", "i-app")
	content := `{"id":"imp-1","ts":"2026-09-01T00:00:00Z","app":"i-app","loop":"a","axis":"examples","verb":"good","label":"one"}` + "\n" +
		`not json` + "\n" +
		`{"id":"imp-2","ts":"2026-09-02T00:00:00Z","app":"i-app","loop":"b","axis":"rules","verb":"add","label":"two"}` + "\n"
	res, _ := json.Marshal(map[string]any{"ok": true, "action": "app_file_read",
		"data": map[string]any{"ok": true, "path": improvementsRel, "exists": true, "truncated": false, "content": content}})
	got := fakePicker(t, db, "user-I", "app_file_read", "done", string(res))
	events, err := readImprovements(context.Background(), "user-I", "i-app", "", "", 0)
	if err != nil {
		t.Fatalf("readImprovements: %v", err)
	}
	if p := <-got; p["path"] != improvementsRel || p["app"] != "i-app" {
		t.Fatalf("picker payload = %v", p)
	}
	if len(events) != 2 || events[0].ID != "imp-2" {
		t.Fatalf("events = %+v (want 2, newest first)", events)
	}
	// Loop filter from the cached read.
	if ev, _ := readImprovements(context.Background(), "user-I", "i-app", "a", "", 0); len(ev) != 1 || ev[0].ID != "imp-1" {
		t.Fatalf("loop filter = %+v", ev)
	}
}

// ── latest cycle from the run store ──────────────────────────────────────────

func TestResolveLatestCycleTsFromRunStore(t *testing.T) {
	db := setupStaleReadsDB(t)
	installFor(t, db, "user-L", "l-app")
	t1 := time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC)
	t2 := time.Date(2026, 9, 21, 4, 5, 6, 0, time.UTC)
	for _, r := range []models.MeAppRun{
		{UserSub: "user-L", App: "l-app", Loop: "main", RunTs: t1.Unix(), Ok: true},
		{UserSub: "user-L", App: "l-app", Loop: "main", RunTs: t2.Unix(), Ok: false},
		{UserSub: "user-L", App: "l-app", Loop: "other", RunTs: t2.Unix() + 100, Ok: true},
		{UserSub: "user-Z", App: "l-app", Loop: "main", RunTs: t2.Unix() + 200, Ok: true},
	} {
		r := r
		if err := db.Create(&r).Error; err != nil {
			t.Fatalf("seed run: %v", err)
		}
	}
	ts, err := resolveLatestCycleTs("user-L", "l-app", "main")
	if err != nil || ts != "20260921T040506Z" {
		t.Fatalf("latest = %q, %v; want 20260921T040506Z", ts, err)
	}
	if _, err := resolveLatestCycleTs("user-L", "l-app", "never-ran"); err == nil {
		t.Fatal("want an error for a loop with no runs")
	}
}

// ── source guards ────────────────────────────────────────────────────────────

func TestStaleReadsRouteThroughScheduler(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_trajectory_ops.go", "MeNextActions", `trajectoryQueryViaScheduler(`},
		{"me_trajectory_ops.go", "MeLoopLineage", `trajectoryQueryViaScheduler(`},
		{"me_trajectory_ops.go", "trajectoryQueryViaScheduler", `"trajectory_query"`},
		{"me_improvements.go", "MeIntentAudit", `readImprovements(`},
		{"me_improvements.go", "readImprovements", `"app_file_read"`},
		{"me_trajectory_signal.go", "MeTrajectorySignals", `appSignalsFromDB(`},
		{"me_cycles.go", "MeCycleFeedback", `resolveLatestCycleTs(`},
		{"me_agent_helpers.go", "agentWriteFeedback", `resolveLatestCycleTs(`},
	} {
		if !strings.Contains(fnBlock(t, c.file, c.fn), c.marker) {
			t.Errorf("%s no longer contains %s — on a cloud pod it would read a tenant tree identity does not mount", c.fn, c.marker)
		}
	}
	for _, c := range []struct{ file, fn, forbidden string }{
		{"me_trajectory_signal.go", "MeTrajectorySignal", `appendOp(signalsRel`},
		{"me_agent_app_ops.go", "toolBranchRun", `appendOp(signalsRel`},
	} {
		if strings.Contains(fnBlock(t, c.file, c.fn), c.forbidden) {
			t.Errorf("%s still queues a signals.jsonl append (%s) — signals are me_app_signals rows now", c.fn, c.forbidden)
		}
	}
}

func TestClaimServesReadIntentsFirst(t *testing.T) {
	db := setupStaleReadsDB(t)
	t.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	old := time.Now().Add(-time.Minute)
	db.Create(&models.MeAppIntent{ID: "old-run", Action: "run_loop", UserSub: "u", Payload: "{}", Status: "pending", CreatedAt: old})
	db.Create(&models.MeAppIntent{ID: "new-read", Action: "app_file_read", UserSub: "u", Payload: "{}", Status: "pending"})
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/internal/me-intents/claim", RequireBridge(), InternalMeIntentsClaim)
	data := postBridge(t, r, "/api/v1/internal/me-intents/claim", map[string]any{})
	in, _ := data["intents"].([]any)
	if len(in) != 2 || in[0].(map[string]any)["intent_id"] != "new-read" {
		t.Fatalf("claim order = %v, want the read intent first", in)
	}
}

func TestRunArmObservations_TopLevelAndPerResult(t *testing.T) {
	top := map[string]any{"arm": "musk_v1", "experiment": "kol_alpha"}
	if got := runArmObservations(top); len(got) != 1 || got[0].arm != "musk_v1" || got[0].experiment != "kol_alpha" {
		t.Fatalf("top-level: %+v", got)
	}
	nested := map[string]any{"command_engine": map[string]any{"results": []any{
		map[string]any{"arm": "tape_covered", "experiment": "backtest_evidence"},
		map[string]any{"arm": "current", "experiment": "backtest_evidence"},
		map[string]any{"note": "no arm"},
	}}}
	got := runArmObservations(nested)
	if len(got) != 2 || got[0].arm != "tape_covered" || got[1].arm != "current" {
		t.Fatalf("per-result: %+v", got)
	}
	if got := runArmObservations(map[string]any{"arms_note": "x"}); len(got) != 0 {
		t.Fatalf("substring match must not count: %+v", got)
	}
}
