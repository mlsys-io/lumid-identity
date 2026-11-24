package handler

// The experiment detail's `series` for CLOUD installs, and `forked_from`.
//
// The detail read data/experiments/<id>/results.jsonl off disk only. Identity
// mounts no tenant volume, so for every cloud install that file is absent and
// the detail served `series: []` while the feeding loops' runs sat in
// me_app_runs. The pure tests below pin the extraction; the DB-backed ones
// (TEST_MYSQL_DSN) drive the real GET /me/apps/:app/experiments/:id handler.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const seriesSpec = "experiments:\n" +
	"- id: kol_alpha\n" +
	"  hypothesis: an arm beats the reference\n" +
	"  metric: {name: realized_pnl_ticks, higher_is_better: true}\n" +
	"  forked_from: kol_alpha_v0\n" +
	"  arms:\n" +
	"  - id: current\n" +
	"  - id: musk_v1\n" +
	"- id: no_parent\n" +
	"  metric: {name: m}\n" +
	"loops:\n" +
	"- name: kol_strategy\n" +
	"  engine: {experiment: kol_alpha}\n" +
	"- name: other_loop\n" +
	"  engine: {experiment: no_parent}\n"

func writeSeriesBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(seriesSpec), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeExpLedger(t *testing.T, dir, expID string, lines ...string) {
	t.Helper()
	p := filepath.Join(dir, "data", "experiments", expID)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(p, "results.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func seriesRun(ts int64, metrics string) models.MeAppRun {
	return models.MeAppRun{Loop: "kol_strategy", RunTs: ts, Metrics: metrics}
}

// The arm shapes the scheduler actually writes.
func TestExpRunPointsReadsEveryArmShape(t *testing.T) {
	cases := []struct {
		name    string
		metrics string
		want    []expRunPoint
	}{
		{"top-level arm (app_runner._self_report_run)",
			`{"arm":"musk_v1","experiment":"kol_alpha","realized_pnl_ticks":4.5}`,
			[]expRunPoint{{runTs: 1, arm: "musk_v1", v: 4.5}}},
		{"U1 alias: experiment == arm is not a foreign study",
			`{"arm":"musk_v1","experiment":"musk_v1","realized_pnl_ticks":2}`,
			[]expRunPoint{{runTs: 1, arm: "musk_v1", v: 2}}},
		{"another experiment fed by the same loop is skipped",
			`{"arm":"x","experiment":"backtest_performance","realized_pnl_ticks":9}`, nil},
		{"per-result arms read their OWN value",
			`{"realized_pnl_ticks":100,"command_engine":{"results":[
				{"arm":"tape_covered","experiment":"kol_alpha","realized_pnl_ticks":1},
				{"arm":"current","realized_pnl_ticks":2},
				{"arm":"elsewhere","experiment":"other","realized_pnl_ticks":3},
				{"note":"no arm","realized_pnl_ticks":4}]}}`,
			[]expRunPoint{{runTs: 1, arm: "tape_covered", v: 1}, {runTs: 1, arm: "current", v: 2}}},
		{"no arm anywhere: plain cycle, inferred current",
			`{"primary_metric":{"name":"realized_pnl_ticks","value":7},"realized_pnl_ticks":7}`,
			[]expRunPoint{{runTs: 1, arm: "current", v: 7, inferred: true}}},
		{"metric absent", `{"arm":"musk_v1","other":1}`, nil},
		{"garbage blob", `not json`, nil},
	}
	for _, c := range cases {
		got := expRunPoints(seriesRun(1, c.metrics), "kol_alpha", "realized_pnl_ticks")
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Same shape as the disk path, oldest-first, arms sorted, newest N kept.
func TestExpSeriesFromRunsShapeAndCap(t *testing.T) {
	runs := []models.MeAppRun{ // newest-first, as the query returns them
		seriesRun(1700000300, `{"arm":"musk_v1","realized_pnl_ticks":3}`),
		seriesRun(1700000200, `{"realized_pnl_ticks":2}`),
		seriesRun(1700000100, `{"arm":"musk_v1","realized_pnl_ticks":1}`),
	}
	series, total := expSeriesFromRuns(runs, "kol_alpha", "realized_pnl_ticks", 2)
	if total != 3 {
		t.Fatalf("total = %d, want 3", total)
	}
	b, _ := json.Marshal(series)
	want := `[{"arm_inferred":true,"points":[{"arm_inferred":true,"ts":"2023-11-14T22:16:40Z","v":2}],"variant_id":"current"},` +
		`{"points":[{"ts":"2023-11-14T22:18:20Z","v":3}],"variant_id":"musk_v1"}]`
	if string(b) != want {
		t.Fatalf("series =\n%s\nwant\n%s", b, want)
	}
}

// (b) The disk path is unchanged: ledger rows → series from the ledger, tagged
// as such, and forked_from passed through.
func TestDetailDiskSeriesUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeSeriesBundle(t, dir)
	writeExpLedger(t, dir, "kol_alpha",
		`{"ts":"2026-11-01T00:00:00Z","variant_id":"current","metrics":{"realized_pnl_ticks":1.5}}`,
		`{"ts":"2026-11-02T00:00:00Z","variant_id":"musk_v1","metrics":{"realized_pnl_ticks":2.5}}`)
	detail, found := loadExperimentDetailFor("", "", dir, "kol_alpha")
	if !found {
		t.Fatal("not found")
	}
	b, _ := json.Marshal(detail["series"])
	want := `[{"points":[{"ts":"2026-11-01T00:00:00Z","v":1.5}],"variant_id":"current"},` +
		`{"points":[{"ts":"2026-11-02T00:00:00Z","v":2.5}],"variant_id":"musk_v1"}]`
	if string(b) != want {
		t.Fatalf("disk series changed:\n%s\nwant\n%s", b, want)
	}
	if detail["series_source"] != "results_ledger" {
		t.Fatalf("series_source = %v", detail["series_source"])
	}
	if _, has := detail["series_total"]; has {
		t.Fatal("run-store fields leaked onto a ledger-backed detail")
	}
}

// (c) forked_from: present when the spec declares it, absent otherwise — on
// the list, the detail, and the cross-node (published spec) parse.
func TestForkedFromPassthrough(t *testing.T) {
	dir := t.TempDir()
	writeSeriesBundle(t, dir)

	byID := map[string]gin.H{}
	for _, r := range loadAppExperiments(dir) {
		byID[r["id"].(string)] = r
	}
	if byID["kol_alpha"]["forked_from"] != "kol_alpha_v0" {
		t.Fatalf("list dropped forked_from: %v", byID["kol_alpha"]["forked_from"])
	}
	if _, has := byID["no_parent"]["forked_from"]; has {
		t.Fatalf("list invented a forked_from: %v", byID["no_parent"]["forked_from"])
	}

	d, _ := loadExperimentDetailFor("", "", dir, "kol_alpha")
	if d["forked_from"] != "kol_alpha_v0" {
		t.Fatalf("detail dropped forked_from: %v", d["forked_from"])
	}
	d2, _ := loadExperimentDetailFor("", "", dir, "no_parent")
	if _, has := d2["forked_from"]; has {
		t.Fatalf("detail invented a forked_from: %v", d2["forked_from"])
	}
	// JSON: omitted entirely, not "forked_from": "".
	b, _ := json.Marshal(d2)
	if json.Valid(b) && containsKey(b, "forked_from") {
		t.Fatalf("absent forked_from serialised: %s", b)
	}

	// Map-form spec (the cross-node fallback parses published bytes).
	m := parseExpManifestBytes([]byte("experiments:\n  e1: {forked_from: e0, metric: {name: m}}\n"))
	if len(m.Experiments) != 1 || m.Experiments[0].ForkedFrom != "e0" {
		t.Fatalf("map-form spec lost forked_from: %+v", m.Experiments)
	}
}

func containsKey(b []byte, k string) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	_, has := m[k]
	return has
}

// ── DB-backed: the real handler ─────────────────────────────────────────────

func setupSeriesDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping DB-backed experiment series test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.Token{}, &models.MeAppRun{}, &models.MeAppExperiment{}, &models.MeAppIntent{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	orig := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = orig })
	return db
}

// seriesTenant makes a user with a legacy sha256 PAT, an installed bundle at
// <operator home>/.tenants/<sub>/.xp/apps/<app>, and returns (sub, pat, dir).
func seriesTenant(t *testing.T, db *gorm.DB, app string) (string, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	sub := fmt.Sprintf("series-%d", time.Now().UnixNano())
	pat := "rm_pat_live_" + sub
	sum := sha256.Sum256([]byte(pat))
	tok := models.Token{ID: sub, UserID: sub, Prefix: "rm_pat_", Hash: hex.EncodeToString(sum[:]), HashAlg: "sha256", Source: "legacy-lqa"}
	if err := db.Create(&tok).Error; err != nil {
		t.Fatalf("seed token: %v", err)
	}
	dir := filepath.Join(tenantAppsDir(sub), app)
	writeSeriesBundle(t, dir)
	t.Cleanup(func() {
		db.Where("id = ?", sub).Delete(&models.Token{})
		db.Where("user_sub = ?", sub).Delete(&models.MeAppRun{})
	})
	return sub, pat, dir
}

func getDetail(t *testing.T, pat, app, id string) map[string]any {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/me/apps/:app/experiments/:id", MeAppExperiment)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/apps/"+app+"/experiments/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET detail: %d %s", w.Code, w.Body.String())
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Data
}

func seedRuns(t *testing.T, db *gorm.DB, sub, app string, rows ...models.MeAppRun) {
	t.Helper()
	for _, r := range rows {
		r.UserSub, r.App, r.Ok = sub, app, true
		if err := db.Create(&r).Error; err != nil {
			t.Fatalf("seed run: %v", err)
		}
	}
}

// (a) Cloud case: no ledger on disk, run-store rows present → a non-empty
// series with the right arm and value, from the experiment's own loops only.
func TestDetailSeriesFromRunStoreWhenLedgerAbsent(t *testing.T) {
	db := setupSeriesDB(t)
	sub, pat, _ := seriesTenant(t, db, "series-app")
	seedRuns(t, db, sub, "series-app",
		models.MeAppRun{Loop: "kol_strategy", RunTs: 1763000000, Metrics: `{"arm":"musk_v1","experiment":"kol_alpha","realized_pnl_ticks":4.5}`},
		models.MeAppRun{Loop: "kol_strategy", RunTs: 1763000100, Metrics: `{"realized_pnl_ticks":1.25}`},
		// Not this experiment's loop: must not appear even though it carries the metric.
		models.MeAppRun{Loop: "other_loop", RunTs: 1763000200, Metrics: `{"arm":"intruder","realized_pnl_ticks":99}`},
	)
	// Another tenant's run of the same app + loop: must not appear.
	seedRuns(t, db, sub+"-other", "series-app",
		models.MeAppRun{Loop: "kol_strategy", RunTs: 1763000300, Metrics: `{"arm":"stranger","realized_pnl_ticks":77}`})
	t.Cleanup(func() { db.Where("user_sub = ?", sub+"-other").Delete(&models.MeAppRun{}) })

	d := getDetail(t, pat, "series-app", "kol_alpha")
	if d["series_source"] != "run_store" {
		t.Fatalf("series_source = %v (series %v)", d["series_source"], d["series"])
	}
	b, _ := json.Marshal(d["series"])
	want := `[{"arm_inferred":true,"points":[{"arm_inferred":true,"ts":"2025-11-13T02:15:00Z","v":1.25}],"variant_id":"current"},` +
		`{"points":[{"ts":"2025-11-13T02:13:20Z","v":4.5}],"variant_id":"musk_v1"}]`
	if string(b) != want {
		t.Fatalf("series =\n%s\nwant\n%s", b, want)
	}
	if d["series_total"] != float64(2) || d["series_truncated"] != false {
		t.Fatalf("series_total/truncated = %v/%v", d["series_total"], d["series_truncated"])
	}
	if d["forked_from"] != "kol_alpha_v0" {
		t.Fatalf("forked_from = %v", d["forked_from"])
	}
}

// (b, through the handler) A readable ledger still wins: run-store rows exist
// but the series is the ledger's.
func TestDetailSeriesPrefersLedgerOverRunStore(t *testing.T) {
	db := setupSeriesDB(t)
	sub, pat, dir := seriesTenant(t, db, "series-app")
	writeExpLedger(t, dir, "kol_alpha",
		`{"ts":"2026-11-01T00:00:00Z","variant_id":"musk_v1","metrics":{"realized_pnl_ticks":8}}`)
	seedRuns(t, db, sub, "series-app",
		models.MeAppRun{Loop: "kol_strategy", RunTs: 1763000000, Metrics: `{"arm":"musk_v1","realized_pnl_ticks":4.5}`})

	d := getDetail(t, pat, "series-app", "kol_alpha")
	if d["series_source"] != "results_ledger" {
		t.Fatalf("series_source = %v", d["series_source"])
	}
	b, _ := json.Marshal(d["series"])
	if want := `[{"points":[{"ts":"2026-11-01T00:00:00Z","v":8}],"variant_id":"musk_v1"}]`; string(b) != want {
		t.Fatalf("series = %s, want %s", b, want)
	}
	if rs, _ := d["results"].([]any); len(rs) != 1 {
		t.Fatalf("results = %v", d["results"])
	}
}
