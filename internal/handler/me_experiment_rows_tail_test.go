package handler

// The experiment detail's `results` for scheduler-run tenants.
//
// The ledger is on the scheduler's volume and identity mounts none, so the
// detail's disk read found nothing and GET /me/apps/:app/experiments/:id served
// `results: []` and `results_total: 0` for every on-prem research app — the
// lumid-ui evidence grid (results[].dims.stage/passed/reason) was empty although
// the rows existed. The cycle now bridges the ledger's tail beside the state;
// identity stores it (<= 2 MiB, oldest dropped) and serves it when the disk has
// nothing. The pure tests pin the encoding and the fallback rule; the
// DB-backed ones (TEST_MYSQL_DSN) drive the real bridge handler.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/models"
)

func rawRows(t *testing.T, rows ...map[string]any) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, 0, len(rows))
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func chainRow(i int, reason string) map[string]any {
	return map[string]any{
		"ts": fmt.Sprintf("2026-11-%02dT00:00:00Z", i%28+1), "variant_id": "current",
		"metrics":  map[string]any{"realized_pnl_ticks": float64(i)},
		"dims":     map[string]any{"stage": "screen", "passed": "True", "reason": reason},
		"cycle_ts": fmt.Sprintf("c%d", i),
	}
}

func TestEncodeRowsTailKeepsEverythingUnderTheCap(t *testing.T) {
	rows := rawRows(t, chainRow(0, "ok"), chainRow(1, "ok"))
	got := encodeRowsTail(rows, expRowsTailMaxBytes)
	back := expRowsFromTail(got, 0)
	if len(back) != 2 || back[0].CycleTS != "c0" || back[1].CycleTS != "c1" {
		t.Fatalf("round trip = %+v", back)
	}
	if back[1].Dims["stage"] != "screen" || back[1].Dims["reason"] != "ok" {
		t.Fatalf("dims lost: %+v", back[1].Dims)
	}
}

func TestEncodeRowsTailDropsTheOldestToFit(t *testing.T) {
	rows := make([]json.RawMessage, 0, 50)
	for i := 0; i < 50; i++ {
		rows = append(rows, rawRows(t, chainRow(i, strings.Repeat("x", 200)))...)
	}
	const capB = 4000
	got := encodeRowsTail(rows, capB)
	if len(got) > capB {
		t.Fatalf("encoded %d bytes, cap %d", len(got), capB)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal([]byte(got), &arr); err != nil {
		t.Fatalf("not a JSON array: %v", err)
	}
	if len(arr) == 0 || len(arr) >= 50 {
		t.Fatalf("kept %d of 50", len(arr))
	}
	back := expRowsFromTail(got, 0)
	if back[len(back)-1].CycleTS != "c49" {
		t.Fatalf("the newest row did not survive: %s", back[len(back)-1].CycleTS)
	}
	// As many as fit: one more (older) row would not.
	if one := encodeRowsTail(rows[50-len(arr)-1:], 1<<30); len(one) <= capB {
		t.Fatalf("one more row (%d bytes) would have fit under %d", len(one), capB)
	}
}

func TestEncodeRowsTailRealCapIsTwoMiB(t *testing.T) {
	rows := make([]json.RawMessage, 0, 200)
	for i := 0; i < 200; i++ {
		rows = append(rows, rawRows(t, chainRow(i, strings.Repeat("y", 20_000)))...)
	}
	got := encodeRowsTail(rows, expRowsTailMaxBytes)
	if len(got) > 2<<20 {
		t.Fatalf("stored %d bytes", len(got))
	}
	if n := len(expRowsFromTail(got, 0)); n < 90 || n > 110 {
		t.Fatalf("kept %d rows of ~20 KB under 2 MiB", n)
	}
}

func TestEncodeRowsTailDiscardsNonObjectsAndHandlesEmpty(t *testing.T) {
	if got := encodeRowsTail(nil, expRowsTailMaxBytes); got != "[]" {
		t.Fatalf("empty = %q", got)
	}
	rows := []json.RawMessage{json.RawMessage(`"str"`), json.RawMessage(`[1]`),
		json.RawMessage(` { "ts" : "t", "variant_id" : "a" } `)}
	if got := encodeRowsTail(rows, expRowsTailMaxBytes); got != `[{"ts":"t","variant_id":"a"}]` {
		t.Fatalf("got %s", got)
	}
}

func TestExpRowsFromTailNormalizesAndCaps(t *testing.T) {
	tail := `[{"ts":"t0","experiment":"a","metrics":{"m":1},"item":{"case_id":"c1"}},` +
		`{"ts":"t1","metrics":{"m":1}},` + // no arm: dropped, as on disk
		`{"ts":"t2","variant_id":"b","metrics":{"m":"bad"}},` + // malformed: only itself
		`{"ts":"t3","variant_id":"b","metrics":{"m":3}}]`
	rows := expRowsFromTail(tail, 0)
	if len(rows) != 2 || rows[0].VariantID != "a" || rows[0].Dims["case_id"] != "c1" || rows[1].TS != "t3" {
		t.Fatalf("rows = %+v", rows)
	}
	if capped := expRowsFromTail(tail, 1); len(capped) != 1 || capped[0].TS != "t3" {
		t.Fatalf("cap kept %+v, want only the newest", capped)
	}
	if expRowsFromTail("", 0) != nil || expRowsFromTail("{not", 0) != nil {
		t.Fatal("empty/garbage tail must be nil")
	}
}

func TestBridgedRowsTotal(t *testing.T) {
	if got := bridgedRowsTotal(map[string]any{"n_rows_total": float64(1234)}, 200); got != 1234 {
		t.Fatalf("n_rows_total ignored: %d", got)
	}
	if got := bridgedRowsTotal(map[string]any{}, 200); got != 200 {
		t.Fatalf("fallback = %d", got)
	}
	// A total smaller than what is served (fenced rows) never undercounts it.
	if got := bridgedRowsTotal(map[string]any{"n_rows_total": float64(3)}, 5); got != 5 {
		t.Fatalf("undercount = %d", got)
	}
}

// stubBridgedRows swaps the DB read for a fixed tail and records who asked.
func stubBridgedRows(t *testing.T, tail string) *[]string {
	t.Helper()
	asked := []string{}
	orig := bridgedExpRows
	bridgedExpRows = func(sub, app, id string, capN int) []expRow {
		asked = append(asked, sub+"/"+app+"/"+id)
		return expRowsFromTail(tail, capN)
	}
	t.Cleanup(func() { bridgedExpRows = orig })
	return &asked
}

const bridgedTail = `[` +
	`{"ts":"2026-11-01T00:00:00Z","variant_id":"current","metrics":{"realized_pnl_ticks":1.5},` +
	`"dims":{"stage":"screen","stage_index":"0","passed":"True","reason":"ok","case_id":"c1"},"cycle_ts":"c0"},` +
	`{"ts":"2026-11-02T00:00:00Z","variant_id":"musk_v1","metrics":{"realized_pnl_ticks":2.5},` +
	`"dims":{"stage":"screen","passed":"False","reason":"too few trades","case_id":"c1"},"cycle_ts":"c1"}]`

// The case this fixes: no ledger on identity's disk, a tail in the DB.
func TestDetailServesBridgedTailWhenDiskIsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeSeriesBundle(t, dir)
	writeExpState(t, dir, "kol_alpha", `{"metric":"realized_pnl_ticks","n_results":2,"n_rows_total":740}`)
	asked := stubBridgedRows(t, bridgedTail)

	d, found := loadExperimentDetailFor("sub-1", "quant-research", dir, "kol_alpha")
	if !found {
		t.Fatal("not found")
	}
	if len(*asked) != 1 || (*asked)[0] != "sub-1/quant-research/kol_alpha" {
		t.Fatalf("tail lookup = %v", *asked)
	}
	rows, _ := d["results"].([]expRow)
	if len(rows) != 2 {
		t.Fatalf("results = %#v", d["results"])
	}
	// What lumid-ui's evidence grid reads.
	if rows[1].Dims["stage"] != "screen" || rows[1].Dims["passed"] != "False" || rows[1].Dims["reason"] != "too few trades" {
		t.Fatalf("dims = %+v", rows[1].Dims)
	}
	if d["results_source"] != "bridge_tail" {
		t.Fatalf("results_source = %v", d["results_source"])
	}
	if d["results_total"] != 740 || d["results_truncated"] != true {
		t.Fatalf("total/truncated = %v/%v", d["results_total"], d["results_truncated"])
	}
	// series and cases derive from the tail exactly as from disk.
	b, _ := json.Marshal(d["series"])
	want := `[{"points":[{"ts":"2026-11-01T00:00:00Z","v":1.5}],"variant_id":"current"},` +
		`{"points":[{"ts":"2026-11-02T00:00:00Z","v":2.5}],"variant_id":"musk_v1"}]`
	if string(b) != want {
		t.Fatalf("series =\n%s\nwant\n%s", b, want)
	}
	if d["series_source"] != "results_ledger" || d["series_kind"] != "raw" {
		t.Fatalf("series source/kind = %v/%v", d["series_source"], d["series_kind"])
	}
	cases, _ := d["cases"].([]gin.H)
	if len(cases) != 1 || cases[0]["case_id"] != "c1" || cases[0]["n"] != 2 {
		t.Fatalf("cases = %#v", d["cases"])
	}
}

// Same answer the disk path would give for the same rows.
func TestBridgedTailMatchesTheDiskDerivation(t *testing.T) {
	disk := t.TempDir()
	writeSeriesBundle(t, disk)
	var raws []json.RawMessage
	_ = json.Unmarshal([]byte(bridgedTail), &raws)
	lines := make([]string, 0, len(raws))
	for _, r := range raws {
		lines = append(lines, string(r))
	}
	writeExpLedger(t, disk, "kol_alpha", lines...)
	fromDisk, _ := loadExperimentDetailFor("", "", disk, "kol_alpha")

	bridged := t.TempDir()
	writeSeriesBundle(t, bridged)
	stubBridgedRows(t, bridgedTail)
	fromTail, _ := loadExperimentDetailFor("sub-1", "quant-research", bridged, "kol_alpha")

	for _, k := range []string{"results", "series", "cases", "results_total"} {
		a, _ := json.Marshal(fromDisk[k])
		b, _ := json.Marshal(fromTail[k])
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs:\ndisk %s\ntail %s", k, a, b)
		}
	}
}

// The disk still wins whenever it has rows; the tail is not even read.
func TestDetailDiskRowsBeatBridgedTail(t *testing.T) {
	dir := t.TempDir()
	writeSeriesBundle(t, dir)
	writeExpLedger(t, dir, "kol_alpha",
		`{"ts":"2026-10-01T00:00:00Z","variant_id":"current","metrics":{"realized_pnl_ticks":9}}`)
	asked := stubBridgedRows(t, bridgedTail)
	d, _ := loadExperimentDetailFor("sub-1", "quant-research", dir, "kol_alpha")
	if len(*asked) != 0 {
		t.Fatalf("tail consulted although disk had rows: %v", *asked)
	}
	rows, _ := d["results"].([]expRow)
	if len(rows) != 1 || rows[0].TS != "2026-10-01T00:00:00Z" {
		t.Fatalf("results = %#v", d["results"])
	}
	if d["results_source"] != "results_ledger" || d["results_total"] != 1 {
		t.Fatalf("source/total = %v/%v", d["results_source"], d["results_total"])
	}
}

// No user/app (a directory-only caller, e.g. the chat tool) → no tail lookup.
func TestDetailWithoutUserDoesNotReadTheTail(t *testing.T) {
	dir := t.TempDir()
	writeSeriesBundle(t, dir)
	asked := stubBridgedRows(t, bridgedTail)
	d, _ := loadExperimentDetailFor("", "", dir, "kol_alpha")
	if len(*asked) != 0 {
		t.Fatalf("tail consulted without a user: %v", *asked)
	}
	if rows, _ := d["results"].([]expRow); len(rows) != 0 || d["results_total"] != 0 {
		t.Fatalf("results = %#v total %v", d["results"], d["results_total"])
	}
}

// ── DB-backed: the real bridge handler ──────────────────────────────────────

func postExpBridge(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/internal/app-experiments", InternalAppExperimentRecord)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/internal/app-experiments", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestBridgeStoresRowsAndAnAbsentKeyKeepsThem(t *testing.T) {
	db := setupSeriesDB(t)
	sub := fmt.Sprintf("rows-%d", time.Now().UnixNano())
	t.Cleanup(func() { db.Where("user_sub = ?", sub).Delete(&models.MeAppExperiment{}) })
	var rows []any
	_ = json.Unmarshal([]byte(bridgedTail), &rows)

	out := postExpBridge(t, map[string]any{"user_sub": sub, "app": "a", "experiment_id": "e",
		"state": map[string]any{"n_results": 2}, "rows": rows})
	if data, _ := out["data"].(map[string]any); data["rows_stored"] != float64(2) {
		t.Fatalf("response = %v", out)
	}
	if got := storedExpRowsTail(sub, "a", "e", 0); len(got) != 2 {
		t.Fatalf("stored %d rows", len(got))
	}

	// An older scheduler: no `rows` key. State updates, the tail survives.
	postExpBridge(t, map[string]any{"user_sub": sub, "app": "a", "experiment_id": "e",
		"state": map[string]any{"n_results": 3}})
	if got := storedExpRowsTail(sub, "a", "e", 0); len(got) != 2 {
		t.Fatalf("a body without rows erased the tail: %d rows left", len(got))
	}
	if st := storedExpState(sub, "a", "e"); st["n_results"] != float64(3) {
		t.Fatalf("state not updated: %v", st)
	}

	// An explicitly empty list does replace it.
	postExpBridge(t, map[string]any{"user_sub": sub, "app": "a", "experiment_id": "e",
		"state": map[string]any{"n_results": 0}, "rows": []any{}})
	if got := storedExpRowsTail(sub, "a", "e", 0); len(got) != 0 {
		t.Fatalf("empty rows did not clear the tail: %d", len(got))
	}
}
