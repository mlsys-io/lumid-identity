package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

// ── cursor parsing ─────────────────────────────────────────────────────────

func TestRunsPageParams(t *testing.T) {
	tok := encodeRunCursor(runCursor{T: 1764000000.25, ID: "scheduled:a:b:20251124T160000Z"})
	legacy := base64.URLEncoding.EncodeToString([]byte("120"))

	cases := []struct {
		cursor, before string
		wantErr        bool
		wantOffset     int
		wantT          float64
		wantID         string
	}{
		{"", "", false, -1, 0, ""},
		{tok, "", false, -1, 1764000000.25, "scheduled:a:b:20251124T160000Z"},
		{"", tok, false, -1, 1764000000.25, "scheduled:a:b:20251124T160000Z"},
		{legacy, "", false, 120, 0, ""},
		{"", "1764000000", false, -1, 1764000000, ""},
		{"", "1764000000.5", false, -1, 1764000000.5, ""},
		{"", "2025-11-24T16:00:00Z", false, -1, 1764000000, ""},
		{"", "2025-11-24T16:00:00.5Z", false, -1, 1764000000.5, ""},
		{"not-base64!!", "", false, -1, 0, ""}, // legacy leniency: first page
		{"", "yesterday", true, 0, 0, ""},
		{"", "r1.!!!", true, 0, 0, ""},
		{tok, "1764000000", true, 0, 0, ""},
	}
	for _, tc := range cases {
		p, err := parseRunsPageParams(tc.cursor, tc.before)
		if (err != nil) != tc.wantErr {
			t.Errorf("cursor=%q before=%q: err=%v wantErr=%v", tc.cursor, tc.before, err, tc.wantErr)
			continue
		}
		if tc.wantErr {
			continue
		}
		if p.offset != tc.wantOffset {
			t.Errorf("cursor=%q before=%q: offset=%d want %d", tc.cursor, tc.before, p.offset, tc.wantOffset)
		}
		if tc.wantT == 0 {
			if p.keyset != nil {
				t.Errorf("cursor=%q before=%q: unexpected keyset %+v", tc.cursor, tc.before, *p.keyset)
			}
			continue
		}
		if p.keyset == nil || math.Abs(p.keyset.T-tc.wantT) > 1e-6 || p.keyset.ID != tc.wantID {
			t.Errorf("cursor=%q before=%q: keyset=%+v want t=%v id=%q", tc.cursor, tc.before, p.keyset, tc.wantT, tc.wantID)
		}
	}
}

// ── keyset walk over a simulated, CAPPED run store ─────────────────────────

// fakeRunSources emulates collectRunsFrom: a run store whose scan is capped at
// runStoreScanCap newest rows ≤ until (integer seconds, like run_ts), plus a
// journal with fractional timestamps that collide with store seconds.
type fakeRunSources struct {
	store   []RunRow
	journal []RunRow
}

func (f *fakeRunSources) scan(until time.Time) ([]RunRow, bool, float64) {
	u := float64(until.Unix())
	var st []RunRow
	for _, r := range f.store {
		if r.StartedAt <= u {
			st = append(st, r)
		}
	}
	// ORDER BY run_ts DESC — ties in arbitrary (here: reversed) order, as
	// MySQL gives no tie order either.
	sort.SliceStable(st, func(i, j int) bool { return st[i].StartedAt > st[j].StartedAt })
	capped := false
	var oldest float64
	if len(st) >= runStoreScanCap {
		st, capped = st[:runStoreScanCap], true
	}
	if len(st) > 0 {
		oldest = st[len(st)-1].StartedAt
	}
	rows := append([]RunRow{}, st...)
	for _, r := range f.journal {
		if r.StartedAt <= u {
			rows = append(rows, r)
		}
	}
	return rows, capped, oldest
}

func newFakeRunSources(nStore, nJournal int, base float64) *fakeRunSources {
	f := &fakeRunSources{}
	for i := 0; i < nStore; i++ {
		// 3 runs per second across 4 apps → many exact ties.
		ts := base - float64(i/3)
		state := "succeeded"
		if i%10 == 0 {
			state = "failed"
		}
		f.store = append(f.store, RunRow{
			RunID: fmt.Sprintf("scheduled:app%d:loop:%d", i%4, i), StartedAt: ts, State: state,
			WorkflowSlug: fmt.Sprintf("app%d:loop", i%4),
		})
	}
	for i := 0; i < nJournal; i++ {
		ts := base - float64(i)*1.37 // fractional, lands inside store seconds
		if i%5 == 0 {
			ts = math.Floor(ts) // and some exactly ON a store second
		}
		state := "succeeded"
		if i%7 == 0 {
			state = "failed"
		}
		f.journal = append(f.journal, RunRow{
			RunID: fmt.Sprintf("scheduled:op:j:%d", i), StartedAt: ts, State: state, WorkflowSlug: "op:j",
		})
	}
	return f
}

// walk pages exactly as MeRuns does: narrow the scan to the cursor, filter,
// sort, page.
func (f *fakeRunSources) walk(t *testing.T, limit int, state string, between func(page int)) []RunRow {
	t.Helper()
	var got []RunRow
	var cur *runCursor
	until := time.Unix(int64(f.store[0].StartedAt)+60, 0)
	for page := 0; page < 10000; page++ {
		rows, capped, oldest := f.scan(keysetScanUntil(cur, until))
		filtered := filterRuns(rows, state, "")
		sortRunsNewestFirst(filtered)
		out, _, next := pageByKeyset(filtered, cur, limit, capped, oldest)
		if len(out) > limit {
			t.Fatalf("page %d has %d rows > limit %d", page, len(out), limit)
		}
		got = append(got, out...)
		if next == "" {
			return got
		}
		c, ok := decodeRunCursor(next)
		if !ok {
			t.Fatalf("next_cursor %q does not decode", next)
		}
		cur = c
		if between != nil {
			between(page)
		}
	}
	t.Fatal("walk did not terminate")
	return nil
}

func expectedRuns(f *fakeRunSources, state string) []RunRow {
	all := filterRuns(append(append([]RunRow{}, f.store...), f.journal...), state, "")
	sortRunsNewestFirst(all)
	return all
}

func assertSameRuns(t *testing.T, label string, got, want []RunRow) {
	t.Helper()
	seen := map[string]int{}
	for _, r := range got {
		seen[r.RunID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("%s: %s served %d times", label, id, n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: walked %d rows, want %d", label, len(got), len(want))
	}
	for i := range want {
		if i >= len(got) {
			t.Errorf("%s: missing from index %d (first missing %s)", label, i, want[i].RunID)
			break
		}
		if got[i].RunID != want[i].RunID {
			t.Errorf("%s: order differs at %d: got %s want %s", label, i, got[i].RunID, want[i].RunID)
			break
		}
	}
}

func TestRunsKeysetWalksPastTheStoreCap(t *testing.T) {
	f := newFakeRunSources(1337, 400, 1764000000)
	for _, limit := range []int{1, 7, 50, 100, 499, 500} {
		got := f.walk(t, limit, "", nil)
		assertSameRuns(t, fmt.Sprintf("limit=%d", limit), got, expectedRuns(f, ""))
	}
}

func TestRunsKeysetWalkWithAStateFilter(t *testing.T) {
	// ~10% of store rows fail: most capped scans hold fewer matches than the
	// page size, so pages come back short and the cursor must still advance.
	f := newFakeRunSources(1337, 400, 1764000000)
	for _, limit := range []int{3, 50, 500} {
		got := f.walk(t, limit, "failed", nil)
		assertSameRuns(t, fmt.Sprintf("failed limit=%d", limit), got, expectedRuns(f, "failed"))
	}
}

func TestRunsKeysetNoDupesWhenRunsLandMidWalk(t *testing.T) {
	// The offset cursor this replaced shifted by one for every run recorded
	// at the head between two pages, serving the boundary row twice.
	f := newFakeRunSources(1200, 0, 1764000000)
	want := expectedRuns(f, "")
	head := f.store[0].StartedAt
	got := f.walk(t, 100, "", func(page int) {
		f.store = append([]RunRow{{
			RunID: fmt.Sprintf("scheduled:new:loop:%d", page), StartedAt: head + float64(page+1), State: "running",
		}}, f.store...)
	})
	assertSameRuns(t, "insert-during-walk", got, want)
}

func TestRunsKeysetDegenerateSecondTerminates(t *testing.T) {
	// > runStoreScanCap rows in one second: no keyset over whole seconds can
	// split them; the walk must still terminate rather than loop.
	f := &fakeRunSources{}
	for i := 0; i < 700; i++ {
		f.store = append(f.store, RunRow{RunID: fmt.Sprintf("scheduled:a:l:%04d", i), StartedAt: 1764000000})
	}
	got := f.walk(t, 100, "", nil)
	if len(got) == 0 {
		t.Fatal("served nothing")
	}
}

func TestRunsPageByOffsetOutOfRangeDoesNotPanic(t *testing.T) {
	rows := []RunRow{{RunID: "a", StartedAt: 3}, {RunID: "b", StartedAt: 2}}
	page, total, next := pageByOffset(rows, 50, 10, false, 0)
	if len(page) != 0 || total != 2 || next != "" {
		t.Fatalf("page=%v total=%d next=%q", page, total, next)
	}
	page, _, next = pageByOffset(rows, 0, 1, false, 0)
	if len(page) != 1 || next == "" {
		t.Fatalf("first page=%v next=%q", page, next)
	}
	// The legacy page hands back a keyset token that continues correctly.
	cur, ok := decodeRunCursor(next)
	if !ok {
		t.Fatalf("legacy page next_cursor is not a keyset token: %q", next)
	}
	p2, _, _ := pageByKeyset(rows, cur, 10, false, 0)
	if len(p2) != 1 || p2[0].RunID != "b" {
		t.Fatalf("continuation = %v", p2)
	}
}

// ── sub-source timeouts ────────────────────────────────────────────────────

func runsTestContext(t *testing.T) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/me/runs", nil)
	return c
}

// seedJournal writes n cycle rows for one tenant app under a temp operator
// home, so the journal source has something to return.
func seedJournal(t *testing.T, user string, n int) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	dir := filepath.Join(home, ".tenants", user, ".xp", "apps", "demo", "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	now := float64(time.Now().Unix())
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"loop":"simulate","ts":%f,"ok":true}`+"\n", now-float64(i*60))
	}
	if err := os.WriteFile(filepath.Join(dir, "journal.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The 6 s: n8n is not deployed on UKS, its default address blackholes, and
// collectRuns waited a fixed 6 s on it, serially, on every call. Now: the wait
// is bounded, concurrent, and the connect failure is remembered.
func TestCollectRunsBoundsAnUnreachableN8n(t *testing.T) {
	common.ResetN8nBreaker()
	t.Cleanup(common.ResetN8nBreaker)
	// TEST-NET-1 (RFC 5737): never routed. Depending on the host it either
	// blackholes (the production shape) or fails at once; both must be bounded.
	t.Setenv("N8N_BASE_URL", "http://192.0.2.1:5678")
	t.Setenv("ME_RUNS_N8N_TIMEOUT_MS", "300")
	seedJournal(t, "u-runs-timeout", 5)
	prevDB := common.DB
	common.DB = nil
	t.Cleanup(func() { common.DB = prevDB })

	now := time.Now().UTC()
	t0 := time.Now()
	rc := collectRunsFrom(runsTestContext(t), "u-runs-timeout", now.Add(-24*time.Hour), now.Add(time.Minute))
	first := time.Since(t0)
	if first > 1200*time.Millisecond {
		t.Fatalf("first call took %v; the n8n source must be bounded by ~300ms", first)
	}
	if st := rc.status["n8n"]; st != "timeout" && st != "unreachable" && st != "error" {
		t.Fatalf("n8n status = %q", st)
	}
	if len(rc.rows) != 5 {
		t.Fatalf("journal rows lost when n8n failed: got %d, want 5", len(rc.rows))
	}

	t0 = time.Now()
	rc = collectRunsFrom(runsTestContext(t), "u-runs-timeout", now.Add(-24*time.Hour), now.Add(time.Minute))
	second := time.Since(t0)
	if rc.status["n8n"] != "unreachable" {
		t.Fatalf("second call n8n status = %q, want unreachable (breaker)", rc.status["n8n"])
	}
	if second > 100*time.Millisecond {
		t.Fatalf("second call took %v; a known-unreachable n8n must cost nothing", second)
	}
	if len(rc.rows) != 5 {
		t.Fatalf("second call rows = %d", len(rc.rows))
	}
	t.Logf("first=%v second=%v", first, second)
}

// A reachable-but-slow n8n times out for THIS caller but is not marked
// unreachable — other callers allow it longer.
func TestCollectRunsSlowN8nTimesOutWithoutTrippingTheBreaker(t *testing.T) {
	common.ResetN8nBreaker()
	t.Cleanup(common.ResetN8nBreaker)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	t.Setenv("N8N_BASE_URL", srv.URL)
	t.Setenv("ME_RUNS_N8N_TIMEOUT_MS", "200")
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	prevDB := common.DB
	common.DB = nil
	t.Cleanup(func() { common.DB = prevDB })

	now := time.Now().UTC()
	for i := 0; i < 2; i++ {
		t0 := time.Now()
		rc := collectRunsFrom(runsTestContext(t), "u-slow", now.Add(-time.Hour), now)
		if d := time.Since(t0); d > 800*time.Millisecond {
			t.Fatalf("call %d took %v", i, d)
		}
		if rc.status["n8n"] != "timeout" {
			t.Fatalf("call %d: n8n status = %q, want timeout (not unreachable)", i, rc.status["n8n"])
		}
	}
}

// Server-Timing names every source with its outcome.
func TestRunsServerTiming(t *testing.T) {
	rc := runsCollection{
		status:  map[string]string{"journal": "ok", "store": "ok", "n8n": "unreachable"},
		timings: map[string]time.Duration{"journal": time.Millisecond, "store": 2 * time.Millisecond, "n8n": 0},
	}
	got := rc.serverTiming()
	for _, want := range []string{`journal;dur=1.0;desc="ok"`, `store;dur=2.0;desc="ok"`, `n8n;dur=0.0;desc="unreachable"`} {
		if !strings.Contains(got, want) {
			t.Errorf("Server-Timing %q lacks %q", got, want)
		}
	}
}

// ── end to end through MeRuns, against MySQL ───────────────────────────────

// The feed used to END at the run store's 500th row: no cursor could reach
// past it. Seed more than twice that and walk every page through the handler.
func TestMeRunsCursorWalksPastFiveHundredRows(t *testing.T) {
	db := setupClaudePoolTestDB(t) // skips without TEST_MYSQL_DSN
	if config.G == nil {
		config.G = &config.Config{}
		t.Cleanup(func() { config.G = nil })
	}
	if common.Keys.Active() == nil {
		cfg := &config.Config{}
		cfg.Signing.KeyDir = t.TempDir()
		if err := common.LoadKeys(cfg); err != nil {
			t.Fatalf("keys: %v", err)
		}
	}
	common.ResetN8nBreaker()
	t.Cleanup(common.ResetN8nBreaker)
	t.Setenv("N8N_BASE_URL", "http://192.0.2.1:5678")
	t.Setenv("ME_RUNS_N8N_TIMEOUT_MS", "200")
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())

	user := claudePoolTestUser(t, db, "runs")
	t.Cleanup(func() { db.Where("user_sub = ?", user).Delete(&models.MeAppRun{}) })
	const n = 1234
	base := time.Now().Add(-time.Hour).Unix()
	batch := make([]models.MeAppRun, 0, n)
	for i := 0; i < n; i++ {
		// 2 apps share every second → ties the cursor must order by run_id.
		batch = append(batch, models.MeAppRun{
			UserSub: user, App: fmt.Sprintf("app%d", i%2), Loop: "simulate",
			RunTs: base - int64(i/2), Ok: i%9 != 0, Source: "self_report",
		})
	}
	if err := db.CreateInBatches(batch, 500).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	tok, _, _, err := common.IssueJWT(user, user+"@example.com", "user", nil)
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	r := gin.New()
	r.GET("/api/v1/me/runs", MeRuns)
	since := time.Unix(base-3600, 0).UTC().Format(time.RFC3339)

	get := func(q string) (int, map[string]any, http.Header) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me/runs?since="+since+"&"+q, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var env map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		data, _ := env["data"].(map[string]any)
		return w.Code, data, w.Header()
	}

	// Default page: unchanged shape and size.
	code, data, hdr := get("")
	if code != 200 || int(data["count"].(float64)) != 50 {
		t.Fatalf("default page: code=%d count=%v", code, data["count"])
	}
	if !strings.Contains(hdr.Get("Server-Timing"), "store;dur=") {
		t.Errorf("Server-Timing = %q", hdr.Get("Server-Timing"))
	}

	for _, tc := range []struct {
		q    string
		want int
	}{{"limit=200", n}, {"limit=500", n}, {"limit=77&state=failed", (n + 8) / 9}} {
		seen := map[string]bool{}
		var last float64 = math.Inf(1)
		lastID := ""
		q := tc.q
		pages := 0
		for {
			code, data, _ := get(q)
			if code != 200 {
				t.Fatalf("%s: code %d", tc.q, code)
			}
			for _, x := range data["runs"].([]any) {
				row := x.(map[string]any)
				id, ts := row["run_id"].(string), row["started_at"].(float64)
				if seen[id] {
					t.Fatalf("%s: duplicate %s on page %d", tc.q, id, pages)
				}
				if ts > last || (ts == last && id > lastID) {
					t.Fatalf("%s: order broken at %s", tc.q, id)
				}
				seen[id], last, lastID = true, ts, id
			}
			pages++
			next, _ := data["next_cursor"].(string)
			if hm, _ := data["has_more"].(bool); hm != (next != "") {
				t.Fatalf("%s: has_more=%v next=%q", tc.q, hm, next)
			}
			if next == "" || pages > 100 {
				break
			}
			q = tc.q + "&cursor=" + next
		}
		if len(seen) != tc.want {
			t.Errorf("%s: walked %d distinct runs over %d pages, want %d", tc.q, len(seen), pages, tc.want)
		}
	}

	// before= with a bare unix time: strictly older.
	cut := base - 100
	_, data, _ = get(fmt.Sprintf("limit=500&before=%d", cut))
	for _, x := range data["runs"].([]any) {
		if ts := x.(map[string]any)["started_at"].(float64); ts >= float64(cut) {
			t.Fatalf("before=%d served a run at %v", cut, ts)
		}
	}
	if code, _, _ := get("before=yesterday"); code != http.StatusBadRequest {
		t.Errorf("before=yesterday: code %d, want 400", code)
	}
}
