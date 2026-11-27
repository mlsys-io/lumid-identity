package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func TestLqtPlanKeysAPinnedWindowByContent(t *testing.T) {
	a := decodeInputs(t, `{"name":"mine","symbol":"KX-1","strategy":{"program":"p","until":"2026-11-01T00:00:00Z","window_secs":3600}}`)
	b := decodeInputs(t, `{"strategy":{"window_secs":3600,"until":"2026-11-01T00:00:00Z","program":"p"},"symbol":"KX-1","name":"theirs"}`)
	pa, err := lqtBacktestPlan(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := lqtBacktestPlan(b)
	if _, once := pa.material["once"]; once {
		t.Fatal("a pinned past window was treated as unrepeatable")
	}
	if measureKey("lqt-backtest", pa.version, pa.material) != measureKey("lqt-backtest", pb.version, pb.material) {
		t.Fatal("key order or the label changed the key")
	}
	if pa.version != "harness-3" {
		t.Errorf("version = %q", pa.version)
	}
}

func TestLqtPlanNeverRepeatsAnUnpinnedOrFutureWindow(t *testing.T) {
	for _, in := range []string{
		`{"symbol":"KX-1","strategy":{"program":"p"}}`,
		`{"symbol":"KX-1","strategy":{"program":"p","until":"2999-01-01T00:00:00Z"}}`,
	} {
		p1, _ := lqtBacktestPlan(decodeInputs(t, in))
		p2, _ := lqtBacktestPlan(decodeInputs(t, in))
		if measureKey("lqt-backtest", p1.version, p1.material) == measureKey("lqt-backtest", p2.version, p2.material) {
			t.Errorf("%s: two requests share a key, but the worker anchors this window to now", in)
		}
	}
	if _, err := lqtBacktestPlan(decodeInputs(t, `{"strategy":{"program":"p"}}`)); err == nil {
		t.Error("no symbol accepted")
	}
	if _, err := lqtBacktestPlan(decodeInputs(t, `{"symbol":"KX","strategy":"p"}`)); err == nil {
		t.Error("a non-object strategy accepted")
	}
}

func TestLqtParseUntil(t *testing.T) {
	want := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, v := range []any{"2026-11-01T00:00:00Z", "2026-11-01", json.Number("1793491200"),
		json.Number("1793491200000"), json.Number("1793491200000000000"), "1793491200"} {
		got, ok := lqtParseUntil(v)
		if !ok || !got.Equal(want) {
			t.Errorf("%v -> %v %v", v, got, ok)
		}
	}
	if _, ok := lqtParseUntil("soon"); ok {
		t.Error("parsed nonsense")
	}
}

func TestLqtShareScopeFollowsTheReceipt(t *testing.T) {
	rec := func(replay, signals, source string, harness any) map[string]any {
		return map[string]any{"status": "done", "replay": map[string]any{"replay": replay, "signals": signals,
			"tape_window_source": source, "harness_version": harness}}
	}
	cases := []struct {
		name     string
		claim    map[string]any
		pinned   bool
		scope    string
		reusable bool
	}{
		{"recorded prints, no recorded signals", rec("pg_tape", "static", "claim", json.Number("3")), true, "global", true},
		{"recorded signals may be the tenant's own", rec("pg_tape", "recorded", "claim", json.Number("3")), true, "tenant:u1", true},
		{"synthetic replay", rec("synthetic_lcg", "static", "claim", json.Number("3")), true, "tenant:u1", false},
		{"window from the env, not the claim", rec("pg_tape", "static", "env", json.Number("3")), true, "tenant:u1", false},
		{"another harness", rec("pg_tape", "static", "claim", json.Number("2")), true, "tenant:u1", false},
		{"unpinned request", rec("pg_tape", "static", "claim", json.Number("3")), false, "tenant:u1", false},
		{"no receipt", map[string]any{"status": "done"}, true, "tenant:u1", false},
		{"recorded signals all from the shared publisher", withSources(rec("pg_tape", "recorded", "claim", json.Number("3")),
			map[string]any{"ofi_z": "shared", "vpin": "shared"}), true, "global", true},
		{"one name is the tenant's own", withSources(rec("pg_tape", "recorded", "claim", json.Number("3")),
			map[string]any{"ofi_z": "shared", "vpin": "own"}), true, "tenant:u1", true},
		{"sources unknown", withSources(rec("pg_tape", "recorded", "claim", json.Number("3")),
			map[string]any{"ofi_z": "unknown"}), true, "tenant:u1", true},
	}
	for _, tc := range cases {
		scope, reusable := lqtShareScope(tc.claim, tc.pinned, "3", "u1")
		if scope != tc.scope || reusable != tc.reusable {
			t.Errorf("%s: got %s/%v, want %s/%v", tc.name, scope, reusable, tc.scope, tc.reusable)
		}
	}
}

// ── The full flow against a fake backtest job API (needs TEST_MYSQL_DSN) ─

type fakeGateway struct {
	mu     sync.Mutex
	posts  []string
	claims map[string]string // claim id -> strategy program
	paced  bool
}

func (g *fakeGateway) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/research/backtests":
		if strings.Contains(string(b), "pace-me") && !g.paced {
			g.paced = true
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"conflict","detail":"too_soon: retry_after_secs=1"}`))
			return
		}
		id := []string{"11111111-1111-1111-1111-11111111111", "22222222-2222-2222-2222-22222222222"}[len(g.posts)%2] +
			string(rune('0'+len(g.posts)%10))
		g.posts = append(g.posts, string(b))
		var body struct {
			Strategy map[string]any `json:"strategy"`
		}
		_ = json.Unmarshal(b, &body)
		g.claims[id], _ = body.Strategy["program"].(string)
		_, _ = w.Write([]byte(`{"claim_id":"` + id + `","status":"queued"}`))
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/research/backtests/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/research/backtests/")
		prog, known := g.claims[id]
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		signals := "static"
		if strings.Contains(prog, "recorded") {
			signals = "recorded"
		}
		_, _ = w.Write([]byte(`{"claim_id":"` + id + `","status":"done","replay":{"replay":"pg_tape","signals":"` +
			signals + `","tape_window_source":"claim","harness_version":3,"realized_pnl_ticks":42}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func lqtTestSetup(t *testing.T) (*fakeGateway, string, string) {
	t.Helper()
	_, owner, other := fleetTestSetup(t)
	g := &fakeGateway{claims: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(g.handler))
	t.Cleanup(srv.Close)
	t.Setenv("LQT_GATEWAY_BASE", srv.URL)
	t.Setenv("MEASURE_LQT_HARNESS", "3")
	ownerSub, otherSub := subOf(t, owner), subOf(t, other)
	measureCleanup(t, ownerSub, otherSub)
	t.Cleanup(func() {
		common.DB.Where("user_sub IN ?", []string{ownerSub, otherSub}).Delete(&models.AppSecret{})
	})
	return g, owner, other
}

func lqtBody(program string, pinned bool) string {
	until := ""
	if pinned {
		until = `,"until":"2026-11-01T00:00:00Z"`
	}
	return `{"instrument":"lqt-backtest","app":"quant-research","inputs":{"symbol":"KX-1","strategy":{"program":"` +
		program + `"` + until + `}}}`
}

func TestLqtMeasureIsSharedOnlyWhenTheReceiptAllows(t *testing.T) {
	g, owner, other := lqtTestSetup(t)

	// No recorded signals: measured once, reused by another tenant.
	code, first := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("static-strat", true), owner)
	if code != http.StatusAccepted || first["status"] != "running" {
		t.Fatalf("first = %d %v", code, first)
	}
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner)
	res, _ := got["result"].(map[string]any)
	if code != 200 || got["status"] != "succeeded" || res["share"] != "everyone" {
		t.Fatalf("settled = %d %v", code, got)
	}
	code, again := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("static-strat", true), other)
	if ares, _ := again["result"].(map[string]any); code != 200 || ares["reused"] != true || len(g.posts) != 1 {
		t.Fatalf("other tenant = %d %v (submits %d)", code, again, len(g.posts))
	}

	// Recorded signals: the owner may reuse it, another tenant runs its own.
	_, rec := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("recorded-strat", true), owner)
	_, rec = measureCall(t, "GET", "/api/v1/me/measure/"+rec["key"].(string), "", owner)
	if r, _ := rec["result"].(map[string]any); rec["status"] != "succeeded" || r["share"] != "you" {
		t.Fatalf("recorded = %v", rec)
	}
	if code, mine := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("recorded-strat", true), owner); code != 200 || mine["status"] != "succeeded" {
		t.Fatalf("owner reuse = %d %v", code, mine)
	}
	before := len(g.posts)
	code, theirs := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("recorded-strat", true), other)
	if code != http.StatusAccepted || len(g.posts) != before+1 || theirs["key"] == rec["key"] {
		t.Fatalf("other tenant on recorded signals = %d %v (submits %d -> %d)", code, theirs, before, len(g.posts))
	}
	if code, _ := measureCall(t, "GET", "/api/v1/me/measure/"+rec["key"].(string), "", other); code != 404 {
		t.Errorf("another tenant read a tenant-only measurement: %d", code)
	}
}

func TestLqtPacingIsAQueueNotAFailure(t *testing.T) {
	g, owner, _ := lqtTestSetup(t)
	code, q := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("pace-me", true), owner)
	if code != http.StatusAccepted || q["status"] != "queued" || q["reason"] == nil || len(g.posts) != 0 {
		t.Fatalf("paced = %d %v", code, q)
	}
	time.Sleep(1100 * time.Millisecond)
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+q["key"].(string), "", owner)
	if code != http.StatusAccepted || got["status"] != "running" || len(g.posts) != 1 {
		t.Fatalf("after the wait = %d %v (submits %d)", code, got, len(g.posts))
	}
}

func TestLqtUnpinnedWindowIsNeverReused(t *testing.T) {
	g, owner, _ := lqtTestSetup(t)
	_, a := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("live-window", false), owner)
	_, a = measureCall(t, "GET", "/api/v1/me/measure/"+a["key"].(string), "", owner)
	if r, _ := a["result"].(map[string]any); a["status"] != "succeeded" || r["share"] != "this run only" {
		t.Fatalf("unpinned = %v", a)
	}
	_, b := measureCall(t, "POST", "/api/v1/me/measure", lqtBody("live-window", false), owner)
	if b["key"] == a["key"] || len(g.posts) != 2 {
		t.Fatalf("an unpinned window was reused: %v (submits %d)", b, len(g.posts))
	}
}

func withSources(claim map[string]any, sources map[string]any) map[string]any {
	claim["replay"].(map[string]any)["signal_sources"] = sources
	return claim
}

func TestMeasuredFromBlobReadsOnlyWhatTheRunSaid(t *testing.T) {
	reused, on := measuredFromBlob(map[string]any{"metrics": map[string]any{
		"reused": true, "measured_on": " Simulated RTX 5080 (mlsys-simulator v0.1.3) · reused from an identical run "}})
	if !reused || on != "Simulated RTX 5080 (mlsys-simulator v0.1.3) · reused from an identical run" {
		t.Errorf("got %v %q", reused, on)
	}
	if r, o := measuredFromBlob(map[string]any{"metrics": map[string]any{"reused": "yes", "measured_on": 3}}); r || o != "" {
		t.Errorf("non-bool / non-string inferred: %v %q", r, o)
	}
	if r, o := measuredFromBlob(map[string]any{}); r || o != "" {
		t.Errorf("no metrics: %v %q", r, o)
	}
	// The run store's shape: the scheduler flattens the app's metrics to the top.
	if r, o := measuredFromBlob(map[string]any{"primary_metric": map[string]any{"name": "objective", "value": 22.4},
		"reused": true, "measured_on": "Simulated RTX 5080 (mlsys-simulator v0.1.3) · reused from an identical run"}); !r || o == "" {
		t.Errorf("flattened store blob: %v %q", r, o)
	}
	if r, o := measuredFromBlob(map[string]any{"reused": "true"}); r || o != "" {
		t.Errorf("flattened non-bool inferred: %v %q", r, o)
	}
}
