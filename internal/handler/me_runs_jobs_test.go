package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"lumid_identity/internal/common"
)

// stubJobsBearer replaces the DB + keyring lookup with a fixed bearer.
func stubJobsBearer(t *testing.T) {
	t.Helper()
	prev := jobsBearerFor
	jobsBearerFor = func(userID string) (string, error) { return "test-bearer-" + userID, nil }
	t.Cleanup(func() { jobsBearerFor = prev })
	resetMeRunsJobsState()
	t.Cleanup(resetMeRunsJobsState)
}

func jobsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("LUMID_DATA_URL", srv.URL)
	return srv, &hits
}

func TestEntranceJobsMapToRunRows(t *testing.T) {
	stubJobsBearer(t)
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	var gotAuth, gotPath string
	jobsServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path+"?"+r.URL.RawQuery
		jobs := []map[string]any{
			{"job_id": "j-ok", "app": "qr", "runtime": "lumilake", "status": "succeeded",
				"spec": map[string]any{"name": "nightly join"}, "created_at": at(-time.Hour),
				"started_at": at(-time.Hour + time.Minute), "ended_at": at(-time.Hour + 3*time.Minute)},
			{"job_id": "j-planned", "app": "qr", "runtime": "lumilake", "status": "planned",
				"spec": map[string]any{}, "created_at": at(-30 * time.Minute)},
			{"job_id": "j-failed", "app": "mbb", "runtime": "flowmesh", "status": "failed",
				"spec": nil, "error": map[string]any{"code": "x", "message": "worker died\ntrace"}, "created_at": at(-20 * time.Minute)},
			{"job_id": "j-refused", "app": "mbb", "runtime": "sandbox", "status": "refused",
				"error": "no site can reach findata", "created_at": at(-10 * time.Minute)},
			{"job_id": "j-cancel", "app": "mbb", "runtime": "sandbox", "status": "cancelled", "created_at": at(-5 * time.Minute)},
			{"job_id": "j-old", "app": "qr", "runtime": "lumilake", "status": "succeeded", "created_at": at(-48 * time.Hour)},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jobs": jobs, "hubs": []any{map[string]any{"id": "home", "ok": true}}})
	})

	rows, st := entranceJobRuns(context.Background(), "u1", now.Add(-24*time.Hour), now.Add(time.Minute), time.Second)
	if st != "ok" {
		t.Fatalf("status = %q", st)
	}
	if gotAuth != "Bearer test-bearer-u1" {
		t.Errorf("Authorization = %q (must be the user's bearer)", gotAuth)
	}
	if !strings.HasPrefix(gotPath, "/jobs/v1/jobs?limit=") {
		t.Errorf("path = %q", gotPath)
	}
	by := map[string]RunRow{}
	for _, r := range rows {
		by[r.RunID] = r
	}
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5 (the 48h-old job is outside the window): %+v", len(rows), rows)
	}
	ok := by["job:j-ok"]
	if ok.Kind != "job" || ok.State != "succeeded" || ok.Name != "nightly join" || ok.App != "" ||
		ok.WorkflowSlug != "job:qr" || ok.Link != "/studio/data-warehouse?tab=jobs&job=j-ok" {
		t.Errorf("succeeded row = %+v", ok)
	}
	if ok.DurationSec < 119 || ok.DurationSec > 121 {
		t.Errorf("duration = %v, want ~120 s (started -> ended)", ok.DurationSec)
	}
	if r := by["job:j-planned"]; r.State != "queued" || r.Name != "qr" {
		t.Errorf("planned row = %+v", r)
	}
	if r := by["job:j-failed"]; r.State != "failed" || r.Reason != "worker died" {
		t.Errorf("failed row = %+v", r)
	}
	if r := by["job:j-refused"]; r.State != "failed" || r.Reason != "refused: no site can reach findata" {
		t.Errorf("refused row = %+v", r)
	}
	if r := by["job:j-cancel"]; r.State != "canceled" {
		t.Errorf("cancelled row = %+v", r)
	}
}

// /me/runs/stream re-collects every 2 s: one fetch per cache window, not per tick.
func TestEntranceJobsAreCachedPerUser(t *testing.T) {
	stubJobsBearer(t)
	_, hits := jobsServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jobs": null}`))
	})
	now := time.Now()
	for i := 0; i < 3; i++ {
		rows, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, time.Second)
		if st != "ok" || rows == nil || len(rows) != 0 {
			t.Fatalf("call %d: rows=%v st=%q (a null jobs list is an empty one)", i, rows, st)
		}
	}
	if n := atomic.LoadInt32(hits); n != 1 {
		t.Errorf("upstream hit %d times for one user, want 1", n)
	}
	_, _ = entranceJobRuns(context.Background(), "u2", now.Add(-time.Hour), now, time.Second)
	if n := atomic.LoadInt32(hits); n != 2 {
		t.Errorf("a second user must not get the first user's cached jobs (hits=%d)", n)
	}
}

func TestEntranceJobsUpstreamStatuses(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{{401, "unauthenticated"}, {403, "unauthenticated"}, {404, "unavailable"}, {500, "error"}, {200, "error"}} {
		stubJobsBearer(t)
		jobsServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(`<html>not json</html>`))
		})
		now := time.Now()
		rows, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, time.Second)
		if st != tc.want || len(rows) != 0 {
			t.Errorf("HTTP %d: status=%q rows=%d, want %q and none", tc.code, st, len(rows), tc.want)
		}
	}
}

// A slow lumid-data is cut off at the timeout and NOT marked down.
func TestEntranceJobsSlowUpstreamTimesOut(t *testing.T) {
	stubJobsBearer(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	t.Setenv("LUMID_DATA_URL", srv.URL)
	now := time.Now()
	for i := 0; i < 2; i++ {
		t0 := time.Now()
		_, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, 200*time.Millisecond)
		if d := time.Since(t0); d > 800*time.Millisecond {
			t.Fatalf("call %d took %v", i, d)
		}
		if st != "timeout" {
			t.Fatalf("call %d: status %q, want timeout (not unreachable)", i, st)
		}
	}
}

// A refused connect is remembered: the next call costs nothing.
func TestEntranceJobsRefusedConnectTripsTheBreaker(t *testing.T) {
	stubJobsBearer(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close() // nothing listens there now
	t.Setenv("LUMID_DATA_URL", base)
	now := time.Now()
	if _, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, time.Second); st != "unreachable" {
		t.Fatalf("status = %q, want unreachable", st)
	}
	if !jobsBaseDown(base, time.Now()) {
		t.Fatalf("breaker not tripped by a refused connect")
	}
	t0 := time.Now()
	if _, st := entranceJobRuns(context.Background(), "u2", now.Add(-time.Hour), now, time.Second); st != "unreachable" {
		t.Fatalf("second status = %q", st)
	}
	if d := time.Since(t0); d > 50*time.Millisecond {
		t.Errorf("known-down call took %v", d)
	}
}

func TestEntranceJobsOffAndUnconfigured(t *testing.T) {
	resetMeRunsJobsState()
	t.Cleanup(resetMeRunsJobsState)
	now := time.Now()
	t.Setenv("ME_RUNS_JOBS", "off")
	if _, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, time.Second); st != "off" {
		t.Errorf("ME_RUNS_JOBS=off: status %q", st)
	}
	t.Setenv("ME_RUNS_JOBS", "")
	// The real bearer minter, with no DB: says so instead of calling out.
	prev := jobsBearerFor
	t.Cleanup(func() { jobsBearerFor = prev })
	jobsBearerFor = func(string) (string, error) { return "", errJobsUnconfigured }
	if _, st := entranceJobRuns(context.Background(), "u1", now.Add(-time.Hour), now, time.Second); st != "unconfigured" {
		t.Errorf("no bearer: status %q", st)
	}
}

func TestMeRunsJobsTimeoutIsClamped(t *testing.T) {
	t.Setenv("ME_RUNS_JOBS_TIMEOUT_MS", "")
	if d := meRunsJobsTimeout(); d != 2*time.Second {
		t.Errorf("default = %v", d)
	}
	t.Setenv("ME_RUNS_JOBS_TIMEOUT_MS", "10000")
	if d := meRunsJobsTimeout(); d != 3*time.Second {
		t.Errorf("clamped = %v, want 3s", d)
	}
	t.Setenv("ME_RUNS_JOBS_TIMEOUT_MS", "500")
	if d := meRunsJobsTimeout(); d != 500*time.Millisecond {
		t.Errorf("override = %v", d)
	}
}

// End to end through collectRunsFrom: job rows join the journal rows, and a
// failing jobs source leaves the other rows intact and says so.
func TestCollectRunsIncludesEntranceJobs(t *testing.T) {
	stubJobsBearer(t)
	t.Setenv("N8N_BASE_URL", "http://192.0.2.1:5678")
	t.Setenv("ME_RUNS_N8N_TIMEOUT_MS", "100")
	seedJournal(t, "u-jobs", 3)
	now := time.Now().UTC()
	jobsServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{map[string]any{
			"job_id": "j1", "app": "qr", "runtime": "lumilake", "status": "running",
			"spec": map[string]any{"name": "join"}, "created_at": now.Add(-time.Minute).Format(time.RFC3339),
		}}})
	})
	withNilDB(t)

	rc := collectRunsFrom(runsTestContext(t), "u-jobs", now.Add(-24*time.Hour), now.Add(time.Minute))
	if rc.status["jobs"] != "ok" {
		t.Fatalf("jobs status = %q", rc.status["jobs"])
	}
	if len(rc.rows) != 4 {
		t.Fatalf("rows = %d, want 3 journal + 1 job", len(rc.rows))
	}
	if !strings.Contains(rc.serverTiming(), `jobs;dur=`) {
		t.Errorf("Server-Timing lacks jobs: %q", rc.serverTiming())
	}

	resetMeRunsJobsState()
	t.Setenv("LUMID_DATA_URL", "http://127.0.0.1:1")
	rc = collectRunsFrom(runsTestContext(t), "u-jobs", now.Add(-24*time.Hour), now.Add(time.Minute))
	if rc.status["jobs"] != "unreachable" {
		t.Fatalf("down jobs status = %q", rc.status["jobs"])
	}
	if len(rc.rows) != 3 {
		t.Fatalf("journal rows lost when the jobs source failed: %d", len(rc.rows))
	}
}

func withNilDB(t *testing.T) {
	t.Helper()
	prev := common.DB
	common.DB = nil
	t.Cleanup(func() { common.DB = prev })
}
