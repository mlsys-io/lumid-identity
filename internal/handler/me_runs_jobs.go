package handler

// /me/runs source 4 — ENTRANCE JOBS: the jobs a user ran through lum.id/data
// (`/jobs/v1/jobs` on lumid-data-service). Without this, a job submitted from
// Studio → Data → Jobs (or an MCP `jobs_submit`) never appeared in the one
// list that is meant to hold every run, whatever runtime carried it.
//
// Called AS THE USER, not as the operator: lumid-data lists only the caller's
// own jobs (`owner_sub = caller.sub`), so the call must carry the user's
// identity. The bearer is the narrowest thing identity can mint for that — a
// 2-minute bridge JWT, audience `lumid-data`, scope `lumid:read` — the same
// audience and scope claude-proxy uses for lum.id/data, so it stays valid
// once introspection enforces JWT audiences.
//
// BEST-EFFORT, like n8n: bounded by meRunsJobsTimeout (≤ 3 s), run
// concurrently with the other sources, and a failure contributes no rows and
// reports its outcome in `sources.jobs` — the flag the UI shows. It never
// fails /me/runs. /me/runs/stream re-collects every 2 s, so results are
// cached per user for a few seconds and a refused connect is remembered for a
// cool-down, so a down lumid-data costs one wait per cool-down, not one per
// tick.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"lumid_identity/internal/common"
)

const (
	// lumidDataAudience — what lumid-data accepts (claude-proxy mints the same).
	lumidDataAudience = "lumid-data"
	// meRunsJobsFetchLimit — newest N jobs read per scan. Jobs older than the
	// newest N inside a window are not listed here; the Jobs tab pages them.
	meRunsJobsFetchLimit = 200
	meRunsJobsCacheTTL   = 10 * time.Second
	meRunsJobsCooldown   = 30 * time.Second
	meRunsJobsMaxTimeout = 3 * time.Second
	meRunsJobsBodyLimit  = 4 << 20
)

var lumidDataReadScopes = []string{"lumid:read"}

// lumidDataBase — the lum.id/data upstream as seen from this pod. In-cluster
// the landing nginx proxies lum.id/data/* to the same Service.
func lumidDataBase() string {
	if v := strings.TrimSpace(os.Getenv("LUMID_DATA_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://lumid-data-primary:5101"
}

// meRunsJobsTimeout bounds the jobs sub-source. ME_RUNS_JOBS_TIMEOUT_MS
// overrides; values above 3 s are clamped (the list must stay fast).
func meRunsJobsTimeout() time.Duration {
	d := 2 * time.Second
	if v, err := strconv.Atoi(os.Getenv("ME_RUNS_JOBS_TIMEOUT_MS")); err == nil && v > 0 {
		d = time.Duration(v) * time.Millisecond
	}
	if d > meRunsJobsMaxTimeout {
		d = meRunsJobsMaxTimeout
	}
	return d
}

// meRunsJobsDisabled — ME_RUNS_JOBS=off turns the source off (status "off").
func meRunsJobsDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ME_RUNS_JOBS")))
	return v == "off" || v == "0" || v == "false"
}

// jobsStudioLink — where a job row opens: Studio → Data → Jobs, that job.
func jobsStudioLink(jobID string) string {
	return "/studio/data-warehouse?tab=jobs&job=" + url.QueryEscape(jobID)
}

// entranceJob is the subset of a lumid-data job this list needs.
type entranceJob struct {
	JobID     string          `json:"job_id"`
	App       string          `json:"app"`
	Runtime   string          `json:"runtime"`
	Site      *string         `json:"site"`
	Status    string          `json:"status"`
	Spec      json.RawMessage `json:"spec"`
	Error     json.RawMessage `json:"error"`
	CreatedAt string          `json:"created_at"`
	StartedAt *string         `json:"started_at"`
	EndedAt   *string         `json:"ended_at"`
}

// ── cache + breaker ────────────────────────────────────────────────────────

type jobsCacheEntry struct {
	at   time.Time
	jobs []entranceJob
}

var meRunsJobsState = struct {
	sync.Mutex
	cache     map[string]jobsCacheEntry // user id -> last good fetch
	downUntil map[string]time.Time      // base URL -> connect cool-down end
}{cache: map[string]jobsCacheEntry{}, downUntil: map[string]time.Time{}}

func jobsCached(userID string, now time.Time) ([]entranceJob, bool) {
	meRunsJobsState.Lock()
	defer meRunsJobsState.Unlock()
	e, ok := meRunsJobsState.cache[userID]
	if !ok || now.Sub(e.at) > meRunsJobsCacheTTL {
		return nil, false
	}
	return e.jobs, true
}

func jobsStore(userID string, jobs []entranceJob, now time.Time) {
	meRunsJobsState.Lock()
	defer meRunsJobsState.Unlock()
	// Bounded: drop expired entries before adding, so a pod serving many
	// users does not keep every one of them forever.
	if len(meRunsJobsState.cache) > 1024 {
		for k, e := range meRunsJobsState.cache {
			if now.Sub(e.at) > meRunsJobsCacheTTL {
				delete(meRunsJobsState.cache, k)
			}
		}
	}
	meRunsJobsState.cache[userID] = jobsCacheEntry{at: now, jobs: jobs}
}

func jobsBaseDown(base string, now time.Time) bool {
	meRunsJobsState.Lock()
	defer meRunsJobsState.Unlock()
	return now.Before(meRunsJobsState.downUntil[base])
}

func jobsMarkDown(base string, now time.Time) {
	meRunsJobsState.Lock()
	meRunsJobsState.downUntil[base] = now.Add(meRunsJobsCooldown)
	meRunsJobsState.Unlock()
}

func jobsMarkUp(base string) {
	meRunsJobsState.Lock()
	delete(meRunsJobsState.downUntil, base)
	meRunsJobsState.Unlock()
}

// resetMeRunsJobsState clears the cache and the breaker. For tests.
func resetMeRunsJobsState() {
	meRunsJobsState.Lock()
	meRunsJobsState.cache = map[string]jobsCacheEntry{}
	meRunsJobsState.downUntil = map[string]time.Time{}
	meRunsJobsState.Unlock()
}

// ── the source ─────────────────────────────────────────────────────────────

// jobsBearerFor mints the per-call bearer. A var so tests can stub identity's
// DB + keyring away.
var jobsBearerFor = func(userID string) (string, error) {
	if common.DB == nil {
		return "", errJobsUnconfigured
	}
	email, role := userEmailRole(userID)
	tok, _, _, err := common.IssueBridgeJWT(userID, email, role, lumidDataAudience, lumidDataReadScopes, 2*time.Minute)
	if err != nil {
		return "", errJobsUnconfigured
	}
	return tok, nil
}

var errJobsUnconfigured = errors.New("jobs source not configured")

// entranceJobRuns lists the user's entrance jobs in [since, until] as run
// rows. Status: ok | off | unconfigured | unreachable | timeout |
// unauthenticated | unavailable (jobs not enabled on lumid-data) | error.
func entranceJobRuns(parent context.Context, userID string, since, until time.Time, timeout time.Duration) ([]RunRow, string) {
	if meRunsJobsDisabled() {
		return nil, "off"
	}
	now := time.Now()
	jobs, ok := jobsCached(userID, now)
	if !ok {
		var st string
		jobs, st = fetchEntranceJobs(parent, userID, timeout)
		if st != "ok" {
			return nil, st
		}
		jobsStore(userID, jobs, now)
	}
	return jobsToRunRows(jobs, since, until), "ok"
}

func fetchEntranceJobs(parent context.Context, userID string, timeout time.Duration) ([]entranceJob, string) {
	base := lumidDataBase()
	if jobsBaseDown(base, time.Now()) {
		return nil, "unreachable"
	}
	bearer, err := jobsBearerFor(userID)
	if err != nil {
		return nil, "unconfigured"
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	u := base + "/jobs/v1/jobs?limit=" + strconv.Itoa(meRunsJobsFetchLimit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "error"
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, "timeout"
		}
		var opErr *net.OpError
		var dnsErr *net.DNSError
		if errors.As(err, &opErr) && opErr.Op == "dial" || errors.As(err, &dnsErr) {
			// Only a failed CONNECT trips the breaker: a slow-but-reachable
			// lumid-data is not "down" for callers that allow longer.
			jobsMarkDown(base, time.Now())
		}
		return nil, "unreachable"
	}
	defer resp.Body.Close()
	jobsMarkUp(base)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, meRunsJobsBodyLimit))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, "unauthenticated"
	case resp.StatusCode == http.StatusNotFound:
		// LUMID_JOBS_ENABLED off: the routes are not mounted.
		return nil, "unavailable"
	case resp.StatusCode != http.StatusOK:
		return nil, "error"
	}
	var env struct {
		Jobs []entranceJob `json:"jobs"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, "error"
	}
	if env.Jobs == nil {
		env.Jobs = []entranceJob{}
	}
	return env.Jobs, "ok"
}

// jobsToRunRows maps jobs to run rows, keeping those created in [since, until].
//
// Ordered by created_at, not started_at: a job's started_at is set when it
// starts running, and a keyset cursor over a timestamp that moves would
// re-serve or skip it between pages.
func jobsToRunRows(jobs []entranceJob, since, until time.Time) []RunRow {
	out := []RunRow{}
	lo, hi := float64(since.Unix()), float64(until.Unix())
	for _, j := range jobs {
		if j.JobID == "" {
			continue
		}
		created := parseTimeToUnix(j.CreatedAt)
		if created == 0 || created < lo || created > hi {
			continue
		}
		out = append(out, jobToRunRow(j, created))
	}
	return out
}

func jobToRunRow(j entranceJob, created float64) RunRow {
	var spec struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(j.Spec, &spec)
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		name = j.App
	}
	if name == "" {
		name = "Data job"
	}
	state, reason := jobState(j)
	var dur float64
	if j.EndedAt != nil {
		start := created
		if j.StartedAt != nil {
			if s := parseTimeToUnix(*j.StartedAt); s > 0 {
				start = s
			}
		}
		if e := parseTimeToUnix(*j.EndedAt); e > start {
			dur = e - start
		}
	}
	return RunRow{
		RunID: "job:" + j.JobID,
		// No App: a job's `app` is a free label on the spec, not necessarily an
		// installed app, and an App here makes Activity link the row to
		// /studio/apps/<app>/w/<…> — a workflow page that does not exist.
		// Grouped instead as "<app>" under the app-less section, linking to the
		// Jobs tab.
		WorkflowSlug: "job:" + j.App,
		Kind:         "job",
		Name:         name,
		State:        state,
		StartedAt:    created,
		StartedISO:   j.CreatedAt,
		DurationSec:  dur,
		Reason:       reason,
		Link:         jobsStudioLink(j.JobID),
	}
}

// jobState maps the lumid-data lifecycle onto the /me/runs vocabulary.
//
//	planned, submitted → queued     (accepted, not running yet)
//	running            → running
//	succeeded          → succeeded
//	failed             → failed     (reason = the job's error message)
//	refused            → failed     (the planner/runtime would not run it)
//	cancelled          → canceled   (the spelling /me/runs already uses)
func jobState(j entranceJob) (string, string) {
	switch strings.ToLower(j.Status) {
	case "planned", "submitted":
		return "queued", ""
	case "running":
		return "running", ""
	case "succeeded":
		return "succeeded", ""
	case "cancelled", "canceled":
		return "canceled", ""
	case "refused":
		if m := jobErrorMessage(j.Error); m != "" {
			return "failed", "refused: " + m
		}
		return "failed", "refused"
	case "failed":
		return "failed", jobErrorMessage(j.Error)
	default:
		return "skipped", j.Status
	}
}

// jobErrorMessage — the error field is JSON: a string, or {message|msg|error}.
func jobErrorMessage(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return truncateReason(s)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		for _, k := range []string{"message", "msg", "error", "code"} {
			if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
				return truncateReason(v)
			}
		}
	}
	return ""
}

func truncateReason(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}
