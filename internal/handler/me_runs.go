// /me/runs — unified run history across runtimes.
//
// Aggregates two sources behind one shape so /studio/runs renders a
// single table:
//   1. Scheduled cycles — journal.jsonl entries from the user's tenant
//      tree + operator-shared apps.
//   2. Visual executions — n8n /rest/executions (W1 best-effort).
//   3. Entrance jobs — lum.id/data /jobs/v1/jobs, as the user (best-effort;
//      me_runs_jobs.go). `sources.jobs` says whether they could be read.
//
// Filters: state (running|succeeded|failed|paused), workflow slug,
// time range (last 24h default; ?since=ISO + ?until=ISO override).
// Keyset cursor pagination over (started_at, run_id) — see me_runs_page.go.

package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// RunRow is the unified per-run record.
type RunRow struct {
	RunID        string  `json:"run_id"`
	WorkflowSlug string  `json:"workflow_slug"`
	Kind         string  `json:"kind"` // "scheduled" | "visual" | "job"
	Name         string  `json:"name"` // workflow display name
	App          string  `json:"app,omitempty"`
	State        string  `json:"state"` // "succeeded" | "failed" | "running" | "skipped" | "canceled" | "queued" (jobs)
	StartedAt    float64 `json:"started_at"`
	StartedISO   string  `json:"started_iso,omitempty"`
	DurationSec  float64 `json:"duration_s,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	CostCents    float64 `json:"cost_cents,omitempty"` // W4 fills this in
	// The artifact dir + step log path for the drill-down view. Empty
	// for visual (n8n keeps its own state).
	CycleDir string `json:"cycle_dir,omitempty"`
	// Link — where the row opens in Studio, when that is not derivable from
	// run_id. Set for entrance jobs (Studio → Data → Jobs).
	Link string `json:"link,omitempty"`
}

// MeRuns — GET /me/runs[?state=&workflow=&since=&until=&limit=&cursor=&before=]
//
// Pagination (see me_runs_page.go): rows are ordered newest first by
// (started_at DESC, run_id DESC). `next_cursor` is an opaque KEYSET token for
// the row after the last one returned; pass it back as `cursor=` or `before=`.
// `before=` also takes a bare started_at (unix seconds or RFC3339) meaning
// "strictly older than this". Legacy integer-offset cursors are still honoured.
func MeRuns(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	stateFilter := strings.TrimSpace(c.Query("state"))
	workflowFilter := strings.TrimSpace(c.Query("workflow"))
	since := parseISOorDefault(c.Query("since"), time.Now().UTC().Add(-24*time.Hour))
	until := parseISOorDefault(c.Query("until"), time.Now().UTC().Add(time.Minute))
	limit := atoiClamp(c.Query("limit"), 50, 1, 500)

	page, err := parseRunsPageParams(c.Query("cursor"), c.Query("before"))
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	until = keysetScanUntil(page.keyset, until)

	col := collectRunsFrom(c, userID, since, until)
	c.Header("Server-Timing", col.serverTiming())

	filtered := filterRuns(col.rows, stateFilter, workflowFilter)
	sortRunsNewestFirst(filtered)

	var (
		out        []RunRow
		total      int
		nextCursor string
	)
	if page.offset >= 0 {
		out, total, nextCursor = pageByOffset(filtered, page.offset, limit, col.storeCapped, col.storeOldest)
	} else {
		out, total, nextCursor = pageByKeyset(filtered, page.keyset, limit, col.storeCapped, col.storeOldest)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"runs":        out,
			"count":       len(out),
			"total":       total,
			"next_cursor": nextCursor,
			"has_more":    nextCursor != "",
			"sources":     col.status,
			"as_of":       time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// MeRunMark — POST /me/runs/:run_id/mark
//
// Manual state override for a scheduled run (Airflow's "mark
// succeeded" / "mark failed" idiom). Writes a synthetic journal.jsonl
// entry the scheduler honors when computing the per-loop state.
//
// Body: {state: "succeeded" | "failed", note?: string}
//
// Visual (n8n) runs aren't supported here — n8n has its own state
// model + execution-stop endpoint; if a future feature needs it,
// route through the n8n client.
func MeRunMark(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	runID := c.Param("run_id")
	parts := strings.SplitN(runID, ":", 4)
	if len(parts) < 4 || parts[0] != "scheduled" {
		fail(c, http.StatusBadRequest, 1400, "mark only supported on scheduled runs (id 'scheduled:<app>:<loop>:<ts>')")
		return
	}
	app, loop, ts := parts[1], parts[2], parts[3]

	var body struct {
		State string `json:"state"`
		Note  string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	if body.State != "succeeded" && body.State != "failed" {
		fail(c, http.StatusBadRequest, 1400, "state must be 'succeeded' or 'failed'")
		return
	}

	// The id is caller-supplied and flows into paths: single safe segments only.
	if !validAppSlug(app) || !safeSeg(loop) || !safeSeg(ts) {
		fail(c, http.StatusBadRequest, 1400, "invalid run id")
		return
	}

	// Owner write. This used to fall back to the OPERATOR-SHARED bundle and
	// append a manual override to a journal every other tenant reads; now only
	// the caller's own install is marked (shared → 403, absent → 404).
	appDir, direct, viaIntent, shared := ownerWriteTarget(userID, app)
	if !direct && !viaIntent {
		ownerWriteFail(c, shared)
		return
	}

	entry := map[string]any{
		"ts":              time.Now().UTC().Format(time.RFC3339),
		"loop":            loop,
		"ok":              body.State == "succeeded",
		"manual_mark":     true,
		"original_run_ts": ts,
		"marked_by":       userID,
	}
	if body.Note != "" {
		entry["note"] = body.Note
	}

	// identity mounts no tenant volume; the scheduler can see the disk. The
	// journal row is appended there (cycle_dir is omitted: it is a path on a
	// disk identity cannot resolve).
	if viaIntent {
		id, err := queueAppFileOps(userID, app, func() ([]map[string]any, error) {
			op, err := appendOp(journalRel, entry)
			return []map[string]any{op}, err
		})
		if err != nil {
			appFileOpsStatus(c, err)
			return
		}
		respondQueued(c, id, gin.H{
			"run_id": runID, "new_state": body.State,
			"note": "Manual override queued for the scheduler. Next scheduler refresh after it applies picks it up.",
		})
		return
	}

	// Resolve the cycle dir (best-effort) so we can journal next to it.
	if cycleDir, _ := resolveCycleDir(userID, app, loop, ts); cycleDir != "" {
		entry["cycle_dir"] = cycleDir
	}
	// Write the synthetic journal entry to the canonical .lumid/journal.jsonl.
	journalPath, err := ResolveRuntimeWritePath(appDir, "data/journal.jsonl")
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "resolve journal: "+err.Error())
		return
	}
	row, _ := json.Marshal(entry)
	f, err := os.OpenFile(journalPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "open journal: "+err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(row, '\n')); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write journal: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"run_id":    runID,
			"new_state": body.State,
			"note":      "Manual override recorded. Next scheduler refresh picks it up.",
		},
	})
}

// MeRunDetail — GET /me/runs/:run_id
//
// Run IDs are opaque to the caller; we encode them as
// "<kind>:<workflow_slug>:<ts>" so the handler can route to the right
// data source. The /me/runs response above already exposes RunIDs in
// that format.
func MeRunDetail(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	runID := c.Param("run_id")
	// Run id shape:
	//   visual    → "visual:n8n:<exec_id>"        (SplitN with 3)
	//   scheduled → "scheduled:<app>:<loop>:<ts>" (SplitN with 4)
	parts := strings.SplitN(runID, ":", 4)
	if len(parts) < 3 {
		fail(c, http.StatusBadRequest, 1400, "invalid run id")
		return
	}
	kind := parts[0]
	if kind == "visual" {
		if len(parts) < 3 {
			fail(c, http.StatusBadRequest, 1400, "invalid run id")
			return
		}
		// Visual runs live in n8n; delegate to the n8n client.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		cli := common.NewN8nClient()
		cookie, _ := c.Cookie("n8n-auth")
		exec, err := cli.GetExecution(ctx, parts[2], cookie)
		if err != nil {
			fail(c, http.StatusBadGateway, 1500, "n8n: "+err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"run_id":    runID,
				"kind":      "visual",
				"execution": exec,
			},
		})
		return
	}

	// scheduled: parts = ["scheduled", "<app>", "<loop>", "<ts>"] (4 segments)
	if len(parts) < 4 {
		fail(c, http.StatusBadRequest, 1400, "invalid scheduled run id (expected scheduled:<app>:<loop>:<ts>)")
		return
	}
	app, loop, ts := parts[1], parts[2], parts[3]

	cycleDir, _ := resolveCycleDir(userID, app, loop, ts)
	if cycleDir == "" && safeSeg(loop) && safeSeg(ts) {
		// The caller's own install lives on the scheduler's volume: have the
		// scheduler read the cycle dir (me_cycle_read_intent.go).
		if _, direct, viaIntent, _ := ownerWriteTarget(userID, app); !direct && viaIntent {
			res, err := cycleFilesViaScheduler(ginReqCtx(c), userID, app, loop, ts, false)
			switch {
			case err == nil:
				summary := parseJSONBytes(res.files["summary.json"])
				stepErrors := parseJSONBytes(res.files["step_errors.json"])
				steps := parseJSONBytes(res.files["step_log.json"])
				if steps == nil {
					steps = []any{}
				}
				c.JSON(http.StatusOK, gin.H{
					"ret_code": 0, "message": "ok",
					"data": gin.H{
						"run_id": runID, "kind": "scheduled", "app": app, "loop": loop, "ts": ts,
						"steps": steps, "summary": summary, "step_errors": stepErrors,
						"source": "scheduler", "cycle_dir_ts": res.resolvedTs,
					},
				})
				return
			case errors.Is(err, errCycleNotOnScheduler):
				fail(c, http.StatusNotFound, 1404, "cycle not found")
				return
			default:
				c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
					"run_id": runID, "kind": "scheduled", "app": app, "loop": loop, "ts": ts,
					"steps":       []any{},
					"unavailable": "per-run step detail could not be read from the scheduler: " + err.Error(),
				}})
				return
			}
		}
	}
	if cycleDir == "" {
		// "cycle not found" is true and useless: resolveCycleDir scans a disk
		// this pod does not mount, so it finds nothing for every run that has
		// ever happened. The run LIST is rebuilt from the run store; the
		// per-step detail behind it is not reconstructible, and saying which is
		// which is the difference between a missing run and an unmountable
		// volume.
		if why := unavailableReason(resolveAppDir(userID, app), "per-run step detail"); why != "" {
			c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
				"run_id": runID, "kind": "scheduled", "app": app, "loop": loop, "ts": ts,
				"steps": []any{}, "unavailable": why,
			}})
			return
		}
		fail(c, http.StatusNotFound, 1404, "cycle not found")
		return
	}

	steps := readStepLog(filepath.Join(cycleDir, "step_log.json"))
	summary := readJSONFile(filepath.Join(cycleDir, "summary.json"))
	stepErrors := readJSONFile(filepath.Join(cycleDir, "step_errors.json"))

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"run_id":      runID,
			"kind":        "scheduled",
			"app":         app,
			"loop":        loop,
			"ts":          ts,
			"cycle_dir":   cycleDir,
			"steps":       steps,
			"summary":     summary,
			"step_errors": stepErrors,
		},
	})
}

func collectRuns(c *gin.Context, userID string, since, until time.Time) []RunRow {
	return collectRunsFrom(c, userID, since, until).rows
}

// meRunsN8nTimeout bounds the n8n sub-source. It was a fixed 6 s, run AFTER the
// other sources, and n8n is not deployed on UKS — so every /me/runs paid the
// full 6 s (measured 6.14–6.33 s in production for 0, 76 and 0 rows; a cheap
// endpoint on the same path answers in 0.39 s). The breaker in common/n8n_client
// makes the wait once per cool-down; this bound makes that once short.
// Override with ME_RUNS_N8N_TIMEOUT_MS.
func meRunsN8nTimeout() time.Duration {
	if v, err := strconv.Atoi(os.Getenv("ME_RUNS_N8N_TIMEOUT_MS")); err == nil && v > 0 {
		return time.Duration(v) * time.Millisecond
	}
	return 1500 * time.Millisecond
}

// runsCollection is what collectRunsFrom gathered, plus how.
type runsCollection struct {
	rows []RunRow
	// storeCapped: the run store returned runStoreScanCap rows, so older rows
	// may exist below storeOldest that this scan did not read.
	storeCapped bool
	storeOldest float64
	// per-source outcome ("ok" | "timeout" | "unreachable" | "error" |
	// "unauthenticated") and wall time.
	status  map[string]string
	timings map[string]time.Duration
}

func (rc runsCollection) serverTiming() string {
	parts := make([]string, 0, len(rc.timings))
	for _, k := range []string{"journal", "store", "n8n", "jobs"} {
		if d, ok := rc.timings[k]; ok {
			parts = append(parts, fmt.Sprintf("%s;dur=%.1f;desc=%q", k, float64(d.Microseconds())/1000, rc.status[k]))
		}
	}
	return strings.Join(parts, ", ")
}

// collectRunsFrom gathers the sources (journal, run store, n8n, entrance
// jobs) CONCURRENTLY. They used to run one after another with the remote one
// last, so the response time was the sum
// — and n8n's fixed 6 s deadline dominated it. Now it is the slowest source,
// and the remote one is bounded (meRunsN8nTimeout) and short-circuited while
// known unreachable. A source that fails or times out contributes no rows and
// reports its outcome in `status`; it never fails the request.
func collectRunsFrom(c *gin.Context, userID string, since, until time.Time) runsCollection {
	rc := runsCollection{status: map[string]string{}, timings: map[string]time.Duration{}}
	var mu sync.Mutex
	record := func(name, status string, d time.Duration) {
		mu.Lock()
		rc.status[name], rc.timings[name] = status, d
		mu.Unlock()
	}
	// Read everything off the gin.Context BEFORE fanning out: it is not safe
	// for concurrent use.
	reqCtx := c.Request.Context()
	cookie, _ := c.Cookie("n8n-auth")

	var journal, store, visual, jobs []RunRow
	var wg sync.WaitGroup
	wg.Add(4)

	// 1. Scheduled — walk every app's journal.jsonl.
	go func() {
		defer wg.Done()
		t0 := time.Now()
		journal = journalRuns(userID, since, until)
		record("journal", "ok", time.Since(t0))
	}()

	// 1b. The RUN STORE. On a cloud pod neither path above exists — identity
	// mounts no tenant volume — so the only source this function had was the
	// n8n API below, and the endpoint could return VISUAL runs and nothing
	// else. Merged, not substituted: an operator install on the scheduler's own
	// volume is readable here and its journal carries a cycle_dir the store
	// does not.
	go func() {
		defer wg.Done()
		t0 := time.Now()
		var capped bool
		var oldest float64
		store, capped, oldest = runRowsFromDBScan(userID, since, until)
		mu.Lock()
		rc.storeCapped, rc.storeOldest = capped, oldest
		mu.Unlock()
		record("store", "ok", time.Since(t0))
	}()

	// 2. Visual — n8n executions. Soft-fail on auth, timeout and unreachable.
	go func() {
		defer wg.Done()
		t0 := time.Now()
		var st string
		visual, st = n8nRuns(reqCtx, cookie, since, until, meRunsN8nTimeout())
		record("n8n", st, time.Since(t0))
	}()

	// 3. Entrance jobs — lum.id/data, as the user. Bounded, best-effort.
	go func() {
		defer wg.Done()
		t0 := time.Now()
		var st string
		jobs, st = entranceJobRuns(reqCtx, userID, since, until, meRunsJobsTimeout())
		record("jobs", st, time.Since(t0))
	}()

	wg.Wait()
	rc.rows = append(append(mergeRunRows(journal, store), visual...), jobs...)
	return rc
}

// journalRuns reads the tenant tree and the operator-shared apps.
func journalRuns(userID string, since, until time.Time) []RunRow {
	out := []RunRow{}
	scan := func(appsRoot string) {
		entries, _ := os.ReadDir(appsRoot)
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			journal, _ := ResolveRuntimeReadPath(filepath.Join(appsRoot, e.Name()), "data/journal.jsonl")
			rows := readJournalInRange(journal, since, until)
			for _, r := range rows {
				row := journalRowToRun(e.Name(), r)
				if row.RunID != "" {
					out = append(out, row)
				}
			}
		}
	}
	scan(tenantAppsDir(userID))
	scan(filepath.Join(operatorHome(), ".xp", "apps"))
	return out
}

// n8nRuns lists n8n executions in [since, until] with a hard deadline.
func n8nRuns(parent context.Context, cookie string, since, until time.Time, timeout time.Duration) ([]RunRow, string) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	execs, err := common.NewN8nClient().ListExecutions(ctx, "", "", cookie)
	switch {
	case err == nil:
	case errors.Is(err, common.ErrN8nUnreachable):
		return nil, "unreachable"
	case errors.Is(err, common.ErrUnauthenticated):
		return nil, "unauthenticated"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, "timeout"
	default:
		return nil, "error"
	}
	out := []RunRow{}
	for _, ex := range execs {
		started := parseTimeToUnix(ex.StartedAt)
		if started < float64(since.Unix()) || started > float64(until.Unix()) {
			continue
		}
		out = append(out, RunRow{
			RunID:        "visual:n8n:" + ex.ID,
			WorkflowSlug: "n8n:" + ex.WorkflowID,
			Kind:         "visual",
			Name:         "",
			State:        n8nStateToOurs(ex.Status, ex.Finished),
			StartedAt:    started,
			StartedISO:   ex.StartedAt,
			DurationSec:  computeDuration(ex.StartedAt, ex.StoppedAt),
		})
	}
	return out, "ok"
}

// journalRowToRun converts a single cycle row from journal.jsonl into
// our unified RunRow. Returns the zero value if the row isn't a cycle
// outcome (the journal also carries quota events, intent acks, etc.).
func journalRowToRun(app string, r map[string]any) RunRow {
	loop, _ := r["loop"].(string)
	if loop == "" {
		return RunRow{}
	}
	// Build a compact ts string that doubles as the cycle-dir name
	// (the runtime writes data/cycles/<loop>/20060102T150405Z/).
	startedUnix := rowUnixTs(r)
	if startedUnix == 0 {
		return RunRow{}
	}
	tsStr := time.Unix(int64(startedUnix), 0).UTC().Format("20060102T150405Z")
	// Prefer the authoritative cycle-dir name the runtime stamped on the row
	// (the journal clock and the dir name can differ by seconds, which made
	// the derived run_id un-resolvable — the "cycle not found" drill failures).
	// `cycle_dir` is sometimes a bare name ("2026…Z") and sometimes a full
	// absolute path — take the basename so the run_id carries just the ts.
	if cd, ok := r["cycle_dir"].(string); ok && cd != "" {
		tsStr = filepath.Base(cd)
	}
	state := "succeeded"
	if skipped, _ := r["skipped"].(bool); skipped {
		state = "skipped"
	} else if ok, _ := r["ok"].(bool); !ok {
		state = "failed"
	}
	reason, _ := r["reason"].(string)
	// THE JOURNAL ROW KNOWS WHY, and this only ever read a top-level `reason`
	// that the runtime does not write. A cycle records its failure as `outcome`
	// plus `metrics.error` (or metrics.command_engine.error for a Pattern-B
	// engine), so every failed run arrived here saying "failed" and nothing
	// more — which is where the reader already was.
	//
	// Measured 2026-09-16: four runs dead on
	// "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']" — a platform bug,
	// written plainly to the journal and invisible on every surface. The user
	// reported it as "won't run".
	if reason == "" && state == "failed" {
		// THE ROW'S OWN `error` FIRST. app_runner writes the derived failure
		// reason straight onto the journal record (`_jrec["error"]`) for both
		// the command and compute engines, and nothing here ever read it — so
		// the one field that always holds the answer was skipped in favour of
		// digging through `metrics`. Measured 2026-09-21: a compute run refused
		// by Lumilake reached this surface as reason "ran".
		if s, _ := r["error"].(string); s != "" {
			reason = s
		} else {
			metrics, _ := r["metrics"].(map[string]any)
			outcome, _ := r["outcome"].(string)
			reason = runFailureReason(metrics, outcome)
		}
	}
	var duration float64
	if v, ok := r["duration_s"].(float64); ok {
		duration = v
	}
	return RunRow{
		RunID:        "scheduled:" + app + ":" + loop + ":" + tsStr,
		WorkflowSlug: app + ":" + loop,
		Kind:         "scheduled",
		Name:         loop,
		App:          app,
		State:        state,
		StartedAt:    startedUnix,
		StartedISO:   tsStr,
		DurationSec:  duration,
		Reason:       reason,
	}
}

// rowUnixTs returns the row's timestamp as unix seconds. Tolerates
// both shapes the runtime emits:
//   - "ts" as a JSON number (float seconds since epoch) — older entries
//   - "ts" as an ISO 8601 string with fractional seconds (current)
//   - "iso" fallback as an ISO string
//
// Returns 0 when no parseable timestamp is present.
func rowUnixTs(row map[string]any) float64 {
	if v, ok := row["ts"].(float64); ok && v != 0 {
		return v
	}
	if s, ok := row["ts"].(string); ok && s != "" {
		return parseTimeToUnix(s)
	}
	if s, ok := row["iso"].(string); ok && s != "" {
		return parseTimeToUnix(s)
	}
	return 0
}

// readJournalInRange walks data/journal.jsonl and returns rows whose
// ts falls within [since, until]. Soft-fails on missing/malformed file.
func readJournalInRange(path string, since, until time.Time) []map[string]any {
	out := []map[string]any{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	sinceU := float64(since.Unix())
	untilU := float64(until.Unix())
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		ts := rowUnixTs(row)
		if ts < sinceU || ts > untilU {
			continue
		}
		out = append(out, row)
	}
	return out
}

// resolveCycleDir is provided by me_cycles.go.

func readStepLog(path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		return []any{}
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return []any{}
	}
	return v
}

// parseJSONBytes decodes b, or nil when it is absent or not JSON — the byte
// twin of readJSONFile, for files the scheduler read for us.
func parseJSONBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return v
}

func readJSONFile(path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil
	}
	return v
}

func parseTimeToUnix(s string) float64 {
	if s == "" {
		return 0
	}
	// Try a few common shapes; the journal mixes ISO + compact-ts
	// strings, and Python's datetime.isoformat() emits fractional
	// seconds with arbitrary precision (e.g. "2026-05-25T06:00:00.171437Z").
	for _, layout := range []string{
		time.RFC3339Nano, // "2006-01-02T15:04:05.999999999Z07:00" — accepts fractional seconds
		time.RFC3339,
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
		"20060102T150405Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return float64(t.Unix())
		}
	}
	return 0
}

func parseISOorDefault(s string, fallback time.Time) time.Time {
	if s == "" {
		return fallback
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return fallback
}

func atoiClamp(s string, def, lo, hi int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}

func stateMatches(state, filter string) bool {
	// Allow comma-separated multi-filter ("succeeded,failed").
	for _, want := range strings.Split(filter, ",") {
		if strings.TrimSpace(want) == state {
			return true
		}
	}
	return false
}

func n8nStateToOurs(status string, finished bool) string {
	switch status {
	case "success":
		return "succeeded"
	case "error", "failed":
		return "failed"
	case "canceled", "cancelled":
		return "canceled"
	case "running":
		return "running"
	case "waiting":
		return "running"
	default:
		if finished {
			return "succeeded"
		}
		return "running"
	}
}

func computeDuration(startedAt, stoppedAt string) float64 {
	if startedAt == "" || stoppedAt == "" {
		return 0
	}
	s := parseTimeToUnix(startedAt)
	e := parseTimeToUnix(stoppedAt)
	if s == 0 || e == 0 || e < s {
		return 0
	}
	return e - s
}

var _ = fmt.Sprintf // keep fmt referenced if future helpers use it
