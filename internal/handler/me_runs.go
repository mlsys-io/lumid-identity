// /me/runs — unified run history across runtimes.
//
// Aggregates two sources behind one shape so /studio/runs renders a
// single table:
//   1. Scheduled cycles — journal.jsonl entries from the user's tenant
//      tree + operator-shared apps.
//   2. Visual executions — n8n /rest/executions (W1 best-effort).
//
// Filters: state (running|succeeded|failed|paused), workflow slug,
// time range (last 24h default; ?since=ISO + ?until=ISO override).
// Cursor pagination via opaque base64 (ts:source:row_id).

package handler

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// RunRow is the unified per-run record.
type RunRow struct {
	RunID        string  `json:"run_id"`
	WorkflowSlug string  `json:"workflow_slug"`
	Kind         string  `json:"kind"`  // "scheduled" | "visual"
	Name         string  `json:"name"`  // workflow display name
	App          string  `json:"app,omitempty"`
	State        string  `json:"state"` // "succeeded" | "failed" | "running" | "skipped" | "canceled"
	StartedAt    float64 `json:"started_at"`
	StartedISO   string  `json:"started_iso,omitempty"`
	DurationSec  float64 `json:"duration_s,omitempty"`
	Reason       string  `json:"reason,omitempty"`
	CostCents    float64 `json:"cost_cents,omitempty"` // W4 fills this in
	// The artifact dir + step log path for the drill-down view. Empty
	// for visual (n8n keeps its own state).
	CycleDir string `json:"cycle_dir,omitempty"`
}

// MeRuns — GET /me/runs[?state=&workflow=&since=&until=&limit=&cursor=]
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

	rows := collectRuns(c, userID, since, until)

	// Apply filters.
	filtered := make([]RunRow, 0, len(rows))
	for _, r := range rows {
		if stateFilter != "" && !stateMatches(r.State, stateFilter) {
			continue
		}
		if workflowFilter != "" && r.WorkflowSlug != workflowFilter {
			continue
		}
		filtered = append(filtered, r)
	}

	// Sort newest first.
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].StartedAt > filtered[j].StartedAt
	})

	// Simple cursor: byte offset into the filtered slice, base64'd.
	cursor := c.Query("cursor")
	startIdx := 0
	if cursor != "" {
		if b, err := base64.URLEncoding.DecodeString(cursor); err == nil {
			if v, err := strconv.Atoi(string(b)); err == nil && v >= 0 {
				startIdx = v
			}
		}
	}
	endIdx := startIdx + limit
	if endIdx > len(filtered) {
		endIdx = len(filtered)
	}
	page := filtered[startIdx:endIdx]
	nextCursor := ""
	if endIdx < len(filtered) {
		nextCursor = base64.URLEncoding.EncodeToString([]byte(strconv.Itoa(endIdx)))
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"runs":        page,
			"count":       len(page),
			"total":       len(filtered),
			"next_cursor": nextCursor,
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

	// Resolve the cycle dir (best-effort) so we can journal next to it.
	cycleDir, _ := resolveCycleDir(userID, app, loop, ts)
	journalPath := filepath.Join(tenantAppsDir(userID), app, "data", "journal.jsonl")
	if _, err := os.Stat(filepath.Dir(journalPath)); err != nil {
		// Try operator-shared.
		journalPath = filepath.Join(operatorHome(), ".xp", "apps", app, "data", "journal.jsonl")
		if _, err := os.Stat(filepath.Dir(journalPath)); err != nil {
			fail(c, http.StatusNotFound, 1404, "app not installed")
			return
		}
	}

	entry := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339),
		"loop":      loop,
		"ok":        body.State == "succeeded",
		"manual_mark": true,
		"original_run_ts": ts,
		"marked_by": userID,
	}
	if cycleDir != "" {
		entry["cycle_dir"] = cycleDir
	}
	if body.Note != "" {
		entry["note"] = body.Note
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
			"run_id":   runID,
			"new_state": body.State,
			"note":     "Manual override recorded. Next scheduler refresh picks it up.",
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
				"run_id":      runID,
				"kind":        "visual",
				"execution":   exec,
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
	if cycleDir == "" {
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
	out := []RunRow{}

	// 1. Scheduled — walk every app's journal.jsonl.
	scan := func(appsRoot string) {
		entries, _ := os.ReadDir(appsRoot)
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			journal := filepath.Join(appsRoot, e.Name(), "data", "journal.jsonl")
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

	// 2. Visual — n8n executions. Soft-fail on auth.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()
	cli := common.NewN8nClient()
	cookie, _ := c.Cookie("n8n-auth")
	execs, err := cli.ListExecutions(ctx, "", "", cookie)
	if err == nil {
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
	}
	return out
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
	state := "succeeded"
	if skipped, _ := r["skipped"].(bool); skipped {
		state = "skipped"
	} else if ok, _ := r["ok"].(bool); !ok {
		state = "failed"
	}
	reason, _ := r["reason"].(string)
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
