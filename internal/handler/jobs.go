package handler

// GET /api/v1/jobs — unified jobs panel data source.
//
// The autoresearch loops in ~/.xp/apps/ can optionally submit work to
// cron / FlowMesh / Lumilake via the submit_jobs skill bundle. Every
// submission is appended to a single JSONL ledger at
// ~/.lumilake/jobs.jsonl with a stable schema. This endpoint reads that
// ledger and returns a unified view so /dashboard/jobs can render any
// source's jobs with the same shape.
//
// Lives next to /api/v1/admin/loops which reads from the same
// ~/.lumilake/scheduler dir — gives the panel one place to query for
// both scheduler state (loops) and per-job state (this).
//
// Bearer-auth gated like the rest of /api/v1/admin/*; the panel is
// observation-only (no Run/Stop/Cancel buttons), so read-only access
// for any authenticated user is fine.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// JobRow is the canonical shape for any job from any source. Matches
// the JSONL schema written by sdk/ops/jobs.py::record_submission.
type JobRow struct {
	JobID         string         `json:"job_id"`
	Source        string         `json:"source"` // cron|flowmesh|lumilake|loop_cycle
	Kind          string         `json:"kind"`
	SubmitterApp  string         `json:"submitter_app"`
	SubmitterLoop string         `json:"submitter_loop"`
	State         string         `json:"state"` // queued|running|succeeded|failed|cancelled|scheduled
	StartedAt     float64        `json:"started_at"`
	FinishedAt    *float64       `json:"finished_at,omitempty"`
	SpecSummary   string         `json:"spec_summary"`
	Spec          map[string]any `json:"spec,omitempty"`
	OutputURL     string         `json:"output_url,omitempty"`
	Output        any            `json:"output,omitempty"`
	Error         string         `json:"error,omitempty"`
	UpdatedAt     float64        `json:"updated_at"`
}

// JobsSummary — top-line counts the panel renders above the table.
type JobsSummary struct {
	Running       int `json:"running"`
	Queued        int `json:"queued"`
	Succeeded24h  int `json:"succeeded_24h"`
	Failed24h     int `json:"failed_24h"`
	TotalInLedger int `json:"total_in_ledger"`
}

// JobsResponse — the full payload returned by GET /api/v1/jobs.
type JobsResponse struct {
	Jobs    []JobRow    `json:"jobs"`
	Summary JobsSummary `json:"summary"`
}

const _maxJobsReturned = 500

// ledgerPath returns the host-side path. The identity container mounts
// /home/webmaster RO; the ledger lives at ~/.lumilake/jobs.jsonl on the
// host (writable by the scheduler container; read-only here).
func ledgerPath() string {
	if p := os.Getenv("LUMID_JOBS_LEDGER"); p != "" {
		return p
	}
	home := operatorHome() // shared helper from admin_loops.go
	return filepath.Join(home, ".lumilake", "jobs.jsonl")
}

// readLedger loads the JSONL file and returns the rows in newest-first
// order. Missing/empty file → empty slice; malformed lines are skipped
// silently (operator can hand-fix the ledger if needed).
func readLedger() []JobRow {
	path := ledgerPath()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var rows []JobRow
	scanner := bufio.NewScanner(f)
	// Allow up to 256 KB per line — `spec` payloads are truncated to 4 KB
	// by sdk/ops/jobs.py, but err on the side of generous to avoid
	// silent record loss.
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row JobRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue // skip malformed
		}
		rows = append(rows, row)
	}

	// Newest first — sort by updated_at desc, fallback started_at.
	sort.SliceStable(rows, func(i, j int) bool {
		a := rows[i].UpdatedAt
		if a == 0 {
			a = rows[i].StartedAt
		}
		b := rows[j].UpdatedAt
		if b == 0 {
			b = rows[j].StartedAt
		}
		return a > b
	})
	return rows
}

// computeSummary tallies the stat strip's counts from the full ledger.
func computeSummary(rows []JobRow) JobsSummary {
	cutoff24h := float64(time.Now().Unix() - 86400)
	s := JobsSummary{TotalInLedger: len(rows)}
	for _, r := range rows {
		switch r.State {
		case "running":
			s.Running++
		case "queued", "scheduled":
			s.Queued++
		case "succeeded":
			if r.FinishedAt != nil && *r.FinishedAt >= cutoff24h {
				s.Succeeded24h++
			}
		case "failed":
			if r.FinishedAt != nil && *r.FinishedAt >= cutoff24h {
				s.Failed24h++
			}
		}
	}
	return s
}

// applyFilters lets the panel narrow to a single app/loop/source/state.
// All query params are optional and combine with AND semantics.
func applyFilters(rows []JobRow, c *gin.Context) []JobRow {
	app := c.Query("submitter_app")
	loop := c.Query("submitter_loop")
	source := c.Query("source")
	state := c.Query("state")
	if app == "" && loop == "" && source == "" && state == "" {
		return rows
	}
	out := make([]JobRow, 0, len(rows))
	for _, r := range rows {
		if app != "" && r.SubmitterApp != app {
			continue
		}
		if loop != "" && r.SubmitterLoop != loop {
			continue
		}
		if source != "" && r.Source != source {
			continue
		}
		if state != "" && r.State != state {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Jobs returns the unified panel payload. Reads the whole ledger (cheap
// — bounded growth, JSONL parse is fast), filters by query params,
// truncates to _maxJobsReturned newest, computes summary across the
// unfiltered set so the stat strip stays stable across filter changes.
//
// Routes through router.go's `admin` group (Bearer auth required). The
// panel is observation-only — read-only is fine for any authenticated
// user (loop authors want to see their own jobs; debugging a misbehaving
// app needs visibility into other apps too).
func Jobs(c *gin.Context) {
	all := readLedger()
	summary := computeSummary(all)

	filtered := applyFilters(all, c)
	if len(filtered) > _maxJobsReturned {
		filtered = filtered[:_maxJobsReturned]
	}
	c.JSON(http.StatusOK, JobsResponse{
		Jobs:    filtered,
		Summary: summary,
	})
}
