package handler

// Planned-runs management — the counterpart to "Plan next run" (MeLoopRunNow).
// MeLoopRunNow appends a queued one-shot to ~/.lumilake/jobs.jsonl that the
// scheduler's drain_oneshots fires (immediately, or at payload.not_before for a
// "schedule once"). Until it fires there was no way to SEE or CANCEL it. These
// two endpoints close that gap:
//
//   GET  /me/loops/:app/:loop/planned          → list this caller's queued rows
//   POST /me/loops/:app/:loop/planned/cancel    → mark one cancelled ({job_id})
//
// Cancel = rewrite the row's state to "cancelled". drain_oneshots only fires
// rows whose state == "queued", so a cancelled row is skipped (no scheduler
// change needed). The rewrite is atomic (temp + rename) to avoid tearing the
// ledger the scheduler reads.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// readJobRows returns every parseable row of the jobs.jsonl ledger, in order.
func readJobRows() ([]map[string]any, error) {
	f, err := os.Open(jobsLedgerPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no ledger yet → nothing planned
		}
		return nil, err
	}
	defer f.Close()
	var rows []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // payloads can be large
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var row map[string]any
		if json.Unmarshal(line, &row) == nil {
			rows = append(rows, row)
		}
	}
	return rows, sc.Err()
}

// plannedRow projects a queued ledger row into the slim shape the UI lists.
func plannedRow(row map[string]any) gin.H {
	payload, _ := row["payload"].(map[string]any)
	if payload == nil {
		payload = map[string]any{}
	}
	return gin.H{
		"job_id":       row["job_id"],
		"loop":         row["submitter_loop"],
		"submitted_at": row["submitted_at"],
		"branch_label": payload["branch_label"],
		"from_run_ts":  payload["from_run_ts"],
		"not_before":   payload["not_before"], // set → "scheduled once" (deferred)
		"criteria":     payload["criteria"],
		"cases":        payload["cases"],
		"auto_promote": payload["auto_promote"],
		"variant":      payload["variant"],
	}
}

// GET /api/v1/me/loops/:app/:loop/planned
// Lists the caller's still-queued one-shots for this app (and loop, when the
// :loop segment is a real loop — pass "_" to list across all loops of the app).
func MePlannedRuns(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	rows, err := readJobRows()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read jobs.jsonl: "+err.Error())
		return
	}
	planned := []gin.H{}
	for _, row := range rows {
		if asString(row["source"]) != "loop_cycle" || asString(row["state"]) != "queued" {
			continue
		}
		if asString(row["submitter_app"]) != app {
			continue
		}
		// per-caller isolation: only your own queued runs.
		if asString(row["submitted_by"]) != userID {
			continue
		}
		if loop != "" && loop != "_" && asString(row["submitter_loop"]) != loop {
			continue
		}
		planned = append(planned, plannedRow(row))
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "loop": loop, "planned": planned, "count": len(planned)}})
}

type cancelPlannedBody struct {
	JobID string `json:"job_id"`
}

// POST /api/v1/me/loops/:app/:loop/planned/cancel  {job_id}
// Marks the caller's queued row cancelled (atomic rewrite). Idempotent: a row
// that's already non-queued (fired/cancelled) returns ok with cancelled=false.
func MeCancelPlanned(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	var body cancelPlannedBody
	if err := c.ShouldBindJSON(&body); err != nil || body.JobID == "" {
		fail(c, http.StatusBadRequest, 1400, "job_id required")
		return
	}
	rows, err := readJobRows()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read jobs.jsonl: "+err.Error())
		return
	}
	cancelled := false
	for _, row := range rows {
		if asString(row["job_id"]) != body.JobID {
			continue
		}
		// authz: only cancel your own row for this app.
		if asString(row["submitter_app"]) != app || asString(row["submitted_by"]) != userID {
			fail(c, http.StatusForbidden, 1003, "not your planned run")
			return
		}
		if asString(row["state"]) == "queued" {
			row["state"] = "cancelled"
			row["cancelled_by"] = userID
			cancelled = true
		}
		break
	}
	if cancelled {
		if err := rewriteJobLedger(rows); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "rewrite jobs.jsonl: "+err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
		"data": gin.H{"job_id": body.JobID, "cancelled": cancelled}})
}

// rewriteJobLedger atomically replaces jobs.jsonl with the given rows
// (temp file in the same dir + rename) so the scheduler never reads a torn file.
func rewriteJobLedger(rows []map[string]any) error {
	dir := filepath.Dir(jobsLedgerPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".jobs-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	w := bufio.NewWriter(tmp)
	for _, row := range rows {
		b, err := json.Marshal(row)
		if err != nil {
			tmp.Close()
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, jobsLedgerPath())
}
