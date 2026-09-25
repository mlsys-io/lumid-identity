package handler

import (
	"encoding/json"
	"strings"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// runResultMaxBytes caps the command output handed back to the model. A
// backtest submit's output is well under this; a pathological command must not
// flood the context.
const runResultMaxBytes = 6 << 10

// toolRunResult reads the outcome of a run_loop_now job — the same intent row
// GET /me/intents/:id serves, scoped to the caller.
//
// run_loop_now returns a job_id and nothing else, and no chat tool read it
// back. Measured 2026-09-25 on quant-research: asked to backtest a sample and
// report the claim id, the model queued the run, then spent five minutes in
// cycle_detail / run_detail / list_runs / loop_status (none of which can see a
// one-shot run), re-submitted twice, and never produced the claim id. The claim
// id was sitting in this row's result the whole time.
func toolRunResult(userID, jobID string) (map[string]any, bool) {
	jobID = strings.TrimSpace(jobID)
	if !meIntentIDRe.MatchString(jobID) {
		return map[string]any{"error": "job_id must be the id run_loop_now returned"}, false
	}
	var row models.MeAppIntent
	if err := common.DB.Where("id = ? AND user_sub = ?", jobID, userID).First(&row).Error; err != nil {
		return map[string]any{"error": "no such job for this user"}, false
	}
	out := map[string]any{"job_id": jobID}
	var payload map[string]any
	if row.Payload != "" && json.Unmarshal([]byte(row.Payload), &payload) == nil {
		out["app"], out["loop"] = payload["app"], payload["loop"]
	}
	if row.Status != "done" && row.Status != "failed" {
		out["status"] = "pending"
		out["hint"] = "still queued or running — check again shortly"
		return out, true
	}
	out["status"] = "completed"
	var res map[string]any
	if row.Result != "" {
		_ = json.Unmarshal([]byte(row.Result), &res)
	}
	return summarizeRunResult(out, res), true
}

// summarizeRunResult lifts the fields a model needs out of the cycle-runner
// envelope ({ok, error, data: <cycle summary>}): the command engine's own
// output (claim_id, symbol, outcome, …) and the surfaced metrics.
func summarizeRunResult(out, res map[string]any) map[string]any {
	if res == nil {
		return out
	}
	if v, ok := res["ok"]; ok {
		out["ok"] = v
	}
	if e, ok := res["error"].(string); ok && e != "" {
		out["error"] = clip(e, 800)
	}
	data, _ := res["data"].(map[string]any)
	if data == nil {
		// The picker's synchronous envelope carries the summary at the top.
		data = res
	}
	if ce, ok := data["command_engine"]; ok {
		if b, err := json.Marshal(ce); err == nil {
			if len(b) > runResultMaxBytes {
				out["output_truncated"] = true
				out["output"] = string(b[:runResultMaxBytes])
			} else {
				out["output"] = ce
			}
		}
	}
	if m, ok := data["metrics"]; ok {
		out["metrics"] = m
	}
	if e, ok := data["error"].(string); ok && e != "" && out["error"] == nil {
		out["error"] = clip(e, 800)
	}
	return out
}
