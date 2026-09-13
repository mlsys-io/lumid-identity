package handler

// The Outputs tier's data source.
//
// WorkflowObservabilityPanel promises "a plain workflow has Outputs only", and
// OutputsTier renders the latest run's final artifact. It binds to MeCycleDetail
// — which, like MeCycleLog, MeRuns and MeCyclesList, reads data/cycles and
// data/journal.jsonl OFF DISK. Identity mounts no tenant volume and its pod has
// no ~/.xp at all, so every one of those returns empty for every app and every
// user. Measured 2026-09-13: cycle-log total 0, /me/cycles 0, /me/runs 0. The
// tier shipped, deployed, and could not render for anyone.
//
// Rather than rewrite four disk-based surfaces, this serves the one thing the
// tier needs from the one store identity CAN read: me_app_runs, which the
// scheduler already self-reports into through the internal bridge. Same shape of
// answer as MeAppExperiment for experiment state.

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// MeAppLatestOutput — GET /me/apps/:app/latest-output[?loop=]
//
// The most recent run's artifact for the caller's own app. Returns an empty
// object rather than 404 when nothing has reported yet: "no runs" and "this app
// does not exist" are different states, and the panel renders them differently.
func MeAppLatestOutput(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	loop := c.Query("loop")
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}

	q := common.DB.Where("user_sub = ? AND app IN ?", userID, appAliases(app))
	if loop != "" {
		q = q.Where("`loop` = ?", loop) // reserved word — backtick-quote
	}
	// Newest run that actually CARRIES an artifact. Ordering by run_ts alone
	// would surface the newest run and then report "no outputs" whenever that
	// one happened not to emit any, hiding a perfectly good earlier artifact.
	var row models.MeAppRun
	err := q.Where("outputs IS NOT NULL AND outputs <> ''").
		Order("run_ts DESC").First(&row).Error

	out := gin.H{"app": app, "loop": loop, "outputs": nil, "run_ts": 0, "ok": true}
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": out})
		return
	}
	var parsed any
	if json.Unmarshal([]byte(row.Outputs), &parsed) != nil {
		parsed = nil // stored blob unreadable — report absence, never a fragment
	}
	out["outputs"] = parsed
	out["run_ts"] = row.RunTs
	out["loop"] = row.Loop
	out["ok"] = row.Ok
	if row.DurationS != nil {
		out["duration_s"] = *row.DurationS
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": out})
}
