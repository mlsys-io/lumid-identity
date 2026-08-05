package handler

// GET /api/v1/me/claude-usage — self-serve view of the caller's Claude
// account-pool consumption (5h/7d rolling windows + per-model 7d breakdown).
// Same queries as AdminClaudeUserUsage filtered to the current user; powers
// the chatbox QuotaMeter shown when a claude-code model is selected.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

func MeClaudeUsage(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	now := time.Now().UTC()

	rows := []struct {
		Win       string
		Tokens    int
		CostCents int
		Reqs      int
	}{}
	err := common.DB.Raw(`
		SELECT CASE WHEN ue.ts >= ? THEN '5h' ELSE '7d' END       AS win,
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens), 0) AS tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents,
		       COUNT(*)                                           AS reqs
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?
		GROUP  BY win`,
		now.Add(-5*time.Hour), userID, now.Add(-7*24*time.Hour)).Scan(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query usage: "+err.Error())
		return
	}

	var fiveH, sevenD, costCents7d, reqs7d int
	for _, r := range rows {
		if r.Win == "5h" {
			fiveH += r.Tokens
		}
		sevenD += r.Tokens // 5h bucket is inside the 7d window
		costCents7d += r.CostCents
		reqs7d += r.Reqs
	}

	reset5, reset7 := ClaudeWindowResets(userID, now)

	// Per-model breakdown over the 7d window.
	modelRows := []struct {
		Model     string
		Tokens    int
		CostCents int
	}{}
	common.DB.Raw(`
		SELECT COALESCE(ue.model, '')                             AS model,
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens), 0) AS tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?
		GROUP  BY ue.model`,
		userID, now.Add(-7*24*time.Hour)).Scan(&modelRows)
	type modelUsage struct {
		Tokens    int `json:"tokens_7d"`
		CostCents int `json:"cost_cents_7d"`
	}
	models := map[string]modelUsage{}
	for _, m := range modelRows {
		models[m.Model] = modelUsage{Tokens: m.Tokens, CostCents: m.CostCents}
	}

	cap5, cap7 := common.ClaudePoolLimits()
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"five_hour_tokens": fiveH,
			"seven_day_tokens": sevenD,
			"five_hour_pct":    float64(fiveH) / float64(cap5) * 100,
			"seven_day_pct":    float64(sevenD) / float64(cap7) * 100,
			"five_hour_reset":  reset5,
			"seven_day_reset":  reset7,
			"cost_cents_7d":    costCents7d,
			"requests_7d":      reqs7d,
			"models":           models,
			"cap_5h":           cap5,
			"cap_7d":           cap7,
		},
	})
}

// ClaudeWindowResets returns when each rolling pool window frees up: the
// moment the OLDEST event still inside the window ages out of it. Zero times
// mean the window holds no usage, so there is nothing to reset.
//
// Shared by MeClaudeUsage (the /quota + statusline surfaces) and
// InternalUsageCharge (which feeds claude-proxy's anthropic-ratelimit-unified-*
// header rewrite) so both report the same instant — a user comparing the
// dashboard against their CLI must not see two different numbers.
func ClaudeWindowResets(userSub string, now time.Time) (reset5, reset7 time.Time) {
	oldest := []struct {
		Win      string
		OldestTs time.Time
	}{}
	// GROUP BY puts each row in exactly one bucket, so the '7d' group holds the
	// oldest row that is NOT also within 5h — which is the true 7d-window edge,
	// since anything in the 5h bucket is strictly newer.
	common.DB.Raw(`
		SELECT CASE WHEN ue.ts >= ? THEN '5h' ELSE '7d' END AS win,
		       MIN(ue.ts)                                   AS oldest_ts
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?
		GROUP  BY win`,
		now.Add(-5*time.Hour), userSub, now.Add(-7*24*time.Hour)).Scan(&oldest)
	for _, o := range oldest {
		switch o.Win {
		case "5h":
			reset5 = o.OldestTs.Add(5 * time.Hour)
		case "7d":
			reset7 = o.OldestTs.Add(7 * 24 * time.Hour)
		}
	}
	return reset5, reset7
}
