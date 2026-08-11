package handler

// GET /api/v1/me/claude-usage — self-serve view of the caller's Claude
// account-pool consumption (5h/7d fixed windows + per-model 7d breakdown).
// Same anchor-based windows as AdminClaudeUserUsage filtered to the current
// user; powers the chatbox QuotaMeter shown when a claude-code model is
// selected.

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

	status, err := common.ClaudePoolUsage(common.DB, userID, now)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query usage: "+err.Error())
		return
	}

	// The cost/requests/model-breakdown stats below hard-reset in lockstep
	// with the 7d token window: bound the query by the SAME instant
	// ClaudePoolUsage just used, reconstructed from the reset it returned
	// (reset - 7d = the live anchor; a zero reset means idle, so the far-
	// future sentinel yields zero rows — matching the token/pct reset).
	sevenDayBound := now.AddDate(100, 0, 0)
	if !status.SevenDayReset.IsZero() {
		sevenDayBound = status.SevenDayReset.Add(-7 * 24 * time.Hour)
	}

	var spend struct {
		CostCents int
		Reqs      int
	}
	if err := common.DB.Raw(`
		SELECT COALESCE(SUM(ue.cost_cents), 0) AS cost_cents,
		       COUNT(*)                        AS reqs
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?`,
		userID, sevenDayBound).Scan(&spend).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query usage: "+err.Error())
		return
	}

	// Per-model breakdown, same anchor-bounded 7d window.
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
		userID, sevenDayBound).Scan(&modelRows)
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
			"five_hour_tokens": status.FiveHourUsed,
			"seven_day_tokens": status.SevenDayUsed,
			"five_hour_pct":    float64(status.FiveHourUsed) / float64(cap5) * 100,
			"seven_day_pct":    float64(status.SevenDayUsed) / float64(cap7) * 100,
			"five_hour_reset":  formatPoolResetForMe(status.FiveHourReset),
			"seven_day_reset":  formatPoolResetForMe(status.SevenDayReset),
			"cost_cents_7d":    spend.CostCents,
			"requests_7d":      spend.Reqs,
			"models":           models,
			"cap_5h":           cap5,
			"cap_7d":           cap7,
			// Env-tunable and no longer 5h — see shortWindowLabel. Any surface
			// showing this quota must render it instead of a hardcoded "5h".
			"short_window_label": shortWindowLabel(),
		},
	})
}

// formatPoolResetForMe renders a reset instant as RFC3339, or "" when the
// window is idle — matches ChargeRes.FiveHourReset/SevenDayReset's wire
// convention exactly so the chatbox QuotaMeter treats both surfaces the same.
func formatPoolResetForMe(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
