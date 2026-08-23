package handler

// GET /api/v1/me/claude-usage — self-serve view of the caller's Claude
// account-pool consumption (5h/7d fixed windows + per-model 7d breakdown).
// Same anchor-based windows as AdminClaudeUserUsage filtered to the current
// user; powers the chatbox QuotaMeter shown when a claude-code model is
// selected.

import (
	"fmt"
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
		Model          string
		Tokens         int
		WeightedTokens int
		CostCents      int
	}{}
	common.DB.Raw(fmt.Sprintf(`
		SELECT COALESCE(ue.model, '')                             AS model,
		       -- RAW tokens, the SAME basis for every model. Omitting the cache
		       -- columns (as this did) puts Claude and non-Claude on different
		       -- footings in one breakdown: a Claude Code turn is 90-95%%
		       -- cache-read, so Claude showed at ~1/20th of real volume while
		       -- deepseek/kimi -- no prompt caching, whole prompt in
		       -- input_tokens -- showed at ~100%%. Mirrors AdminClaudeUserUsage.
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens
		                    + ue.cache_read_tokens + ue.cache_creation_tokens), 0) AS tokens,
		       -- Weighted quota units: what the cap is actually enforced against.
		       COALESCE(SUM(%[1]s), 0)                            AS weighted_tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?
		GROUP  BY ue.model`, common.ClaudeWeightedTokensSQL("ue.")),
		userID, sevenDayBound).Scan(&modelRows)
	type modelUsage struct {
		// Raw tokens (model-neutral) and price-weighted quota units, named
		// separately -- they differ ~10x on Claude traffic and one number
		// labelled "tokens" cannot honestly be both.
		Tokens         int `json:"tokens_7d"`
		WeightedTokens int `json:"weighted_tokens_7d"`
		CostCents      int `json:"cost_cents_7d"`
	}
	models := map[string]modelUsage{}
	for _, m := range modelRows {
		models[m.Model] = modelUsage{
			Tokens:         m.Tokens,
			WeightedTokens: m.WeightedTokens,
			CostCents:      m.CostCents,
		}
	}

	// Per-USER caps, not the global. Enforcement resolves the caller's role tier
	// (ClaudePoolLimitsForUser on the charge path), so reading the global here
	// would show a user a cap that is not the one they are actually held to:
	// admins are uncapped, and role `user` reads LUMID_QUOTA_CLAUDE_USER_*.
	// Showing someone else's number is worse than showing none.
	cap5, cap7 := common.ClaudePoolLimitsForUser(common.DB, userID)
	unlimited := common.ClaudePoolIsUnlimited(cap5)
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
			// True for admin/super_admin, who are uncapped. The caps above are
			// then a sentinel, not a budget — render "—", not 2.1B.
			"cap_unlimited": unlimited,
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
