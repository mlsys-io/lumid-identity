package handler

// /api/v1/me/limits             — user-auth read; "today's totals + caps + reset"
// /api/v1/internal/usage/charge — bridge-auth atomic check + record
//
// Phase 0.6 (Tier-1 limits). See internal/common/quota.go for the
// underlying semantics. The picker (Python) calls the bridge endpoint
// at cycle-fire time + at every LLM/external-API call; the web UI calls
// the user endpoint to render the "free tier reached" banner on
// /app/loops.

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// RequireBridge gates a route on the X-Bridge-Secret header matching the
// env-configured shared secret. Used for service-to-service paths the
// Python scheduler/picker hits — never exposed to the public surface.
//
// If LUMID_IDENTITY_BRIDGE_SECRET is empty (dev/operator-only mode), the
// gate refuses everything — operators must explicitly opt in to service
// callers. This keeps the endpoint from being a footgun on a fresh box
// where the env var simply wasn't set.
func RequireBridge() gin.HandlerFunc {
	return func(c *gin.Context) {
		want := os.Getenv("LUMID_IDENTITY_BRIDGE_SECRET")
		if want == "" {
			fail(c, http.StatusServiceUnavailable, 1503, "bridge secret not configured")
			c.Abort()
			return
		}
		got := c.GetHeader("X-Bridge-Secret")
		if got == "" || got != want {
			fail(c, http.StatusUnauthorized, 1401, "invalid bridge secret")
			c.Abort()
			return
		}
		c.Next()
	}
}

// GET /api/v1/me/limits
//
// Returns the current user's today-totals + the active limit numbers +
// the next reset time. No write. Used by /app/loops to render the
// "Free tier reached" banner and "X cycles left today" hints.
func MeLimits(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	totals, err := common.FetchTodayTotals(common.DB, userID)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "fetch totals: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"today":    totals,
			"limits":   common.DefaultLimits(),
			"reset_at": common.NextResetAt().Format("2006-01-02T15:04:05Z07:00"),
		},
	})
}

// internalChargeBody is the wire shape for /internal/usage/charge.
// user_sub is passed explicitly because the bridge has no session;
// the caller (scheduler/picker) supplies it from the cycle's tenant root.
type internalChargeBody struct {
	UserSub      string `json:"user_sub"      binding:"required"`
	Kind         string `json:"kind"          binding:"required"`
	Endpoint     string `json:"endpoint,omitempty"`
	Model        string `json:"model,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`
	Count        int    `json:"count,omitempty"`
	CostCents    int    `json:"cost_cents,omitempty"`
	DryRun       bool   `json:"dry_run,omitempty"`
	Meta         string `json:"meta,omitempty"`
}

// POST /api/v1/internal/usage/charge   (X-Bridge-Secret required)
//
// Atomic check-and-record. Returns {allowed, deny_reason?, today, limits, reset_at}.
// On allowed=true && dry_run=false, writes a usage_events row.
func InternalUsageCharge(c *gin.Context) {
	var body internalChargeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	res, err := common.CheckAndCharge(common.DB, common.ChargeReq{
		UserSub:      body.UserSub,
		Kind:         body.Kind,
		Endpoint:     body.Endpoint,
		Model:        body.Model,
		InputTokens:  body.InputTokens,
		OutputTokens: body.OutputTokens,
		Count:        body.Count,
		CostCents:    body.CostCents,
		DryRun:       body.DryRun,
		Meta:         body.Meta,
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "charge: "+err.Error())
		return
	}
	// Return 200 regardless of allowed — the caller branches on res.allowed.
	// For the claude pool, piggyback the user's recording preference so the
	// proxy can skip shipping a transcript blob when the user opted out.
	if body.Kind == "claude_proxy" {
		// Window resets ride along so claude-proxy can rewrite the
		// anthropic-ratelimit-unified-* response headers with the CALLER's pool
		// budget. Without these the proxy would have to forward the pooled
		// ACCOUNT's reset, which belongs to a shared credential and tells the
		// user nothing about their own ceiling. Note `reset_at` above is the
		// daily counter roll, NOT these rolling windows — different clocks.
		reset5, reset7 := ClaudeWindowResets(body.UserSub, time.Now().UTC())
		fiveReset, sevenReset := "", ""
		if !reset5.IsZero() {
			fiveReset = reset5.UTC().Format(time.RFC3339)
		}
		if !reset7.IsZero() {
			sevenReset = reset7.UTC().Format(time.RFC3339)
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"allowed": res.Allowed, "deny_reason": res.DenyReason,
				"today": res.Today, "limits": res.Limits, "reset_at": res.ResetAt,
				"five_hour_pct": res.FiveHourPct, "seven_day_pct": res.SevenDayPct,
				"five_hour_reset": fiveReset, "seven_day_reset": sevenReset,
				"recording": recordingEnabled(body.UserSub),
			},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok", "data": res,
	})
}
