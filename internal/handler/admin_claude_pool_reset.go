package handler

// Reset the per-user SHORT-window quota clock.
//
// Needed whenever the window is retuned: on 2026-08-11 the cap moved from
// 4M/5h to 2M/4h, and every anchor already in the table had been opened under
// the old policy. A user who had spent 3M was instantly over the new 2M ceiling
// and stayed locked out until their stale anchor aged out — through no action
// of their own. Resetting hands everyone a clean window under the new rules.
//
// Deliberately expires the anchor rather than deleting the row or stamping it
// to now:
//
//   - DELETE would drop seven_day_anchor too, silently resetting the 7d budget
//     as well. That is a much bigger giveaway than asked for.
//   - Stamping the anchor to NOW would start a 4h clock ticking for someone who
//     is not working, so their fresh window would be partly gone before their
//     first request. An EXPIRED anchor is the natural "no window open" state:
//     ClaudePoolUsage reads zero, and ClaudePoolCommit opens a fresh anchor on
//     the user's next charge — matching the anchored-on-first-use design.

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// AdminClaudePoolResetWindow — POST /api/v1/admin/claude-pool/reset-window
// (RequireSuperAdmin)
//
// Body (optional): {"email": "user@example.com"} or {"user_sub": "..."} to
// reset ONE user. With neither, resets every user — which is the intended use
// after a policy change, so it is allowed, but the response always reports the
// row count so a pool-wide reset is never silent.
func AdminClaudePoolResetWindow(c *gin.Context) {
	var body struct {
		Email   string `json:"email"`
		UserSub string `json:"user_sub"`
	}
	_ = c.ShouldBindJSON(&body) // empty body = reset all; not an error

	sub := body.UserSub
	if sub == "" && body.Email != "" {
		var u models.User
		if err := common.DB.Where("email = ?", body.Email).First(&u).Error; err != nil {
			fail(c, http.StatusNotFound, 1404, "no such user: "+body.Email)
			return
		}
		sub = u.ID
	}

	// One second past the window so ClaudeWindowLive reports it closed, with no
	// dependence on clock skew between replicas.
	expired := time.Now().UTC().Add(-common.ClaudePoolShortWindow() - time.Second)

	q := common.DB.Model(&models.ClaudePoolWindow{})
	if sub != "" {
		q = q.Where("user_sub = ?", sub)
	}
	res := q.Update("five_hour_anchor", expired)
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "reset: "+res.Error.Error())
		return
	}

	scope := "all users"
	if sub != "" {
		scope = sub
	}
	actor, _ := currentUserID(c)
	// Audit line: this grants capacity back, so who did it and how widely must
	// be recoverable from logs alone.
	logPoolWindowReset(actor, scope, res.RowsAffected)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"reset":        res.RowsAffected,
			"scope":        scope,
			"window":       shortWindowLabel(),
			"reopens_on":   "next request (anchored on first use)",
			"budget_short": firstOf(common.ClaudePoolLimits()),
		},
	})
}

func firstOf(a, _ int) int { return a }

// logPoolWindowReset records a quota reset. Separate function so the audit
// line has one call site and cannot be dropped by a refactor of the handler.
func logPoolWindowReset(actor, scope string, rows int64) {
	log.Printf("claude-pool: quota window RESET by %s — scope=%s rows=%d window=%s",
		actor, scope, rows, shortWindowLabel())
}
