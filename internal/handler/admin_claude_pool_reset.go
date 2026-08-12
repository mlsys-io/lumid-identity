package handler

// Reset a per-user quota clock — the short (4h) window, the weekly (7d)
// window, or both. Short is the default; see the handler doc for why.
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
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// AdminClaudePoolResetWindow — POST /api/v1/admin/claude-pool/reset-window
// (RequireSuperAdmin)
//
// Body (all optional):
//
//	{"email": "..."} or {"user_sub": "..."}  — reset ONE user; neither = everyone
//	{"window": "short" | "weekly" | "both"}  — which clock; DEFAULT "short"
//
// The default stays "short" so every existing caller keeps its exact behaviour:
// the 7d budget is the expensive one to hand back, and a caller that didn't ask
// for it must never get it. Resetting the weekly clock is a deliberate,
// explicitly-named act.
//
// The response always reports the row count and which window moved, so a
// pool-wide reset is never silent.
func AdminClaudePoolResetWindow(c *gin.Context) {
	var body struct {
		Email   string `json:"email"`
		UserSub string `json:"user_sub"`
		Window  string `json:"window"`
	}
	_ = c.ShouldBindJSON(&body) // empty body = reset all, short window; not an error

	updates, label, err := poolResetColumns(body.Window, time.Now().UTC())
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}

	sub := body.UserSub
	if sub == "" && body.Email != "" {
		var u models.User
		if err := common.DB.Where("email = ?", body.Email).First(&u).Error; err != nil {
			fail(c, http.StatusNotFound, 1404, "no such user: "+body.Email)
			return
		}
		sub = u.ID
	}

	q := common.DB.Model(&models.ClaudePoolWindow{})
	if sub != "" {
		q = q.Where("user_sub = ?", sub)
	} else {
		// GORM refuses an UPDATE with no WHERE clause (ErrMissingWhereClause,
		// surfaced as "WHERE conditions required") — a guard against the
		// accidental global write. Resetting everyone is the whole point of the
		// no-argument form, so opt in EXPLICITLY rather than faking a predicate
		// like "1 = 1": the intent stays visible at the call site.
		q = q.Session(&gorm.Session{AllowGlobalUpdate: true})
	}
	res := q.Updates(updates)
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "reset: "+res.Error.Error())
		return
	}

	scope := "all users"
	if sub != "" {
		scope = sub
	}
	actor, _ := currentUserID(c)
	// Audit line: this grants capacity back, so who did it, how widely, and
	// WHICH clock must all be recoverable from logs alone.
	logPoolWindowReset(actor, scope, res.RowsAffected, label)

	short, weekly := common.ClaudePoolLimits()
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"reset":         res.RowsAffected,
			"scope":         scope,
			"window":        label,
			"reopens_on":    "next request (anchored on first use)",
			"budget_short":  short,
			"budget_weekly": weekly,
		},
	})
}

// logPoolWindowReset records a quota reset. Separate function so the audit
// line has one call site and cannot be dropped by a refactor of the handler.
func logPoolWindowReset(actor, scope string, rows int64, window string) {
	log.Printf("claude-pool: quota window RESET by %s — scope=%s rows=%d window=%s",
		actor, scope, rows, window)
}

// poolResetColumns maps the requested window onto the exact columns to update.
//
// Pulled out of the handler as a PURE function on purpose. The property that
// actually matters — "a short reset must not touch the 7d anchor" — is a
// statement about which columns get written, and that cannot be tested through
// the handler without a live DB. The previous test for it compared two string
// literals to each other, so it passed regardless of what the handler did; it
// did not catch this very change from Update() to Updates(). A pure function
// makes the real assertion cheap and DB-free.
//
// Anchors are EXPIRED rather than stamped to now: ClaudePoolCommit reopens an
// anchor on the next charge once its window has fully elapsed, so "expired"
// means "no window open" and the user's fresh window starts when they actually
// work — not the moment an operator ran the reset.
func poolResetColumns(window string, now time.Time) (map[string]interface{}, string, error) {
	w := strings.ToLower(strings.TrimSpace(window))
	if w == "" {
		// Default is SHORT, never weekly: the 7d budget is the expensive one to
		// hand back, and a caller that did not name it must not get it.
		w = "short"
	}
	updates := map[string]interface{}{}
	switch w {
	case "short":
		updates["five_hour_anchor"] = now.Add(-common.ClaudePoolShortWindow() - time.Second)
		return updates, shortWindowLabel(), nil
	case "weekly":
		updates["seven_day_anchor"] = now.Add(-7*24*time.Hour - time.Second)
		return updates, "7d", nil
	case "both":
		updates["five_hour_anchor"] = now.Add(-common.ClaudePoolShortWindow() - time.Second)
		updates["seven_day_anchor"] = now.Add(-7*24*time.Hour - time.Second)
		return updates, shortWindowLabel() + "+7d", nil
	}
	return nil, "", fmt.Errorf(`window must be one of "short", "weekly", "both" (got %q)`, window)
}
