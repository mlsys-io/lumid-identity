package handler

// Run-now guard (2026-11-26).
//
// Run-now (POST /me/agents/:agent/workflows/:workflow/run, the legacy
// /me/loops/:app/:loop/run, and the Studio agent's run tool) queues a cycle —
// a scheduler pod — and had no limit at all. Measured: one tenant drove
// 900–2,400 quant-research backtest cycles a day for five weeks, one every
// ~37 s, most of them `poll <claim>` cycles that only READ a claim, from a
// personal token scoped to lqt:strategy. The schedule saying `run: manual`
// and the tenant's own overrides disabling the workflow stopped none of it:
// both govern the scheduler, not Run-now.
//
//   - A per-user rate limit, enforced: RUN_NOW_PER_HOUR (60) and
//     RUN_NOW_PER_DAY (600) run_loop intents. Over 7 days the busiest hour of
//     every other user was ≤ 9. Admins are exempt (operators, e2e).
//   - A token-scope check for personal tokens, OBSERVED by default: a PAT
//     must name a scope that can start work (*, lumid:write, lumid:admin,
//     lumid:run, flowmesh:workflows:write, flowmesh:write). With
//     RUN_NOW_REQUIRE_SCOPE=enforce a narrower token (lqt:strategy,
//     claude:proxy, lumid:read, …) is refused; until then each such call is
//     logged once per token per hour, so the switch can be flipped knowing
//     who depends on the loophole (the admin-scope gate did the same).
//
// Refusals say how to READ a result without starting a run, which is what
// most of the measured traffic wanted.

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const runNowReadHint = "To read a run you already started, don't start another: GET /api/v1/me/runs/<run_id>. " +
	"For a backtest claim, GET https://lum.id/api/research/backtests/<claim_id> with your lqt:strategy token, " +
	"or measure_get(<key>)."

var runNowScopes = map[string]bool{
	"*": true, "lumid:write": true, "lumid:admin": true, "lumid:run": true,
	"flowmesh:workflows:write": true, "flowmesh:write": true,
}

// runNowScopesAllow — the decision, separate from credential lookup.
func runNowScopesAllow(scopes string) bool {
	for _, s := range strings.Fields(scopes) {
		if runNowScopes[s] {
			return true
		}
	}
	return false
}

// runNowLimit returns a refusal and a Retry-After (seconds), or "" when the
// user may start another run.
func runNowLimit(userID string) (string, int) {
	if _, role := userEmailRole(userID); role == "admin" || role == "super_admin" {
		return "", 0
	}
	now := time.Now()
	count := func(since time.Time) (int64, time.Time) {
		var n int64
		q := common.DB.Model(&models.MeAppIntent{}).
			Where("user_sub = ? AND action = ? AND created_at > ?", userID, "run_loop", since)
		q.Count(&n)
		var oldest models.MeAppIntent
		common.DB.Where("user_sub = ? AND action = ? AND created_at > ?", userID, "run_loop", since).
			Order("created_at ASC").Limit(1).Select("created_at").Find(&oldest)
		return n, oldest.CreatedAt
	}
	if hour := measureLimit("RUN_NOW_PER_HOUR", 60); hour > 0 {
		if n, oldest := count(now.Add(-time.Hour)); n >= int64(hour) {
			return fmt.Sprintf("You started %d runs in the last hour (limit %d). %s", n, hour, runNowReadHint),
				runNowRetry(oldest, time.Hour, now)
		}
	}
	if day := measureLimit("RUN_NOW_PER_DAY", 600); day > 0 {
		if n, oldest := count(now.Add(-24 * time.Hour)); n >= int64(day) {
			return fmt.Sprintf("You started %d runs in the last 24 hours (limit %d). %s", n, day, runNowReadHint),
				runNowRetry(oldest, 24*time.Hour, now)
		}
	}
	return "", 0
}

func runNowRetry(oldest time.Time, window time.Duration, now time.Time) int {
	if oldest.IsZero() {
		return 60
	}
	s := int(oldest.Add(window).Sub(now).Seconds()) + 1
	if s < 1 {
		s = 1
	}
	return s
}

// runNowScopeObserved remembers which tokens were already logged this hour.
var runNowScopeObserved sync.Map // token id -> time.Time

// runNowScopeRefusal: "" when the credential may start runs (a session JWT,
// or a PAT with a run-capable scope), or when the check only observes.
func runNowScopeRefusal(c *gin.Context, userID, app, loop string) string {
	tok := bearerToken(c)
	if !strings.HasPrefix(tok, "lm_pat_") && !strings.HasPrefix(tok, "rm_pat_") {
		return ""
	}
	row, found := lookupPAT(tok)
	if !found || runNowScopesAllow(row.Scopes) {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RUN_NOW_REQUIRE_SCOPE")), "enforce") {
		return fmt.Sprintf("This token (%q, scopes: %s) can't start runs. Create a token with lumid:write to start "+
			"runs. %s", row.Name, row.Scopes, runNowReadHint)
	}
	key := fmt.Sprint(row.ID)
	if last, seen := runNowScopeObserved.Load(key); !seen || time.Since(last.(time.Time)) > time.Hour {
		runNowScopeObserved.Store(key, time.Now())
		log.Printf("[run-now] OBSERVE token lacks a run scope: user=%s token=%q scopes=%q app=%s loop=%s "+
			"(refused once RUN_NOW_REQUIRE_SCOPE=enforce)", userID, row.Name, row.Scopes, app, loop)
	}
	return ""
}

// runNowRefuse writes the 429 for a rate-limit refusal.
func runNowRefuse(c *gin.Context, msg string, retry int) {
	c.Header("Retry-After", fmt.Sprint(retry))
	c.JSON(http.StatusTooManyRequests, gin.H{"ret_code": 1429, "message": msg,
		"data": gin.H{"status": "not_started", "retry_after": retry, "reason": msg}})
}
