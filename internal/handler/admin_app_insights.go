package handler

// Per-app user-insight rollup — the reviewer's view of how one xpio app is
// actually being used, across every tenant.
//
//   GET /admin/apps/:app/insights?days=30
//
// WHY THIS IS ADMIN AND NOT SUPER_ADMIN. It mirrors /admin/cohort/submissions:
// reading how a cohort used an app is oversight, not privilege escalation. It
// moves nothing, grants nothing, and changes no state. Chat *transcripts* stay
// super_admin where the 2026-09-02 audit put them; this endpoint deliberately
// reports chat COUNTS and never chat content.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not score, rank, or grade anyone.
// The rule /admin/cohort/submissions set still holds: "telemetry cannot tell a
// researcher who converged from one who merely ran loops; that judgement is the
// reviewer's, and a summariser between the two would quietly become the thing
// being read." A reject-reason histogram is a fact about the compiler. A
// leaderboard of students would be a fact about nothing.
//
// WHY ONE ENDPOINT. The page needs six correlated numbers that must agree with
// each other; six round trips over a moving table is how a funnel ends up
// reporting more deploys than submissions.
//
// It is generic over apps by construction — every query keys on `app` — so a
// second app costs a route param, not a handler.

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	insightsDefaultDays = 30
	insightsMaxDays     = 365
	// Bound every scan. These tables have no retention (only `sessions` does),
	// so an unbounded SELECT here grows into a page-load-time incident later.
	insightsRowCap = 20000
)

type insightCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type insightDay struct {
	Day         string `json:"day"`
	Submissions int    `json:"submissions"`
	Runs        int    `json:"runs"`
	Intents     int    `json:"intents"`
}

// submissionFunnel is the heart of it: what people tried, and what happened.
type submissionFunnel struct {
	Total      int `json:"total"`
	Users      int `json:"users"`
	Attributed struct {
		Deployed  int `json:"deployed"`
		Rejected  int `json:"rejected"`
		NoVerdict int `json:"no_verdict"`
		Refused   int `json:"mailbox_refused"`
		Transport int `json:"transport_error"`
	} `json:"attributed"`
	// Rows written before the verdict was recorded. Counted, never guessed at.
	UnknownOutcome int            `json:"unknown_outcome"`
	RejectReasons  []insightCount `json:"reject_reasons"`
	// Attempts a user made before their first `deployed`, for those who got
	// there. Users who never deployed are reported separately, not as a large
	// number that would drag an average toward a fake answer.
	AttemptsToFirstDeploy []insightCount `json:"attempts_to_first_deploy"`
	UsersNeverDeployed    int            `json:"users_never_deployed"`
	VerdictMsP50          int            `json:"verdict_ms_p50,omitempty"`
	VerdictMsP95          int            `json:"verdict_ms_p95,omitempty"`
}

// pctl is nearest-rank: ceil(p*n)-1. Truncating instead — int((n-1)*p) — puts
// p95 of a 10-sample set at the 9th value, quietly reporting a latency budget
// as met when the sample that broke it is right there. A percentile that errs
// should err pessimistic.
func pctl(sorted []int, p float64) int {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(n))) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return sorted[i]
}

func topCounts(m map[string]int, n int) []insightCount {
	out := make([]insightCount, 0, len(m))
	for k, v := range m {
		out = append(out, insightCount{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// firstLine keeps a compiler diagnostic groupable. The full text stays in
// audit_log.detail; a histogram keyed on a message carrying character offsets
// would have one bucket per submission and say nothing.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func AdminAppInsights(c *gin.Context) {
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", strconv.Itoa(insightsDefaultDays)))
	if days < 1 {
		days = insightsDefaultDays
	}
	if days > insightsMaxDays {
		days = insightsMaxDays
	}
	since := time.Now().AddDate(0, 0, -days)
	aliases := appAliases(app)

	byDay := map[string]*insightDay{}
	touch := func(t time.Time) *insightDay {
		k := t.UTC().Format("2006-01-02")
		d, ok := byDay[k]
		if !ok {
			d = &insightDay{Day: k}
			byDay[k] = d
		}
		return d
	}

	// ── submissions ──────────────────────────────────────────────────────────
	var subs []models.AuditLog
	common.DB.Where("event = ? AND app IN ? AND created_at >= ?",
		"lqt:strategy.submit", aliases, since).
		Order("created_at ASC").Limit(insightsRowCap).Find(&subs)

	funnel, subDays := computeSubmissionFunnel(subs)
	for day, n := range subDays {
		byDay[day] = &insightDay{Day: day, Submissions: n}
	}

	// ── runs ─────────────────────────────────────────────────────────────────
	var runs []models.MeAppRun
	common.DB.Where("app IN ? AND run_ts >= ?", aliases, since.Unix()).
		Order("run_ts ASC").Limit(insightsRowCap).Find(&runs)
	runsByLoop := map[string]int{}
	runFails := map[string]int{}
	runUsers := map[string]bool{}
	var newestRun int64
	for _, r := range runs {
		runsByLoop[r.Loop]++
		runUsers[r.UserSub] = true
		if !r.Ok {
			runFails[r.Loop]++
		}
		if r.RunTs > newestRun {
			newestRun = r.RunTs
		}
		touch(time.Unix(r.RunTs, 0)).Runs++
	}

	// ── UI actions that ran a loop ───────────────────────────────────────────
	// me_app_intents is the only record of what someone clicked, with the
	// arguments they chose and what came back. Nothing has ever read it.
	var intents []models.MeAppIntent
	// Narrow to this app IN SQL before the row cap bites. The app lives inside
	// the payload JSON (a TEXT column, so no JSON_EXTRACT), and filtering in Go
	// after `LIMIT insightsRowCap` would cap on ALL apps' intents and then
	// discard most of them — silently undercounting this app whenever the fleet
	// is busy. LIKE is a prefilter only; the exact match still happens below on
	// the decoded payload.
	q := common.DB.Where("created_at >= ?", since)
	likes := common.DB.Session(&gorm.Session{NewDB: true})
	for i, a := range aliases {
		// Match the bare name, not `"app":"<name>"`. The exact check below is
		// on the decoded payload, so this only has to narrow — and a pattern
		// keyed on the serialised shape would silently match nothing the day
		// something writes that JSON with a space after the colon.
		pat := "%" + a + "%"
		if i == 0 {
			likes = likes.Where("payload LIKE ?", pat)
		} else {
			likes = likes.Or("payload LIKE ?", pat)
		}
	}
	q.Where(likes).Order("created_at ASC").Limit(insightsRowCap).Find(&intents)
	intentsByAction := map[string]int{}
	intentsByStatus := map[string]int{}
	intentUsers := map[string]bool{}
	var queueMs []int
	var runMs []int
	intentTotal := 0
	for _, it := range intents {
		var p map[string]any
		if it.Payload == "" || json.Unmarshal([]byte(it.Payload), &p) != nil {
			continue
		}
		pa, _ := p["app"].(string)
		if !containsStr(aliases, pa) {
			continue
		}
		intentTotal++
		intentsByAction[it.Action]++
		intentsByStatus[it.Status]++
		intentUsers[it.UserSub] = true
		touch(it.CreatedAt).Intents++
		if it.ClaimedAt != nil {
			queueMs = append(queueMs, int(it.ClaimedAt.Sub(it.CreatedAt).Milliseconds()))
			if it.CompletedAt != nil {
				runMs = append(runMs, int(it.CompletedAt.Sub(*it.ClaimedAt).Milliseconds()))
			}
		}
	}
	sort.Ints(queueMs)
	sort.Ints(runMs)

	// ── chats (counts only — never content) ──────────────────────────────────
	var chatTotal, chatUsersN int64
	common.DB.Model(&models.MeChat{}).Where("app IN ?", aliases).Count(&chatTotal)
	common.DB.Model(&models.MeChat{}).Where("app IN ?", aliases).
		Distinct("user_sub").Count(&chatUsersN)

	days30 := make([]insightDay, 0, len(byDay))
	for _, d := range byDay {
		days30 = append(days30, *d)
	}
	sort.Slice(days30, func(i, j int) bool { return days30[i].Day < days30[j].Day })

	staleSecs := int64(0)
	if newestRun > 0 {
		staleSecs = time.Now().Unix() - newestRun
	}

	ok(c, "ok", gin.H{
		"app":          app,
		"aliases":      aliases,
		"window_days":  days,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"submissions":  funnel,
		"runs": gin.H{
			"total":            len(runs),
			"users":            len(runUsers),
			"by_loop":          topCounts(runsByLoop, 0),
			"failures_by_loop": topCounts(runFails, 0),
			"newest_run_ts":    newestRun,
			"stale_seconds":    staleSecs,
		},
		"intents": gin.H{
			"total":        intentTotal,
			"users":        len(intentUsers),
			"by_action":    topCounts(intentsByAction, 0),
			"by_status":    topCounts(intentsByStatus, 0),
			"queue_ms_p50": pctl(queueMs, 0.50),
			"queue_ms_p95": pctl(queueMs, 0.95),
			"run_ms_p50":   pctl(runMs, 0.50),
			"run_ms_p95":   pctl(runMs, 0.95),
		},
		// A thread only carries an app when it was opened FROM an app page
		// (me_agent_chats.go), so a general-chatbox thread about this app is
		// invisible here. Labelled a floor so the page cannot present it as a
		// measurement.
		"chats": gin.H{
			"total":      chatTotal,
			"users":      chatUsersN,
			"is_floor":   true,
			"floor_note": "threads carry an app only when opened from an app page; general-chatbox threads about this app are not counted",
		},
		"activity": days30,
		"caveats": []string{
			"submissions before the verdict change carry outcome=unknown; they are counted, never inferred",
			"chat counts are a floor, not a measurement",
			"row scans are capped at " + strconv.Itoa(insightsRowCap) + " per table",
		},
	})
}

// computeSubmissionFunnel is the whole submission story, extracted from the
// handler so it can be tested without a database — the attempts-to-first-deploy
// accounting is the part most likely to be subtly wrong.
//
// Rows MUST arrive oldest-first: "attempts before first deploy" is a running
// count, and reversing the order silently inverts it.
func computeSubmissionFunnel(subs []models.AuditLog) (submissionFunnel, map[string]int) {
	funnel := submissionFunnel{}
	reasons := map[string]int{}
	perDay := map[string]int{}
	var verdictMs []int
	subUsers := map[string]bool{}
	attempts := map[string]int{}
	deployedAt := map[string]int{}

	for _, r := range subs {
		funnel.Total++
		subUsers[r.UserID] = true
		perDay[r.CreatedAt.UTC().Format("2006-01-02")]++
		if r.DurationMs > 0 {
			verdictMs = append(verdictMs, r.DurationMs)
		}
		var d map[string]any
		outcome := ""
		if r.Detail != "" && json.Unmarshal([]byte(r.Detail), &d) == nil {
			outcome, _ = d["outcome"].(string)
		}
		// Count the attempt only while this user has not yet deployed.
		if _, done := deployedAt[r.UserID]; !done {
			attempts[r.UserID]++
		}
		switch outcome {
		case "deployed":
			funnel.Attributed.Deployed++
			if _, done := deployedAt[r.UserID]; !done {
				deployedAt[r.UserID] = attempts[r.UserID]
			}
		case "rejected":
			funnel.Attributed.Rejected++
			if reason, _ := d["reason"].(string); reason != "" {
				reasons[firstLine(reason)]++
			} else {
				reasons["(reason not recorded)"]++
			}
		case "no_verdict":
			funnel.Attributed.NoVerdict++
		case "mailbox_refused":
			funnel.Attributed.Refused++
		case "transport_error":
			funnel.Attributed.Transport++
		default:
			// Written before the verdict was recorded. Counted as unknown
			// rather than folded into an outcome we do not actually know.
			funnel.UnknownOutcome++
		}
	}

	funnel.Users = len(subUsers)
	funnel.RejectReasons = topCounts(reasons, 20)
	tries := map[string]int{}
	for u := range subUsers {
		if n, ok := deployedAt[u]; ok {
			tries[strconv.Itoa(n)]++
		} else {
			funnel.UsersNeverDeployed++
		}
	}
	funnel.AttemptsToFirstDeploy = topCounts(tries, 10)
	sort.Ints(verdictMs)
	funnel.VerdictMsP50 = pctl(verdictMs, 0.50)
	funnel.VerdictMsP95 = pctl(verdictMs, 0.95)
	return funnel, perDay
}
