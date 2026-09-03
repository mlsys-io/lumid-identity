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
	UnknownOutcome int `json:"unknown_outcome"`
	// Users every one of whose submissions predates outcome recording. They are
	// NOT "never deployed" — we do not know what happened to them, and saying
	// otherwise turns a gap in our records into a claim about a person.
	UsersOutcomeUnknown int            `json:"users_outcome_unknown"`
	RejectReasons       []insightCount `json:"reject_reasons"`
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

	// ── submissions ──────────────────────────────────────────────────────────
	var subs []models.AuditLog
	common.DB.Where("event = ? AND app IN ? AND created_at >= ?",
		"lqt:strategy.submit", aliases, since).
		Order("created_at ASC").Limit(insightsRowCap).Find(&subs)

	funnel, subDays := computeSubmissionFunnel(subs)
	for day, n := range subDays {
		touch2(byDay, day).Submissions = n
	}

	// ── runs ─────────────────────────────────────────────────────────────────
	// Aggregated in SQL, not by loading rows. This app produces ~20k runs a
	// month across the fleet, so a row scan hits the cap and reports the cap as
	// a total; GROUP BY is both exact and cheaper. `loop` is a MySQL reserved
	// word and must stay backticked.
	type loopAgg struct {
		LoopName string
		N        int
		Fails    int
	}
	var loopAggs []loopAgg
	// Alias to loop_name, NOT loop. `loop` is a MySQL reserved word, so
	// "SELECT `loop` as loop" is a syntax error — and because the Scan error
	// was ignored this produced an EMPTY aggregate beside a working
	// COUNT(DISTINCT user_sub), i.e. a panel reading "0 runs across 43 users".
	// Self-contradictory numbers are worse than an error, so the error is
	// surfaced now rather than swallowed.
	aggErr := common.DB.Model(&models.MeAppRun{}).
		Select("`loop` as loop_name, COUNT(*) as n, SUM(CASE WHEN ok THEN 0 ELSE 1 END) as fails").
		Where("app IN ? AND run_ts >= ?", aliases, since.Unix()).
		Group("`loop`").Scan(&loopAggs).Error
	if aggErr != nil {
		fail(c, http.StatusInternalServerError, 1500, "runs rollup: "+aggErr.Error())
		return
	}

	runsByLoop := map[string]int{}
	runFails := map[string]int{}
	runTotal := 0
	for _, a := range loopAggs {
		runsByLoop[a.LoopName] = a.N
		runTotal += a.N
		if a.Fails > 0 {
			runFails[a.LoopName] = a.Fails
		}
	}

	var runUsersN int64
	common.DB.Model(&models.MeAppRun{}).
		Where("app IN ? AND run_ts >= ?", aliases, since.Unix()).
		Distinct("user_sub").Count(&runUsersN)

	var newestRun int64
	common.DB.Model(&models.MeAppRun{}).
		Where("app IN ?", aliases).
		Select("COALESCE(MAX(run_ts), 0)").Scan(&newestRun)

	type dayAgg struct {
		Day string
		N   int
	}
	var runDays []dayAgg
	if err := common.DB.Model(&models.MeAppRun{}).
		Select("DATE_FORMAT(FROM_UNIXTIME(run_ts), '%Y-%m-%d') as day, COUNT(*) as n").
		Where("app IN ? AND run_ts >= ?", aliases, since.Unix()).
		Group("day").Scan(&runDays).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "runs by day: "+err.Error())
		return
	}
	for _, d := range runDays {
		touch2(byDay, d.Day).Runs = d.N
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
		touch2(byDay, it.CreatedAt.UTC().Format("2006-01-02")).Intents++
		if it.ClaimedAt != nil {
			queueMs = append(queueMs, int(it.ClaimedAt.Sub(it.CreatedAt).Milliseconds()))
			if it.CompletedAt != nil {
				runMs = append(runMs, int(it.CompletedAt.Sub(*it.ClaimedAt).Milliseconds()))
			}
		}
	}
	sort.Ints(queueMs)
	sort.Ints(runMs)

	// ── backtest honesty ─────────────────────────────────────────────────────
	// The three axes the backtest loop records, straight from its own metrics
	// block. This is the only panel where an aggregate could quietly launder a
	// synthetic number into an apparent result, so the split is preserved
	// rather than summed: `presentable` counts ONLY runs where all three axes
	// came back real. Runs that carry no axes at all (queued, refused, or
	// written before the loop emitted them) are counted as unlabelled, never
	// as not-presentable — absent and false are different claims.
	var btRows []models.MeAppRun
	common.DB.Where("app IN ? AND `loop` = ? AND run_ts >= ?", aliases, "backtest", since.Unix()).
		Order("run_ts DESC").Limit(insightsRowCap).Find(&btRows)

	bt := map[string]int{}
	replayProv := map[string]int{}
	for _, r := range btRows {
		var m map[string]any
		if r.Metrics == "" || json.Unmarshal([]byte(r.Metrics), &m) != nil {
			bt["unlabelled"]++
			continue
		}
		if v, ok := m["replay"].(string); ok && v != "" {
			replayProv[v]++
		}
		p, hasP := m["presentable_as_performance"].(bool)
		_, hasAxis := m["replay"]
		switch {
		case hasP && p:
			bt["presentable (all 3 axes real)"]++
		case hasP && !p:
			bt["not presentable"]++
		case hasAxis:
			// Axes present but no verdict flag — still a run we know something
			// about, but not one we can call presentable.
			bt["partial labels"]++
		default:
			bt["unlabelled"]++
		}
	}

	// ── surface interactions ─────────────────────────────────────────────────
	// The only record of someone opening a page and doing nothing, which is
	// exactly the population a funnel otherwise cannot see.
	type actionAgg struct {
		Action string
		N      int
	}
	var actionAggs []actionAgg
	if err := common.DB.Model(&models.MeInteractionEvent{}).
		Select("action, COUNT(*) as n").
		Where("app IN ? AND created_at >= ?", aliases, since).
		Group("action").Scan(&actionAggs).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "interactions rollup: "+err.Error())
		return
	}
	byAction := map[string]int{}
	ixTotal := 0
	for _, a := range actionAggs {
		byAction[a.Action] = a.N
		ixTotal += a.N
	}
	var ixUsers int64
	common.DB.Model(&models.MeInteractionEvent{}).
		Where("app IN ? AND created_at >= ?", aliases, since).
		Distinct("user_sub").Count(&ixUsers)

	var surfaceAggs []struct {
		Surface string
		N       int
	}
	common.DB.Model(&models.MeInteractionEvent{}).
		Select("surface, COUNT(*) as n").
		Where("app IN ? AND created_at >= ? AND action = ?", aliases, since, "surface_view").
		Group("surface").Scan(&surfaceAggs)
	bySurface := map[string]int{}
	for _, a := range surfaceAggs {
		bySurface[a.Surface] = a.N
	}

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

	// A capped scan must SAY it was capped. `total: 20000` against a cap of
	// 20000 is not a total, it is the cap wearing a total's name — and it reads
	// as a precise number, which is worse than an obviously rounded one.
	truncated := gin.H{
		"submissions": len(subs) >= insightsRowCap,
		"runs":        false, // aggregated in SQL — exact
		"intents":     len(intents) >= insightsRowCap,
		"row_cap":     insightsRowCap,
	}

	ok(c, "ok", gin.H{
		"app":          app,
		"truncated":    truncated,
		"aliases":      aliases,
		"window_days":  days,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"submissions":  funnel,
		"runs": gin.H{
			"total":            runTotal,
			"users":            runUsersN,
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
		"backtests": gin.H{
			"total":      len(btRows),
			"by_verdict": topCounts(bt, 0),
			"by_tape":    topCounts(replayProv, 0),
			"truncated":  len(btRows) >= insightsRowCap,
		},
		"interactions": gin.H{
			"total":      ixTotal,
			"users":      ixUsers,
			"by_action":  topCounts(byAction, 0),
			"by_surface": topCounts(bySurface, 0),
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
	knownOutcome := map[string]bool{}

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
		if outcome != "" {
			knownOutcome[r.UserID] = true
		}
	}

	funnel.Users = len(subUsers)
	funnel.RejectReasons = topCounts(reasons, 20)
	tries := map[string]int{}
	for u := range subUsers {
		switch {
		case deployedAt[u] > 0:
			tries[strconv.Itoa(deployedAt[u])]++
		case knownOutcome[u]:
			// Had at least one recorded outcome, none of them a deploy.
			funnel.UsersNeverDeployed++
		default:
			funnel.UsersOutcomeUnknown++
		}
	}
	funnel.AttemptsToFirstDeploy = topCounts(tries, 10)
	sort.Ints(verdictMs)
	funnel.VerdictMsP50 = pctl(verdictMs, 0.50)
	funnel.VerdictMsP95 = pctl(verdictMs, 0.95)
	return funnel, perDay
}

// touch2 returns the per-day bucket for an ISO day key, creating it on demand.
func touch2(m map[string]*insightDay, day string) *insightDay {
	d, ok := m[day]
	if !ok {
		d = &insightDay{Day: day}
		m[day] = d
	}
	return d
}
