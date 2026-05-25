// /me/mind — the Improve surface (W4).
//
// Two endpoints power /studio/mind:
//   GET /me/mind/workflow/:slug  — workflow report card (plain-English deltas)
//   POST /me/mind/evaluate       — enqueue a (skill, app) onto skill-roster's
//                                  evaluate queue for on-demand scoring.
//
// Sources (all existing infrastructure; no new collection pipeline):
//   - tenant journal.jsonl per app → run counts, success/fail rates,
//     duration trends.
//   - tenant data/drafts state map → draft accept-rate (sent/total).
//   - usage_events table (when present) → cost deltas.
//
// Deferred to a follow-up:
//   - /me/mind/skills?compare=<name> for the parallel-coords plot.
//     Requires denser attestation rows than we have at W1 close.

package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// MeMindWorkflow — GET /me/mind/workflow/:slug
//
// Plain-English progress card built from the user's own data
// (tenant-isolated). No cross-tenant reads.
func MeMindWorkflow(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	slug := c.Param("slug")
	parts := strings.SplitN(slug, ":", 2)
	if len(parts) != 2 || parts[0] == "n8n" {
		fail(c, http.StatusBadRequest, 1400, "report cards only for scheduled workflows (slug '<app>:<loop>')")
		return
	}
	app, loop := parts[0], parts[1]

	now := time.Now().UTC()
	thisMonth := now.AddDate(0, -1, 0)
	prevMonth := now.AddDate(0, -2, 0)

	thisMonthStats := buildLoopStats(userID, app, loop, thisMonth, now)
	prevMonthStats := buildLoopStats(userID, app, loop, prevMonth, thisMonth)

	deltas := buildDeltas(thisMonthStats, prevMonthStats)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"slug":         slug,
			"app":          app,
			"loop":         loop,
			"this_month":   thisMonthStats,
			"prev_month":   prevMonthStats,
			"deltas":       deltas,
			"as_of":        now.Format(time.RFC3339),
		},
	})
}

// MeMindSkills — GET /me/mind/skills?compare=<skill_name>
//
// Returns the parallel-coords dataset for one skill: rows = each
// attestation run; columns = (version, model, casebook, score,
// latency_s, cost_cents). Reads the xpcloud-side skill_scores.jsonl
// which is bind-mounted into identity at /var/lib/lumid-xpcloud-data/
// (read-only). When the file is missing or empty, returns an empty
// rows array — the UI handles "coming soon" gracefully.
//
// Globally-shared: every tenant sees the same plot. The data is
// reproducible (skill + casebook + model + score) and contains no
// personal information per the isolation contract.
func MeMindSkills(c *gin.Context) {
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	skill := strings.TrimSpace(c.Query("compare"))
	if skill == "" {
		fail(c, http.StatusBadRequest, 1400, "compare=<skill_name> required")
		return
	}

	// Two candidate paths: bind-mounted xpcloud data (preferred),
	// or the source-of-truth path (host runs).
	candidates := []string{
		"/var/lib/lumid-xpcloud-data/scores/skill_scores.jsonl",
		"/proj/infra/compose/xpcloud/data/scores/skill_scores.jsonl",
	}
	scoresPath := ""
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			scoresPath = p
			break
		}
	}

	rows := []map[string]any{}
	if scoresPath != "" {
		f, err := os.Open(scoresPath)
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				var row map[string]any
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					continue
				}
				if s, _ := row["skill"].(string); s == skill {
					rows = append(rows, row)
				}
			}
		}
	}

	// Sort newest first for stable rendering.
	sort.SliceStable(rows, func(i, j int) bool {
		ti, _ := rows[i]["ts"].(string)
		tj, _ := rows[j]["ts"].(string)
		return ti > tj
	})

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"skill":  skill,
			"rows":   rows,
			"count":  len(rows),
			"as_of":  time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// MeMindEvaluate — POST /me/mind/evaluate
//
// Body: {skill_name, for_app}
// Enqueues (skill_name, for_app) onto skill-roster's evaluate queue.
// The skill-roster cycle picks it up within ~60s and POSTs an
// attestation to xpcloud when scoring completes.
func MeMindEvaluate(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		SkillName string `json:"skill_name"`
		ForApp    string `json:"for_app"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	if body.SkillName == "" || body.ForApp == "" {
		fail(c, http.StatusBadRequest, 1400, "skill_name and for_app required")
		return
	}

	queuePath := filepath.Join(operatorHome(), ".xp", "apps", "skill-roster", "data", "eval-queue.jsonl")
	if err := os.MkdirAll(filepath.Dir(queuePath), 0o775); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "queue dir: "+err.Error())
		return
	}

	entry := map[string]any{
		"skill":       body.SkillName,
		"for_app":     body.ForApp,
		"requested_by": userID,
		"requested_at": time.Now().UTC().Format(time.RFC3339),
		"status":      "queued",
	}
	row, _ := json.Marshal(entry)
	f, err := os.OpenFile(queuePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "open queue: "+err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(row, '\n')); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write queue: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"queued":      true,
			"skill":       body.SkillName,
			"for_app":     body.ForApp,
			"note":        "skill-roster picks up the queue within 60s; attestation lands on xpcloud once scoring completes.",
		},
	})
}

// LoopStats — what we summarise per workflow over a time window.
type LoopStats struct {
	RunCount       int     `json:"run_count"`
	SuccessCount   int     `json:"success_count"`
	FailureCount   int     `json:"failure_count"`
	SkippedCount   int     `json:"skipped_count"`
	SuccessRate    float64 `json:"success_rate"`
	AvgDurationSec float64 `json:"avg_duration_s"`
	DraftsCreated  int     `json:"drafts_created,omitempty"`
	DraftsAccepted int     `json:"drafts_accepted,omitempty"`
	DraftAcceptRate float64 `json:"draft_accept_rate,omitempty"`
}

func buildLoopStats(userID, app, loop string, since, until time.Time) LoopStats {
	stats := LoopStats{}
	for _, root := range []string{
		tenantAppsDir(userID),
		filepath.Join(operatorHome(), ".xp", "apps"),
	} {
		journal := filepath.Join(root, app, "data", "journal.jsonl")
		if _, err := os.Stat(journal); err != nil {
			continue
		}
		f, err := os.Open(journal)
		if err != nil {
			continue
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		sinceU := float64(since.Unix())
		untilU := float64(until.Unix())
		durSum := 0.0
		durCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				continue
			}
			if lp, _ := row["loop"].(string); lp != loop {
				continue
			}
			ts := rowUnixTs(row)
			if ts < sinceU || ts > untilU {
				continue
			}
			stats.RunCount++
			if skipped, _ := row["skipped"].(bool); skipped {
				stats.SkippedCount++
				continue
			}
			if ok, _ := row["ok"].(bool); ok {
				stats.SuccessCount++
			} else {
				stats.FailureCount++
			}
			if d, ok := row["duration_s"].(float64); ok {
				durSum += d
				durCount++
			}
		}
		if durCount > 0 {
			stats.AvgDurationSec = durSum / float64(durCount)
		}
		denom := stats.SuccessCount + stats.FailureCount
		if denom > 0 {
			stats.SuccessRate = float64(stats.SuccessCount) / float64(denom)
		}
		break // first match wins (tenant > operator)
	}

	// Draft accept-rate, if the loop produces drafts.
	if drafts := countDraftsInWindow(userID, app, since, until); drafts.created > 0 {
		stats.DraftsCreated = drafts.created
		stats.DraftsAccepted = drafts.accepted
		if drafts.created > 0 {
			stats.DraftAcceptRate = float64(drafts.accepted) / float64(drafts.created)
		}
	}

	return stats
}

type draftCounts struct{ created, accepted int }

// countDraftsInWindow walks the tenant's per-app drafts state map
// and counts {created, accepted=sent} within the window.
func countDraftsInWindow(userID, app string, since, until time.Time) draftCounts {
	out := draftCounts{}
	stateMap := loadStateMap(filepath.Join(tenantAppsDir(userID), app))
	for _, s := range stateMap {
		ts, _ := time.Parse(time.RFC3339, s.ActedAt)
		if ts.IsZero() {
			continue
		}
		if ts.Before(since) || ts.After(until) {
			continue
		}
		out.created++
		if s.State == "sent" {
			out.accepted++
		}
	}
	return out
}

// Delta — what we report to the UI / chat.
type Delta struct {
	Headline string `json:"headline"`
	Detail   string `json:"detail,omitempty"`
	Trend    string `json:"trend"` // "up" | "down" | "flat"
}

// buildDeltas compares two LoopStats and emits plain-English deltas.
func buildDeltas(cur, prev LoopStats) []Delta {
	out := []Delta{}

	if cur.RunCount == 0 && prev.RunCount == 0 {
		return []Delta{{Headline: "No runs yet — your AI hasn't run this workflow.", Trend: "flat"}}
	}

	// Success rate.
	if cur.SuccessRate > 0 || prev.SuccessRate > 0 {
		diff := cur.SuccessRate - prev.SuccessRate
		curPct := int(cur.SuccessRate * 100)
		prevPct := int(prev.SuccessRate * 100)
		switch {
		case diff > 0.05:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Reliability up: %d%% → %d%%.", prevPct, curPct),
				Trend:    "up",
			})
		case diff < -0.05:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Reliability down: %d%% → %d%%.", prevPct, curPct),
				Detail:   "Check recent failures in Runs.",
				Trend:    "down",
			})
		default:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Reliability steady at %d%%.", curPct),
				Trend:    "flat",
			})
		}
	}

	// Latency.
	if cur.AvgDurationSec > 0 && prev.AvgDurationSec > 0 {
		ratio := cur.AvgDurationSec / prev.AvgDurationSec
		switch {
		case ratio < 0.9:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Faster: %.1fs → %.1fs (%.0f%% quicker).", prev.AvgDurationSec, cur.AvgDurationSec, (1-ratio)*100),
				Trend:    "up",
			})
		case ratio > 1.1:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Slower: %.1fs → %.1fs.", prev.AvgDurationSec, cur.AvgDurationSec),
				Detail:   "Some steps may be re-running unnecessarily.",
				Trend:    "down",
			})
		}
	}

	// Draft accept-rate.
	if cur.DraftsCreated > 0 || prev.DraftsCreated > 0 {
		diff := cur.DraftAcceptRate - prev.DraftAcceptRate
		switch {
		case diff > 0.05:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Drafts more useful — accept-rate %d%% (was %d%%).", int(cur.DraftAcceptRate*100), int(prev.DraftAcceptRate*100)),
				Trend:    "up",
			})
		case diff < -0.05:
			out = append(out, Delta{
				Headline: fmt.Sprintf("Drafts less useful — accept-rate %d%% (was %d%%).", int(cur.DraftAcceptRate*100), int(prev.DraftAcceptRate*100)),
				Detail:   "You're dismissing more than before — consider swapping the drafting skill.",
				Trend:    "down",
			})
		}
	}

	if len(out) == 0 {
		out = append(out, Delta{
			Headline: fmt.Sprintf("Steady — %d runs this month.", cur.RunCount),
			Trend:    "flat",
		})
	}

	return out
}

// unused import guard — common is referenced for future expansion
// (attestation reads from xpcloud will land in a follow-up).
var _ = common.TodayBound
