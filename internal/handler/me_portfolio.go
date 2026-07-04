package handler

// P4 — the cross-workflow fleet/portfolio view.
//
// GET /api/v1/me/portfolio rolls every one of the caller's workflows up
// into a single fleet view: per-workflow health + 30d cost / tokens /
// learning velocity, plus fleet totals. The rest of Studio frames each
// workflow as a Goal scored on a Data casebook, pursued by Runs that
// compound learning; this endpoint answers the portfolio question across
// ALL of them — "how's the fleet doing on health, cost, and learning?"
//
// REUSE, not reinvention:
//   - The workflow enumeration is scheduledWorkflows() from me_workflows.go
//     verbatim — same tenant-tree + operator-shared walk, dedupe, showcase
//     gating, running/recovered logic. We don't re-derive the tenant scan.
//   - Per-cycle cost/tokens/learned come from each cycle dir's cycle.json,
//     read exactly like me_cycle.go (cost.cost_usd / cost.total_tokens and
//     auto_publish.memories[agent].pushed).
//
// Read-only and defensive throughout: a missing dir, an odd cycle.json
// shape, or a bad timestamp never errors the response — it defaults to
// zeros/empty so one broken workflow can't blank the fleet view.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
)

// portfolioCycleScanCap bounds how many of a workflow's cycle dirs we read
// per request. We scan the NEWEST dirs first (dir names are
// "20060102T150405Z", lexicographically sortable == chronological), so the
// 30d window is almost always fully covered by this many. A workflow with
// more than this many cycles INSIDE the 30d window would undercount — the
// response flags that with `scan_capped: true` so the UI can footnote it.
const portfolioCycleScanCap = 30

// PortfolioWorkflow is one workflow's fleet rollup.
type PortfolioWorkflow struct {
	App   string `json:"app"`
	Loop  string `json:"loop"`
	Label string `json:"label,omitempty"` // declared goal.primary, if any
	// health mirrors the dot the rest of Studio shows:
	//   healthy | needs_attention | recovered | paused | never
	Health         string  `json:"health"`
	LastRunTS      float64 `json:"last_run_ts,omitempty"`
	LastRunOK      *bool   `json:"last_run_ok,omitempty"`
	Runs30d        int     `json:"runs_30d"`
	CostUSD30d     float64 `json:"cost_usd_30d"`
	TotalTokens30d float64 `json:"total_tokens_30d"`
	Learned30d     int     `json:"learned_30d"`           // sum of memories pushed across the window's cycles
	AvgDurationS   float64 `json:"avg_duration_s"`        // mean cycle duration over the window (0 when no timed runs)
	ScanCapped     bool    `json:"scan_capped,omitempty"` // window may undercount: >cap cycles in 30d
}

// PortfolioTotals is the fleet headline.
type PortfolioTotals struct {
	Workflows      int     `json:"workflows"`
	Healthy        int     `json:"healthy"`
	NeedsAttention int     `json:"needs_attention"`
	CostUSD30d     float64 `json:"cost_usd_30d"`
	TotalTokens30d float64 `json:"total_tokens_30d"`
	Learned30d     int     `json:"learned_30d"`
	Runs30d        int     `json:"runs_30d"`
}

// MePortfolio serves GET /api/v1/me/portfolio — the cross-workflow fleet view.
func MePortfolio(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// REUSE the exact tenant + operator-shared workflow walk. This already
	// applies dedupe, showcase gating, schedule/goal/enabled overrides, and
	// the journal-truth last-run + running/recovered logic.
	rows := scheduledWorkflows(userID)

	cutoff := float64(time.Now().Add(-30 * 24 * time.Hour).Unix())

	out := make([]PortfolioWorkflow, 0, len(rows))
	totals := PortfolioTotals{}

	for _, w := range rows {
		pw := PortfolioWorkflow{
			App:       w.App,
			Loop:      w.Name,
			Health:    portfolioHealth(w),
			LastRunTS: w.LastRunTS,
			LastRunOK: w.LastRunOK,
		}
		if w.Goal != nil && w.Goal.Primary != "" {
			pw.Label = w.Goal.Primary
		}

		// 30d window — scan this workflow's cycle dirs (newest-first, capped).
		appDir := resolveAppDir(userID, w.App)
		if appDir != "" {
			runs, costUSD, tokens, learned, durSum, durN, capped :=
				scanCycleWindow(filepath.Join(appDir, "data", "cycles", w.Name), cutoff)
			pw.Runs30d = runs
			pw.CostUSD30d = costUSD
			pw.TotalTokens30d = tokens
			pw.Learned30d = learned
			pw.ScanCapped = capped
			if durN > 0 {
				pw.AvgDurationS = durSum / float64(durN)
			}
		}

		// Fleet rollup.
		totals.Workflows++
		switch pw.Health {
		case "healthy":
			totals.Healthy++
		case "needs_attention":
			totals.NeedsAttention++
		}
		totals.CostUSD30d += pw.CostUSD30d
		totals.TotalTokens30d += pw.TotalTokens30d
		totals.Learned30d += pw.Learned30d
		totals.Runs30d += pw.Runs30d

		out = append(out, pw)
	}

	// Stable order: busiest-by-cost first, then most-recent run, then name —
	// the UI may re-sort, but a deterministic default keeps the list calm.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CostUSD30d != out[j].CostUSD30d {
			return out[i].CostUSD30d > out[j].CostUSD30d
		}
		if out[i].LastRunTS != out[j].LastRunTS {
			return out[i].LastRunTS > out[j].LastRunTS
		}
		return out[i].App+out[i].Loop < out[j].App+out[j].Loop
	})

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"workflows": out,
			"totals":    totals,
			"as_of":     time.Now().UTC().Format(time.RFC3339),
			// Scan cap is per-workflow; surfaced so the UI can footnote
			// "windows may undercount very high-frequency loops".
			"cycle_scan_cap": portfolioCycleScanCap,
		},
	})
}

// portfolioHealth maps a WorkflowRow's live fields onto the same five-state
// health vocabulary the dots use elsewhere:
//
//	paused          — workflow disabled
//	never           — no completed run yet
//	recovered       — last run succeeded only via a retry/fallback self-heal
//	needs_attention — last run failed (and hasn't recovered)
//	healthy         — last run clean
//
// (A running cycle keeps the prior health; the fleet view is a rollup, not a
// live light board — /studio/runs owns the live "running" state.)
func portfolioHealth(w WorkflowRow) string {
	if !w.Enabled {
		return "paused"
	}
	if w.LastRunOK == nil {
		return "never"
	}
	if *w.LastRunOK {
		if w.LastRunRecovered {
			return "recovered"
		}
		return "healthy"
	}
	return "needs_attention"
}

// scanCycleWindow reads a loop's cycle dirs newest-first (dir names sort
// chronologically), capped at portfolioCycleScanCap, and aggregates the
// cycles whose timestamp is within the 30d window (ts >= cutoff). It returns
// run count, summed cost_usd, summed total_tokens, summed memories pushed,
// the duration sum + count (for the mean), and whether the cap was hit while
// still inside the window (→ possible undercount). Defensive: a missing dir
// or unparseable cycle.json contributes zero, never an error.
func scanCycleWindow(cyclesLoopDir string, cutoff float64) (
	runs int, costUSD, tokens float64, learned int, durSum float64, durN int, capped bool,
) {
	ents, err := os.ReadDir(cyclesLoopDir)
	if err != nil {
		return
	}
	// Collect dir names, sort newest-first (lexicographic == chronological
	// for the "20060102T150405Z" naming convention).
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	const layout = "20060102T150405Z"
	scanned := 0
	for _, name := range names {
		if scanned >= portfolioCycleScanCap {
			// We stopped early. If the LAST dir we looked at was still inside
			// the window, there may be more in-window cycles below the cap.
			capped = true
			break
		}
		scanned++

		// Window check by dir-name timestamp (cheap — no file read). A name
		// that doesn't parse falls back to a stat-based mtime so odd-named
		// dirs aren't silently dropped from the window.
		var ts float64
		if t, perr := time.Parse(layout, name); perr == nil {
			ts = float64(t.Unix())
		} else if st, serr := os.Stat(filepath.Join(cyclesLoopDir, name)); serr == nil {
			ts = float64(st.ModTime().Unix())
		}
		if ts > 0 && ts < cutoff {
			// Newest-first → once we pass the cutoff, everything older is
			// out of the window too. Stop (not capped — we genuinely reached
			// the window edge).
			break
		}

		// Read cycle.json for cost / tokens / duration / memories — same
		// shape me_cycle.go reads.
		b, rerr := os.ReadFile(filepath.Join(cyclesLoopDir, name, "cycle.json"))
		if rerr != nil {
			continue
		}
		var raw map[string]any
		if json.Unmarshal(b, &raw) != nil {
			continue
		}
		runs++
		if d, ok := raw["duration_s"].(float64); ok && d > 0 {
			durSum += d
			durN++
		}
		if cost, ok := raw["cost"].(map[string]any); ok {
			if v, ok := cost["cost_usd"].(float64); ok {
				costUSD += v
			}
			if v, ok := cost["total_tokens"].(float64); ok {
				tokens += v
			}
		}
		// Memories learned this cycle = sum of auto_publish.memories[*].pushed.
		if ap, ok := raw["auto_publish"].(map[string]any); ok {
			if mem, ok := ap["memories"].(map[string]any); ok {
				for _, v := range mem {
					if m, ok := v.(map[string]any); ok {
						if p, ok := m["pushed"].(float64); ok && p > 0 {
							learned += int(p)
						}
					}
				}
			}
		}
	}
	return
}
