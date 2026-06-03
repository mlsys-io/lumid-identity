package handler

// /api/v1/me/today — the headline summary the new /app/loops page renders
// in its "Today" section. Aggregates across the caller's tenant tree:
//
//   - drafts pending count (from drafts-state.json + outbox enumeration)
//   - last cycle outcome per scheduled loop (from data/journal.jsonl
//     entries with today's UTC date)
//   - quota-paused banner (any journal entry today with a
//     quota_exceeded_* reason — set by the scheduler when a cycle defers)
//
// The shape is deliberately ready-to-render — the UI shouldn't have to
// do its own scanning or aggregation. One round-trip per page load.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// Headline is one bullet in the Today list. The UI maps `kind` to
// presentation (icon, color) but the message text is server-authored
// so wording stays consistent across the web + future CLI surfaces.
type todayHeadline struct {
	Kind    string `json:"kind"`              // brief | drafts | quota_paused | cycle_ok | cycle_failed
	App     string `json:"app,omitempty"`
	Loop    string `json:"loop,omitempty"`
	Ts      string `json:"ts,omitempty"`      // ISO8601; empty for ambient items like "drafts"
	Summary string `json:"summary"`           // one short sentence
	Detail  string `json:"detail,omitempty"`  // optional second line
}

type todayCycleRow struct {
	App         string  `json:"app"`
	Loop        string  `json:"loop"`
	OK          bool    `json:"ok"`
	Ts          string  `json:"ts"`
	DurationS   float64 `json:"duration_s,omitempty"`
	Skipped     bool    `json:"skipped,omitempty"`
	SkipReason  string  `json:"skip_reason,omitempty"`
	LastError   string  `json:"last_error,omitempty"`
	// Engine-revamp observability (B0): the cycle's outcome + how many
	// items are held for human review / offered as compound recall.
	Outcome     string  `json:"outcome,omitempty"`      // ran | no_change | awaiting_review | no_setup
	ReviewCount int     `json:"review_count,omitempty"`
	OffersCount int     `json:"offers_count,omitempty"`
}

// MeToday serves GET /api/v1/me/today.
//
// Reads only the calling user's tenant tree
// (/home/webmaster/.tenants/<sub>/.xp/apps/*/data/...). Operator-shared
// apps are excluded — the Today view is the user's surface, not the
// operator's dashboard.
func MeToday(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	headlines := []todayHeadline{}
	cycles := []todayCycleRow{}
	quotaPausedAlready := false

	// Pending drafts across all installed apps (kind=draft state == pending
	// OR no state entry).
	if n := countPendingDraftsForUser(userID); n > 0 {
		headlines = append(headlines, todayHeadline{
			Kind: "drafts",
			Summary: pluralize(n, "draft is waiting for you.", "drafts are waiting for you."),
		})
	}

	// Walk tenant journals for today's UTC date. Per-app, we keep the
	// most recent journal entry for each loop and translate it into
	// a headline.
	tenantApps := tenantAppsDir(userID)
	dirs, _ := os.ReadDir(tenantApps)
	todayStart := common.TodayBound()

	for _, d := range dirs {
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		appName := d.Name()
		journal := filepath.Join(tenantApps, appName, "data", "journal.jsonl")
		rows := readTodayJournal(journal, todayStart)
		// Group by loop; keep the latest per loop.
		latest := map[string]map[string]any{}
		for _, r := range rows {
			loop, _ := r["loop"].(string)
			if loop == "" {
				continue
			}
			latest[loop] = r
		}
		for loop, r := range latest {
			row := todayCycleRow{App: appName, Loop: loop}
			row.OK, _ = r["ok"].(bool)
			row.Ts, _ = r["iso"].(string)
			if row.Ts == "" {
				row.Ts, _ = r["ts"].(string) // app_runner journal shape
			}
			if v, exists := r["duration_s"].(float64); exists {
				row.DurationS = v
			}
			row.Skipped, _ = r["skipped"].(bool)
			if v, exists := r["reason"].(string); exists {
				row.SkipReason = v
			}
			if v, exists := r["error"].(string); exists {
				row.LastError = v
			}
			// B0 observability fields (present on cycles run by the
			// revamped engine; absent on older journal lines).
			if v, exists := r["outcome"].(string); exists {
				row.Outcome = v
			}
			if v, exists := r["review_queue"].(float64); exists {
				row.ReviewCount = int(v)
			}
			if v, exists := r["offers"].(float64); exists {
				row.OffersCount = int(v)
			}
			cycles = append(cycles, row)

			// Translate the most informative cycle into a Today bullet.
			// Priority: quota_paused > failed > brief-shaped success.
			if row.Skipped && strings.HasPrefix(row.SkipReason, "quota_exceeded") && !quotaPausedAlready {
				headlines = append(headlines, todayHeadline{
					Kind:    "quota_paused",
					App:     appName,
					Loop:    loop,
					Ts:      row.Ts,
					Summary: "Free tier reached today.",
					Detail:  "Your AI resumes at midnight UTC, or add ANTHROPIC_API_KEY in Account to upgrade.",
				})
				quotaPausedAlready = true
			} else if row.OK && isBriefLoop(loop) {
				headlines = append(headlines, todayHeadline{
					Kind:    "brief",
					App:     appName,
					Loop:    loop,
					Ts:      row.Ts,
					Summary: "Your " + humanizeLoop(loop) + " is ready.",
				})
			} else if !row.OK && !row.Skipped {
				headlines = append(headlines, todayHeadline{
					Kind:    "cycle_failed",
					App:     appName,
					Loop:    loop,
					Ts:      row.Ts,
					Summary: humanizeLoop(loop) + " didn't run cleanly.",
					Detail:  truncate(row.LastError, 200),
				})
			}
		}
	}

	// Sort headlines: quota first (action-required), then brief (good news),
	// then drafts, then failures (least pleasant last).
	sort.SliceStable(headlines, func(i, j int) bool {
		return todayKindOrder(headlines[i].Kind) < todayKindOrder(headlines[j].Kind)
	})

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"headlines": headlines,
			"cycles":    cycles,
			"as_of":     time.Now().UTC().Format(time.RFC3339),
		},
	})
}

func todayKindOrder(kind string) int {
	switch kind {
	case "quota_paused":
		return 0
	case "drafts":
		return 1
	case "brief":
		return 2
	case "cycle_ok":
		return 3
	case "cycle_failed":
		return 4
	default:
		return 5
	}
}

// readTodayJournal walks data/journal.jsonl line-by-line and returns
// today's entries as parsed dicts. Tolerates malformed lines (skips them).
// Today = anything with ts >= midnight UTC OR iso starting with today's date.
func readTodayJournal(path string, todayStart time.Time) []map[string]any {
	out := []map[string]any{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// Journal lines can be longer than the default 64KB scanner buffer;
	// cycle summaries with embedded text occasionally hit this. Bump to
	// 1MB which covers anything practical without burning memory.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	todayStartUnix := float64(todayStart.Unix())
	todayPrefix := todayStart.Format("2006-01-02")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		// Two acceptable shapes: numeric ts (unix float) or iso string.
		// Either must match today.
		if ts, ok := row["ts"].(float64); ok {
			if ts >= todayStartUnix {
				out = append(out, row)
				continue
			}
		}
		if iso, ok := row["iso"].(string); ok {
			if strings.HasPrefix(iso, todayPrefix) {
				out = append(out, row)
				continue
			}
		}
		// app_runner journals write `ts` as an ISO8601 STRING (not a unix
		// float and not under an `iso` key). Match those too.
		if tss, ok := row["ts"].(string); ok {
			if strings.HasPrefix(tss, todayPrefix) {
				out = append(out, row)
				continue
			}
		}
	}
	return out
}

// countPendingDraftsForUser walks the tenant outbox tree once and
// returns the number of drafts whose state is pending (or absent).
// Reuses the same disk layout MeDraftsList does.
func countPendingDraftsForUser(userSub string) int {
	tenantApps := tenantAppsDir(userSub)
	dirs, err := os.ReadDir(tenantApps)
	if err != nil {
		return 0
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		appDir := filepath.Join(tenantApps, d.Name())
		stateMap := loadStateMap(appDir)
		outboxRoot := filepath.Join(appDir, "data", "outbox")
		tsDirs, _ := os.ReadDir(outboxRoot)
		for _, td := range tsDirs {
			if !td.IsDir() {
				continue
			}
			draftsDir := filepath.Join(outboxRoot, td.Name(), "drafts")
			files, _ := os.ReadDir(draftsDir)
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				abs := filepath.Join(draftsDir, f.Name())
				rel, _ := filepath.Rel(appDir, abs)
				id := draftID(rel)
				st := stateMap[id]
				if st.State == "" || st.State == "pending" {
					n++
				}
			}
		}
	}
	return n
}

// Loop name → human-friendly verb. Kept in code (not config) so the
// strings ship with the bundle and don't need per-tenant translation
// during dogfood. Localisation moves to the UI layer when we have it.
func humanizeLoop(loop string) string {
	switch loop {
	case "morning_brief":
		return "morning brief"
	case "hourly_triage":
		return "hourly triage"
	case "weekly_reflection":
		return "weekly reflection"
	case "cc_watcher":
		return "Claude Code watcher"
	}
	// Convert snake_case → "snake case" as a generic fallback.
	return strings.ReplaceAll(loop, "_", " ")
}

func isBriefLoop(loop string) bool {
	switch loop {
	case "morning_brief", "weekly_reflection":
		return true
	}
	return false
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconvItoa(n) + " " + plural
}

// Pull strconv via a thin alias to keep the import block tidy.
func strconvItoa(n int) string {
	return strconv.Itoa(n)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
