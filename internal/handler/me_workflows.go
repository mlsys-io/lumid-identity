// /me/workflows — the unified workflow surface (W1).
//
// Aggregates three sources behind a single response shape so Studio's
// /studio/workflows page renders one table:
//   1. Scheduled — xpio loops walked from the user's tenant tree +
//      operator-shared ~/.xp/apps/. Reuses AdminLoops' loopRow scan.
//   2. Visual — n8n workflows fetched via the REST API (W1 best-effort
//      without SSO; an empty list is normal until W2 lands the bridge).
//   3. Skill (catalog-only kind) — not enumerated here. The Studio
//      "Available" lens hits /api/v1/skills/catalog directly.
//
// Tenant-isolated by construction: scheduled rows are scoped to the
// caller's ~/.tenants/<sub>/ tree via the same MeLoopsHealth path; the
// n8n REST call uses the caller's session cookie when forwarded.

package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
)

// MeLoopDelete hard-removes a single workflow (loop) from one of the caller's
// OWN apps — drops it from xpcloud.yaml::loops[] (and manifest.json::loops[]
// if present) and deletes its cycle history. The lumid-scheduler unregisters
// the apscheduler job on its next discovery pass. Synchronous (identity runs
// as the operator uid and writes the tenant tree directly — no intent queue).
//
// Guards: tenant apps only (operator-shared xpcloud.yaml lives in the operator
// home and must not be edited per-user); refuses to remove the LAST loop (an
// app with zero workflows is meaningless — delete the app instead).
func MeLoopDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || loop == "" {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop")
		return
	}
	appDir := filepath.Join(tenantAppsDir(userID), app)
	xpPath := filepath.Join(appDir, "xpcloud.yaml")
	b, err := os.ReadFile(xpPath)
	if err != nil {
		fail(c, http.StatusNotFound, 1404,
			"app not found in your account (operator-shared apps can't be edited)")
		return
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "parse xpcloud.yaml: "+err.Error())
		return
	}
	rawLoops, _ := doc["loops"].([]any)
	kept := make([]any, 0, len(rawLoops))
	found := false
	for _, l := range rawLoops {
		lm, _ := l.(map[string]any)
		name, _ := lm["name"].(string)
		if name == loop {
			found = true
			continue
		}
		kept = append(kept, l)
	}
	if !found {
		fail(c, http.StatusNotFound, 1404, "workflow '"+loop+"' not found in "+app)
		return
	}
	if len(kept) == 0 {
		fail(c, http.StatusBadRequest, 1409,
			"can't remove the last workflow — delete the app instead")
		return
	}
	doc["loops"] = kept
	out, err := yaml.Marshal(doc)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "marshal: "+err.Error())
		return
	}
	if err := os.WriteFile(xpPath, out, 0o644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write xpcloud.yaml: "+err.Error())
		return
	}
	// Mirror into manifest.json::loops[] if it carries them (legacy shape).
	if mb, err := os.ReadFile(filepath.Join(appDir, "manifest.json")); err == nil {
		var mj map[string]any
		if json.Unmarshal(mb, &mj) == nil {
			if ml, ok := mj["loops"].([]any); ok {
				keptM := make([]any, 0, len(ml))
				for _, l := range ml {
					lm, _ := l.(map[string]any)
					if n, _ := lm["name"].(string); n == loop {
						continue
					}
					keptM = append(keptM, l)
				}
				mj["loops"] = keptM
				if nb, e := json.MarshalIndent(mj, "", "  "); e == nil {
					_ = os.WriteFile(filepath.Join(appDir, "manifest.json"), nb, 0o644)
				}
			}
		}
	}
	// ARCHIVE the loop's cycle history (don't destroy) so "walk me through
	// run X" stays answerable after a workflow delete. Move it into
	// .xp/.trash/<app>/<loop>-<ts>/ (dot-dir → skipped by the apps scan).
	srcCycles := filepath.Join(appDir, "data", "cycles", loop)
	if _, err := os.Stat(srcCycles); err == nil {
		trashDir := filepath.Join(tenantAppsDir(userID), "..", ".trash", app)
		_ = os.MkdirAll(trashDir, 0o755)
		dest := filepath.Join(trashDir, fmt.Sprintf("%s-%d", loop, time.Now().Unix()))
		if err := os.Rename(srcCycles, dest); err != nil {
			_ = os.RemoveAll(srcCycles) // fallback: still remove from the live tree
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app": app, "removed_loop": loop, "remaining": len(kept),
			"note": "scheduler unregisters this workflow within a few minutes",
		},
	})
}

// readAppVersion reads an app's version from manifest.json (preferred) or
// xpcloud.yaml. Used so EVERY card carries a version badge — loadAppGitStatus
// only reads the operator home, so tenant apps were version-less without this.
func readAppVersion(appDir string) string {
	if b, err := os.ReadFile(filepath.Join(appDir, "manifest.json")); err == nil {
		var m struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &m) == nil && m.Version != "" {
			return m.Version
		}
	}
	if b, err := os.ReadFile(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
		var m struct {
			Version string `yaml:"version"`
		}
		if yaml.Unmarshal(b, &m) == nil {
			return m.Version
		}
	}
	return ""
}

// showcaseApps returns the set of operator-shared app slugs that should
// appear on the home grid for every user (the curated demo set). Backend-
// driven so the list can change WITHOUT a frontend rebuild — the old
// RUNNING_APPS constant was baked into the JS bundle. Override via the
// LUMID_SHOWCASE_APPS env var (comma-separated); defaults to the canonical
// showcase. A user's OWN tenant apps always show regardless of this list.
// userIsAdmin reports whether the user holds an operator-level role.
// One indexed-PK lookup; callers are list endpoints, not hot paths.
func userIsAdmin(userID string) bool {
	var role string
	common.DB.Raw(`SELECT role FROM users WHERE id = ? LIMIT 1`, userID).Scan(&role)
	return role == "admin" || role == "super_admin"
}

func showcaseApps() map[string]bool {
	raw := os.Getenv("LUMID_SHOWCASE_APPS")
	if strings.TrimSpace(raw) == "" {
		raw = "personal-agent,mbb-ai,auto-sysresearch,auto-quant"
	}
	out := map[string]bool{}
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out[s] = true
		}
	}
	return out
}

// WorkflowRow is the unified per-workflow record the UI consumes.
type WorkflowRow struct {
	Slug         string `json:"slug"`           // unique within tenant: "<app>:<name>" or "n8n:<id>"
	Kind         string `json:"kind"`           // "scheduled" | "visual"
	Name         string `json:"name"`           // display name (loop name or n8n workflow name)
	App          string `json:"app,omitempty"`  // for scheduled
	Trigger      string `json:"trigger"`        // human-readable
	Enabled      bool   `json:"enabled"`
	Tenant       bool   `json:"tenant"`         // true = tenant-installed; false = operator-shared
	Showcase     bool   `json:"showcase"`       // operator-shared app on the backend showcase list (curates the home grid without a frontend rebuild)
	Version      string `json:"version,omitempty"` // app version (manifest.json/xpcloud.yaml) — surfaced so EVERY card shows a version badge, incl. tenant apps loadAppGitStatus can't see
	// Experiments this workflow is attached to (steps[].experiment /
	// engine.experiment) — drives the flask chip in the detail card.
	ExperimentIDs []string `json:"experiment_ids,omitempty"`
	LastRunTS    float64 `json:"last_run_ts,omitempty"`
	LastRunOK    *bool   `json:"last_run_ok,omitempty"`
	NextRunTS    float64 `json:"next_run_ts,omitempty"`
	Description  string `json:"description,omitempty"`
	Engine       string `json:"engine,omitempty"`        // "runner_steps" | "command:<verb>" (scheduled)
	StepCount    int    `json:"step_count,omitempty"`
	N8nID        string `json:"n8n_id,omitempty"`        // for kind=visual
	// Sparkline of recent run states (W5+ visual polish). One char per
	// run, oldest→newest, last 14 runs max. Encoding: "."=skipped,
	// "✓"=succeeded, "✗"=failed, "·"=running. The UI renders these as
	// state-colored squares. Empty when no journal entries exist.
	RunSpark string `json:"run_spark,omitempty"`
	// G2 — month-to-date cost in cents from usage_events. 0 when the
	// workflow hasn't generated any server-funded LLM/external-API
	// usage this month (visual workflows that run entirely client-side
	// will be 0 here). Omitted from JSON when 0 for clean responses.
	CostCentsMTD int `json:"cost_cents_mtd,omitempty"`
	// Running — a cycle is in-progress right now: the loop's newest cycle
	// dir is newer than its last completed journal entry (a cycle creates
	// its dir at start, journals on completion). Lets the dashboard show a
	// live "running" indicator so long loops don't look frozen/stale.
	Running bool `json:"running,omitempty"`
	// LastRunRecovered — the last completed run succeeded but only after a
	// retry/fallback self-healed an LLM call. Dashboard shows an amber dot
	// (flaky-but-recovering) instead of clean green.
	LastRunRecovered bool `json:"last_run_recovered,omitempty"`
	// RunsRecent — per-dot addressing for the sparkline. One entry per
	// run_spark char, SAME order (oldest→newest), so the UI can make each
	// dot clickable: hover/click → open that cycle's detail. `Ts` is the
	// cycle dir-id (matches GET /me/cycles/:app/:loop/:ts) resolved by
	// nearest-start match (the journal logs completion, the dir is named
	// from cycle start ~seconds earlier). Empty `Ts` = no cycle dir found
	// (e.g. a skipped run) → that dot stays non-clickable.
	RunsRecent []SparkRun `json:"runs_recent,omitempty"`
	// Goal — the loop's declared objective from xpcloud.yaml (goal.primary +
	// tracked metric names). Drives the app-overview goal header so users see
	// what the loop is chasing, not just a generic description.
	Goal *WorkflowGoal `json:"goal,omitempty"`
	// Datasets — dataset ids/refs the loop runs against (xpcloud.yaml).
	Datasets []string `json:"datasets,omitempty"`
	// MemoryAgents — the app's knowledge agents (xpcloud.yaml top-level
	// memory_agents + roles[].memory_agent). Powers the learning-history
	// timeline (what the app has banked over time). App-level, repeated on
	// each of the app's loop rows for the UI's convenience.
	MemoryAgents []string `json:"memory_agents,omitempty"`
}

// WorkflowGoal mirrors xpcloud.yaml loops[].goal.
type WorkflowGoal struct {
	Primary string   `json:"primary"`
	Tracked []string `json:"tracked,omitempty"`
}

// SparkRun is one addressable dot in a workflow's run sparkline.
type SparkRun struct {
	Ts string `json:"ts"` // cycle dir-id, "" when unmatched
	St string `json:"st"` // state char: o|r|x|_|.  (mirrors run_spark)
}

// MeWorkflows — GET /me/workflows[?kind=scheduled|visual]
//
// Optional kind filter narrows to one source; default returns the union.
func MeWorkflows(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	kindFilter := strings.TrimSpace(c.Query("kind"))

	rows := make([]WorkflowRow, 0, 32)

	// Run the two sources CONCURRENTLY — the scheduled scan is filesystem-bound
	// (tenant + operator app trees) and the visual fetch is an n8n HTTP round-
	// trip; running them sequentially made /me/workflows the slowest aggregate
	// on the apps page (~400ms = fs + n8n). max() instead of sum(). The main
	// goroutine only reads c inside the worker (cookie/request ctx) while
	// blocked on Wait, so there's no concurrent gin.Context write.
	var sched, vis []WorkflowRow
	var wg sync.WaitGroup
	// 1. Scheduled — the caller's tenant tree + operator-shared xpio loops.
	if kindFilter == "" || kindFilter == "scheduled" {
		wg.Add(1)
		go func() { defer wg.Done(); sched = scheduledWorkflows(userID) }()
	}
	// 2. Visual — n8n. Soft-fail on unauthenticated (W1 norm); empty until the
	//    user signs into n8n directly.
	if kindFilter == "" || kindFilter == "visual" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
			defer cancel()
			vis = visualWorkflows(ctx, c)
		}()
	}
	wg.Wait()
	rows = append(rows, sched...)
	rows = append(rows, vis...)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"workflows": rows,
			"count":     len(rows),
			"as_of":     time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// scheduledWorkflows walks the tenant + operator app trees and returns
// one WorkflowRow per xpio loop (post-coalesce, so workflows: entries
// are included as scheduled rows too).
func scheduledWorkflows(userID string) []WorkflowRow {
	out := []WorkflowRow{}
	// One DB hit for the user's month-to-date costs, keyed by
	// `endpoint = <app>.<loop>`. Distributed lookup-by-key in the
	// row-build loop below.
	costMap := fetchCostsByEndpoint(userID)

	showcase := showcaseApps()        // backend-driven home-grid curation
	seenTenantApps := map[string]bool{} // dedupe: tenant app shadows operator-shared
	privileged := userIsAdmin(userID)   // admins see all operator loops; users only showcase

	scan := func(appsRoot string, isTenant bool) {
		entries, err := os.ReadDir(appsRoot)
		if err != nil {
			return
		}
		state := readSchedulerState(operatorHome())
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			// Dedupe: when the caller's tenant has an app of the same name as
			// an operator-shared one, the tenant copy wins — skip the operator
			// dup so the UI doesn't merge both into one card (the auto-quant
			// collision). Tenant pass runs first and records names.
			if isTenant {
				seenTenantApps[e.Name()] = true
			} else if seenTenantApps[e.Name()] {
				continue
			}
			// Privacy: the operator tree carries personal/ops loops
			// (yao-agent, lqt-mailbox, skill-ci, …). Plain users only get
			// the curated showcase set; everything else is operator-private.
			if !isTenant && !privileged && !showcase[e.Name()] {
				continue
			}
			appDir := filepath.Join(appsRoot, e.Name())
			loops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml"))
			if err != nil || len(loops) == 0 {
				// Try manifest.json fallback.
				loops, _ = readManifestLoops(filepath.Join(appDir, "manifest.json"))
			}
			if len(loops) == 0 {
				continue
			}
			memAgents := readYamlMemoryAgents(filepath.Join(appDir, "xpcloud.yaml"))
			appVersion := readAppVersion(appDir)
			// Tolerant goal read — survives loops whose other fields break the
			// full rawLoop parse (object-typed datasets/skills_invoked).
			goalsByLoop := readYamlLoopGoals(filepath.Join(appDir, "xpcloud.yaml"))
			enabledMap := readEnabledOverrides(filepath.Join(appDir, ".user-overrides.yaml"))
			scheduleMap := readScheduleOverrides(filepath.Join(appDir, ".user-overrides.yaml"))
			for _, L := range loops {
				if L.Name == "" {
					continue
				}
				if s, ok := scheduleMap[L.Name]; ok {
					L.Schedule = s
				}
				// Scheduler job-ids are tenant-scoped for tenant installs
				// (xpio:<sub[:8]>:<app>:<loop>, see xpio_scheduler.job_id).
				// Looking up the unprefixed key for a tenant row would
				// inherit the OPERATOR's stale run state — a fresh install
				// must read "no runs yet", not someone else's failures.
				jobID := "xpio:" + e.Name() + ":" + L.Name
				if isTenant {
					sub := userID
					if len(sub) > 8 {
						sub = sub[:8]
					}
					jobID = "xpio:" + sub + ":" + e.Name() + ":" + L.Name
				}
				s := state.Loops[jobID]
				enabled := true
				if v, ok := enabledMap[L.Name]; ok {
					enabled = v
				}
				engine := "runner_steps"
				if L.Engine.Type != "" {
					engine = L.Engine.Type
					if L.Engine.Module != "" {
						engine += ":" + L.Engine.Module
					}
				}
				row := WorkflowRow{
					Slug:         e.Name() + ":" + L.Name,
					Kind:         "scheduled",
					Name:         L.Name,
					App:          e.Name(),
					Trigger:      L.Schedule,
					Enabled:      enabled,
					Tenant:       isTenant,
					Showcase:     showcase[e.Name()],
					Version:      appVersion,
					LastRunTS:    s.LastRunTS,
					Description:  L.Description,
					Engine:       engine,
					StepCount:    len(L.Steps),
					CostCentsMTD: costMap[e.Name()+"."+L.Name],
				}
				// Experiments attached to this loop (flask chip).
				expIDs := map[string]bool{}
				if L.Engine.Experiment != "" {
					expIDs[L.Engine.Experiment] = true
				}
				for _, st := range L.Steps {
					if st.Experiment != "" {
						expIDs[st.Experiment] = true
					}
				}
				for eid := range expIDs {
					row.ExperimentIDs = append(row.ExperimentIDs, eid)
				}
				row.RunSpark, row.RunsRecent = buildRunSparkDetailed(
					filepath.Join(appDir, "data", "journal.jsonl"),
					filepath.Join(appDir, "data", "cycles", L.Name),
					L.Name, 14)
				if g, ok := goalsByLoop[L.Name]; ok {
					row.Goal = &WorkflowGoal{Primary: g.Primary, Tracked: g.Tracked}
				} else if L.Goal.Primary != "" || len(L.Goal.Tracked) > 0 {
					row.Goal = &WorkflowGoal{Primary: L.Goal.Primary, Tracked: L.Goal.Tracked}
				}
				row.Datasets = []string(L.Datasets)
				row.MemoryAgents = memAgents
				if s.LastOk != nil {
					b := *s.LastOk
					row.LastRunOK = &b
				}
				// The scheduler state file is operator-scoped and goes stale
				// for tenant loops (frozen at the last operator run). The
				// per-app journal is the real run log — prefer it so
				// last-run reflects what actually ran.
				if jts, jok, ok := lastRunFromJournal(filepath.Join(appDir, "data", "journal.jsonl"), L.Name); ok {
					row.LastRunTS = jts
					row.LastRunOK = &jok
				}
				row.Running = loopRunning(appDir, L.Name, row.LastRunTS)
				row.LastRunRecovered = lastRunRecovered(filepath.Join(appDir, "data", "journal.jsonl"), L.Name)
				out = append(out, row)
			}
		}
	}

	// Tenant first so Studio shows the user's own workflows on top.
	scan(tenantAppsDir(userID), true)
	scan(filepath.Join(operatorHome(), ".xp", "apps"), false)
	return out
}

// visualWorkflows hits the n8n REST API and maps the result to
// WorkflowRow. Returns an empty slice on auth failure (W1 norm).
func visualWorkflows(ctx context.Context, c *gin.Context) []WorkflowRow {
	cli := common.NewN8nClient()
	// Forward the user's n8n session cookie if the browser sent one.
	// Pre-W2 SSO this is typically empty; n8n returns 401 → soft-fail.
	cookie, _ := c.Cookie("n8n-auth")
	wfs, err := cli.ListWorkflows(ctx, cookie)
	if err != nil {
		return nil
	}
	out := make([]WorkflowRow, 0, len(wfs))
	for _, w := range wfs {
		trigger := "manual"
		// Heuristic: an n8n workflow with a Cron node trigger is
		// scheduled; otherwise treat as manual/webhook.
		for _, n := range w.Nodes {
			if strings.Contains(strings.ToLower(n.Type), "cron") ||
				strings.Contains(strings.ToLower(n.Type), "schedule") {
				trigger = "cron"
				break
			}
			if strings.Contains(strings.ToLower(n.Type), "webhook") {
				trigger = "webhook"
				break
			}
		}
		out = append(out, WorkflowRow{
			Slug:      "n8n:" + w.ID,
			Kind:      "visual",
			Name:      w.Name,
			Trigger:   trigger,
			Enabled:   w.Active,
			Tenant:    true,
			StepCount: len(w.Nodes),
			N8nID:     w.ID,
		})
	}
	return out
}

// fetchCostsByEndpoint returns a map of "<app>.<loop>" → month-to-date
// cost in cents for one user. One SQL aggregation. Empty map on error
// (don't fail the whole /me/workflows response on a missing usage_events
// table or no rows).
func fetchCostsByEndpoint(userSub string) map[string]int {
	out := map[string]int{}
	if common.DB == nil {
		return out
	}
	now := time.Now().UTC()
	mtd := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	rows := []struct {
		Endpoint string
		Cents    int
	}{}
	err := common.DB.Raw(`
		SELECT endpoint AS endpoint,
		       COALESCE(SUM(cost_cents), 0) AS cents
		FROM   usage_events
		WHERE  user_sub = ?
		  AND  ts >= ?
		  AND  kind = 'cycle_llm'
		  AND  endpoint IS NOT NULL
		  AND  endpoint <> ''
		GROUP  BY endpoint`, userSub, mtd).Scan(&rows).Error
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.Endpoint] = r.Cents
	}
	return out
}

// buildRunSpark scans the per-app journal for entries matching `loop`,
// and returns a compact string (oldest→newest, max `limit` chars) where
// each character encodes one run's state. The UI renders this as a row
// of state-colored squares (a sparkline) for "how has this gone lately".
// lastRunFromJournal returns the unix ts + ok of the most recent journal
// entry for `loop`, and whether any was found. Source of truth for "when
// did this actually last run" (the scheduler state file is operator-scoped
// and stale for tenant loops).
// loopRunning reports whether a cycle is in-progress: the loop's newest
// cycle dir (created at cycle start) is newer than its last completed
// journal entry (written at cycle end). The recency cap avoids reporting
// a crashed-cycle leftover dir as "running" forever.
func loopRunning(appDir, loop string, lastJTS float64) bool {
	ents, err := os.ReadDir(filepath.Join(appDir, "data", "cycles", loop))
	if err != nil {
		return false
	}
	var newest float64
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil {
			if m := float64(info.ModTime().Unix()); m > newest {
				newest = m
			}
		}
	}
	if newest == 0 {
		return false
	}
	now := float64(time.Now().Unix())
	return newest > lastJTS+5 && now-newest < 1800
}

// lastRunRecovered reports whether the most recent COMPLETED run of loop
// self-healed (recovered=true) — succeeded only via a retry/fallback. Drives
// the amber "recovered" dot, distinct from clean green.
func lastRunRecovered(journalPath, loop string) bool {
	f, err := os.Open(journalPath)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	rec := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if lp, _ := row["loop"].(string); lp != loop {
			continue
		}
		if _, hasOk := row["ok"]; !hasOk {
			continue // intermediate/stage entry, not a completed run
		}
		r, _ := row["recovered"].(bool)
		rec = r // keep the last completed run's flag
	}
	return rec
}

func lastRunFromJournal(journalPath, loop string) (float64, bool, bool) {
	f, err := os.Open(journalPath)
	if err != nil {
		return 0, false, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var bestTs float64
	var bestOk bool
	found := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if lp, _ := row["loop"].(string); lp != loop {
			continue
		}
		ts := rowUnixTs(row)
		if ts >= bestTs {
			bestTs = ts
			ok, _ := row["ok"].(bool)
			bestOk = ok
			found = true
		}
	}
	return bestTs, bestOk, found
}

// buildRunSpark returns just the char string (back-compat shim).
func buildRunSpark(journalPath, loop string, limit int) string {
	spark, _ := buildRunSparkDetailed(journalPath, "", loop, limit)
	return spark
}

// buildRunSparkDetailed returns the char string AND a per-dot SparkRun
// slice (same order) carrying each run's cycle dir-id, so the UI can make
// dots clickable. `cyclesLoopDir` is data/cycles/<loop> (pass "" to skip
// dir resolution — runs[] then carry empty Ts). Matching: the journal logs
// completion ts; the cycle dir is named from start (~seconds earlier), so
// each run maps to the dir with the largest start ≤ completion within a 6h
// window.
func buildRunSparkDetailed(journalPath, cyclesLoopDir, loop string, limit int) (string, []SparkRun) {
	f, err := os.Open(journalPath)
	if err != nil {
		return "", nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	type pair struct{ ts float64; ch byte }
	rows := []pair{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
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
		var ch byte = '.'
		rec, _ := row["recovered"].(bool)
		if skipped, _ := row["skipped"].(bool); skipped {
			ch = '_'
		} else if rec {
			// amber: self-fix / transient class — a run that succeeded via
			// retry/fallback, OR a past transient failure (504/no_output/
			// network) backfilled as "would-self-heal-now".
			ch = 'r'
		} else if ok, _ := row["ok"].(bool); ok {
			ch = 'o'
		} else {
			ch = 'x'
		}
		rows = append(rows, pair{ts: ts, ch: ch})
	}
	// Sort newest-first, take limit, then reverse so output is oldest→newest.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ts > rows[j].ts })
	if len(rows) > limit {
		rows = rows[:limit]
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	// Resolved-failure → amber: a failure the loop later recovered from (a
	// success exists after it in the window) is past history, not a current
	// problem — show it amber ('r'), not red. Only an UNRESOLVED trailing
	// failure (no later success) stays red ('x'). Walk newest→oldest.
	seenOk := false
	for i := len(rows) - 1; i >= 0; i-- {
		switch rows[i].ch {
		case 'o', 'r':
			seenOk = true
		case 'x':
			if seenOk {
				rows[i].ch = 'r'
			}
		}
	}
	out := make([]byte, len(rows))
	for i, p := range rows {
		out[i] = p.ch
	}

	// Resolve each dot to its cycle dir-id (for clickable dots). Read the
	// loop's cycle dirs once, parse names → start unix, sort ascending,
	// then for each run pick the dir with the largest start ≤ completion.
	runs := make([]SparkRun, len(rows))
	type cdir struct{ start float64; id string }
	var dirs []cdir
	if cyclesLoopDir != "" {
		if ents, err := os.ReadDir(cyclesLoopDir); err == nil {
			for _, e := range ents {
				if !e.IsDir() {
					continue
				}
				if t, err := time.Parse("20060102T150405Z", e.Name()); err == nil {
					dirs = append(dirs, cdir{start: float64(t.Unix()), id: e.Name()})
				}
			}
			sort.Slice(dirs, func(i, j int) bool { return dirs[i].start < dirs[j].start })
		}
	}
	for i, p := range rows {
		runs[i].St = string(p.ch)
		// largest start ≤ completion, within a 6h window (skip stale mismatch).
		best := -1
		for d := range dirs {
			if dirs[d].start <= p.ts+1 {
				best = d
			} else {
				break
			}
		}
		if best >= 0 && p.ts-dirs[best].start < 6*3600 {
			runs[i].Ts = dirs[best].id
		}
	}
	return string(out), runs
}

// readEnabledOverrides — read just the per-loop `enabled` flag from
// .user-overrides.yaml. Tolerates missing file (returns empty map).
func readEnabledOverrides(path string) map[string]bool {
	out := map[string]bool{}
	overrides := readSimpleOverrides(path)
	loopsMap, _ := overrides["loops"].(map[string]any)
	for name, v := range loopsMap {
		settings, _ := v.(map[string]any)
		if en, ok := settings["enabled"].(bool); ok {
			out[name] = en
		}
	}
	return out
}

// readScheduleOverrides returns per-loop schedule overrides from
// .user-overrides.yaml (written by MeLoopPatch + the chat agent's
// patch_loop). The scheduler merges these at discovery; the workflow
// list must show the SAME effective schedule or a chat-patched
// schedule looks like it silently failed.
func readScheduleOverrides(path string) map[string]string {
	out := map[string]string{}
	overrides := readSimpleOverrides(path)
	loopsMap, _ := overrides["loops"].(map[string]any)
	for name, v := range loopsMap {
		settings, _ := v.(map[string]any)
		if s, ok := settings["schedule"].(string); ok && s != "" {
			out[name] = s
		}
	}
	return out
}

// MeWorkflowDetail — GET /me/workflows/:slug
//
// Returns the full definition + last N runs + step metadata. Slug
// shape: "<app>:<loop>" for scheduled, "n8n:<id>" for visual.
func MeWorkflowDetail(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	slug := c.Param("slug")
	parts := strings.SplitN(slug, ":", 2)
	if len(parts) != 2 {
		fail(c, http.StatusBadRequest, 1400, "invalid slug")
		return
	}

	if parts[0] == "n8n" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		cli := common.NewN8nClient()
		cookie, _ := c.Cookie("n8n-auth")
		wf, err := cli.GetWorkflow(ctx, parts[1], cookie)
		if err != nil {
			fail(c, http.StatusBadGateway, 1500, "n8n: "+err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"slug":       slug,
				"kind":       "visual",
				"definition": wf,
			},
		})
		return
	}

	// scheduled: parts[0] = app, parts[1] = loop
	app, loop := parts[0], parts[1]
	// Read the app's xpcloud.yaml from tenant tree (or operator-shared
	// as fallback) and surface the matching loop entry verbatim.
	loops, src := readLoopsFromAnywhere(userID, app)
	for _, L := range loops {
		if L.Name == loop {
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{
					"slug":         slug,
					"kind":         "scheduled",
					"app":          app,
					"loop":         loop,
					"source":       src,
					"definition":   L,
				},
			})
			return
		}
	}
	fail(c, http.StatusNotFound, 1404, "workflow not found")
}

// MeImportFromN8n — POST /me/workflows/import-from-n8n
//
// Best-effort translator: given an n8n workflow ID, fetch its JSON
// via the n8n client and translate to a tenant xpcloud.yaml. Unknown
// node types become TODO shells in skill_imports[] so the user can
// fix them up in the YAML editor.
//
// Body: {n8n_id: string, target_slug?: string}
//
// Returns: {draft_slug, draft_dir, n8n_id, unsupported_nodes[]}
func MeImportFromN8n(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		N8nID       string `json:"n8n_id"`
		TargetSlug  string `json:"target_slug"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.N8nID == "" {
		fail(c, http.StatusBadRequest, 1400, "n8n_id required")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
	defer cancel()
	cli := common.NewN8nClient()
	cookie, _ := c.Cookie("n8n-auth")
	wf, err := cli.GetWorkflow(ctx, body.N8nID, cookie)
	if err != nil {
		fail(c, http.StatusBadGateway, 1500, "n8n: "+err.Error())
		return
	}

	slug := body.TargetSlug
	if slug == "" {
		slug = "n8n-" + body.N8nID
	}

	yaml, unsupported := translateN8nToXpcloud(wf, slug)

	draftDir := filepath.Join(tenantAppsDir(userID), slug)
	if err := os.MkdirAll(draftDir, 0o775); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "draft dir: "+err.Error())
		return
	}
	if err := os.WriteFile(filepath.Join(draftDir, "xpcloud.yaml"), []byte(yaml), 0o644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write yaml: "+err.Error())
		return
	}
	manifest := map[string]any{
		"name": slug, "kind": "app", "version": "0.1.0",
		"description": "Promoted from n8n workflow " + body.N8nID,
		"fork_of":     "n8n:" + body.N8nID,
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(draftDir, "manifest.json"), manifestBytes, 0o644)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"draft_slug":         slug,
			"draft_dir":          draftDir,
			"n8n_id":             body.N8nID,
			"unsupported_nodes":  unsupported,
			"note":               "Promoted as a draft. Open /studio/workflows to install + adjust.",
		},
	})
}

// translateN8nToXpcloud — best-effort node-type mapping. Returns the
// generated YAML + a list of unsupported node names (rendered as
// TODO shells in skill_imports[] so the user can fix them up).
//
// v1 supports: HTTP Request, Code, Schedule trigger, Webhook trigger,
// Slack, Gmail. Anything else becomes a TODO marker.
func translateN8nToXpcloud(wf *common.N8nWorkflow, slug string) (string, []string) {
	unsupported := []string{}
	skillImports := []string{}
	steps := []string{}
	schedule := "@trigger"
	for _, n := range wf.Nodes {
		t := strings.ToLower(n.Type)
		switch {
		case strings.Contains(t, "schedule") || strings.Contains(t, "cron"):
			// Best-effort: keep @trigger; the user can paste a real
			// cron via the YAML editor.
			schedule = "@trigger  # imported from n8n schedule trigger; edit to a real cron"
		case strings.Contains(t, "webhook"):
			schedule = "@trigger  # n8n webhook → manual trigger for now"
		case strings.Contains(t, "httprequest") || strings.Contains(t, "http.request"):
			skillImports = appendUnique(skillImports, "community/fetch")
			steps = append(steps, "      - "+n.Name+"  # fetch (was n8n HTTP Request)")
		case strings.Contains(t, "code") || strings.Contains(t, "function"):
			skillImports = appendUnique(skillImports, "community/python-repl")
			steps = append(steps, "      - "+n.Name+"  # python-repl (was n8n Code node)")
		case strings.Contains(t, "slack"):
			skillImports = appendUnique(skillImports, "community/slack-mcp")
			steps = append(steps, "      - "+n.Name+"  # slack-mcp")
		case strings.Contains(t, "gmail"):
			skillImports = appendUnique(skillImports, "community/gmail-mcp")
			steps = append(steps, "      - "+n.Name+"  # gmail-mcp")
		default:
			unsupported = append(unsupported, n.Type)
			steps = append(steps, "      - TODO  # n8n node \""+n.Type+"\" — no direct skill mapping yet")
		}
	}

	var sb strings.Builder
	sb.WriteString("# Promoted from n8n — review + edit before installing.\n")
	sb.WriteString("# Best-effort node→skill mapping; TODO shells need a hand-pick.\n\n")
	fmt.Fprintf(&sb, "name: %s\n", slug)
	sb.WriteString("kind: app\n")
	sb.WriteString("version: 0.1.0\n\n")
	if len(skillImports) > 0 {
		sb.WriteString("skill_imports:\n")
		for _, s := range skillImports {
			fmt.Fprintf(&sb, "  - %s\n", s)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("workflows:\n")
	fmt.Fprintf(&sb, "  - name: %s\n", slug)
	fmt.Fprintf(&sb, "    schedule: \"%s\"\n", schedule)
	sb.WriteString("    skills:\n")
	for _, st := range steps {
		sb.WriteString(st + "\n")
	}
	return sb.String(), unsupported
}

func appendUnique(arr []string, s string) []string {
	for _, e := range arr {
		if e == s {
			return arr
		}
	}
	return append(arr, s)
}

// readLoopsFromAnywhere tries the user's tenant copy first, then the
// operator-shared copy. Returns the loops list + a label describing
// where it came from ("tenant" | "operator-shared").
func readLoopsFromAnywhere(userID, app string) ([]rawLoop, string) {
	for _, candidate := range []struct {
		path  string
		label string
	}{
		{filepath.Join(tenantAppsDir(userID), app, "xpcloud.yaml"), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "apps", app, "xpcloud.yaml"), "operator-shared"},
	} {
		loops, err := readYamlLoops(candidate.path)
		if err == nil && len(loops) > 0 {
			return loops, candidate.label
		}
	}
	return nil, ""
}

// debug helper — included so the request-trace JSON encoding is sane;
// remove if mypy/staticcheck flags it as unused.
var _ = json.RawMessage{}
