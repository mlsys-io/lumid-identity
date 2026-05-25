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
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// WorkflowRow is the unified per-workflow record the UI consumes.
type WorkflowRow struct {
	Slug         string `json:"slug"`           // unique within tenant: "<app>:<name>" or "n8n:<id>"
	Kind         string `json:"kind"`           // "scheduled" | "visual"
	Name         string `json:"name"`           // display name (loop name or n8n workflow name)
	App          string `json:"app,omitempty"`  // for scheduled
	Trigger      string `json:"trigger"`        // human-readable
	Enabled      bool   `json:"enabled"`
	Tenant       bool   `json:"tenant"`         // true = tenant-installed; false = operator-shared
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

	// 1. Scheduled — reuse the existing AdminLoops scan but scope it
	//    to the caller's tenant tree + operator-shared. AdminLoops
	//    today serves operator-only; we duplicate the scan with the
	//    tenant root prepended.
	if kindFilter == "" || kindFilter == "scheduled" {
		rows = append(rows, scheduledWorkflows(userID)...)
	}

	// 2. Visual — n8n. Soft-fail on unauthenticated (W1 norm); the
	//    list is empty until the user signs into n8n directly. W2 SSO
	//    bridge will mint the session cookie automatically.
	if kindFilter == "" || kindFilter == "visual" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		rows = append(rows, visualWorkflows(ctx, c)...)
	}

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
			appDir := filepath.Join(appsRoot, e.Name())
			loops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml"))
			if err != nil || len(loops) == 0 {
				// Try manifest.json fallback.
				loops, _ = readManifestLoops(filepath.Join(appDir, "manifest.json"))
			}
			if len(loops) == 0 {
				continue
			}
			enabledMap := readEnabledOverrides(filepath.Join(appDir, ".user-overrides.yaml"))
			for _, L := range loops {
				if L.Name == "" {
					continue
				}
				jobID := "xpio:" + e.Name() + ":" + L.Name
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
					LastRunTS:    s.LastRunTS,
					Description:  L.Description,
					Engine:       engine,
					StepCount:    len(L.Steps),
					RunSpark:     buildRunSpark(filepath.Join(appDir, "data", "journal.jsonl"), L.Name, 14),
					CostCentsMTD: costMap[e.Name()+"."+L.Name],
				}
				if s.LastOk != nil {
					b := *s.LastOk
					row.LastRunOK = &b
				}
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
func buildRunSpark(journalPath, loop string, limit int) string {
	f, err := os.Open(journalPath)
	if err != nil {
		return ""
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
		if skipped, _ := row["skipped"].(bool); skipped {
			ch = '_'
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
	out := make([]byte, len(rows))
	for i, p := range rows {
		out[i] = p.ch
	}
	return string(out)
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
