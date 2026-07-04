package handler

// W1 — workflow surface tools for the chat agent.
// Mirrors the MeWorkflows / MeRuns HTTP handlers but operates in-process
// (no HTTP round-trip from the agent back to its own server).
//
// W2 adds the Create-surface tools (search_marketplace, compose_workflow,
// add_skill_to_workflow) below the W1 helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// toolListWorkflows returns a slim list (max 50) of the user's
// workflows for chat consumption. Mirrors MeWorkflows.
func toolListWorkflows(c *gin.Context, userID, kindFilter string) map[string]any {
	rows := make([]WorkflowRow, 0, 32)
	if kindFilter == "" || kindFilter == "scheduled" {
		rows = append(rows, scheduledWorkflows(userID)...)
	}
	if kindFilter == "" || kindFilter == "visual" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		rows = append(rows, visualWorkflows(ctx, c)...)
	}
	// Trim for chat context budget.
	if len(rows) > 50 {
		rows = rows[:50]
	}
	return map[string]any{
		"workflows": rows,
		"count":     len(rows),
	}
}

func toolWorkflowDetail(c *gin.Context, userID, slug string) map[string]any {
	// Reuse the parsing from MeWorkflowDetail's case logic.
	// For chat we omit the full step list to keep the response light;
	// the user can ask follow-up questions to pull individual steps.
	parts := splitN(slug, ":", 2)
	if len(parts) != 2 {
		return map[string]any{"error": "invalid slug"}
	}
	if parts[0] == "n8n" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		cli := common.NewN8nClient()
		cookie, _ := c.Cookie("n8n-auth")
		wf, err := cli.GetWorkflow(ctx, parts[1], cookie)
		if err != nil {
			return map[string]any{"error": "n8n: " + err.Error()}
		}
		return map[string]any{
			"slug":       slug,
			"kind":       "visual",
			"name":       wf.Name,
			"step_count": len(wf.Nodes),
			"active":     wf.Active,
		}
	}
	loops, src := readLoopsFromAnywhere(userID, parts[0])
	for _, L := range loops {
		if L.Name == parts[1] {
			engine := "runner_steps"
			if L.Engine.Type != "" {
				engine = L.Engine.Type
				if L.Engine.Module != "" {
					engine += ":" + L.Engine.Module
				}
			}
			return map[string]any{
				"slug":         slug,
				"kind":         "scheduled",
				"app":          parts[0],
				"loop":         L.Name,
				"source":       src,
				"schedule":     L.Schedule,
				"description":  L.Description,
				"primary_role": L.PrimaryRole,
				"engine":       engine,
				"step_count":   len(L.Steps),
				"skills":       L.Skills,
			}
		}
	}
	return map[string]any{"error": "workflow not found: " + slug}
}

func toolListRuns(c *gin.Context, userID, stateFilter, workflowFilter string, limit int) map[string]any {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	now := time.Now().UTC()
	rows := collectRuns(c, userID, now.Add(-24*time.Hour), now.Add(time.Minute))
	// Filter.
	filtered := make([]RunRow, 0, len(rows))
	for _, r := range rows {
		if stateFilter != "" && !stateMatches(r.State, stateFilter) {
			continue
		}
		if workflowFilter != "" && r.WorkflowSlug != workflowFilter {
			continue
		}
		filtered = append(filtered, r)
	}
	// Sort newest first; trim to limit.
	sortRunsByTimeDesc(filtered)
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	// Slim each row for chat — strip cycle_dir, keep the rest.
	slim := make([]map[string]any, 0, len(filtered))
	for _, r := range filtered {
		slim = append(slim, map[string]any{
			"run_id":        r.RunID,
			"workflow_slug": r.WorkflowSlug,
			"kind":          r.Kind,
			"name":          r.Name,
			"app":           r.App,
			"state":         r.State,
			"started_iso":   r.StartedISO,
			"duration_s":    r.DurationSec,
			"reason":        r.Reason,
		})
	}
	return map[string]any{
		"runs":  slim,
		"count": len(slim),
	}
}

func toolRunDetail(c *gin.Context, userID, runID string) map[string]any {
	head := splitN(runID, ":", 2)
	if len(head) < 2 {
		return map[string]any{"error": "invalid run id"}
	}
	switch head[0] {
	case "visual":
		// "visual:n8n:<execID>"
		vp := splitN(runID, ":", 3)
		if len(vp) < 3 {
			return map[string]any{"error": "invalid run id (expected visual:n8n:<id>)"}
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		cli := common.NewN8nClient()
		cookie, _ := c.Cookie("n8n-auth")
		exec, err := cli.GetExecution(ctx, vp[2], cookie)
		if err != nil {
			return map[string]any{"error": "n8n: " + err.Error()}
		}
		return map[string]any{
			"run_id":  runID,
			"kind":    "visual",
			"state":   n8nStateToOurs(exec.Status, exec.Finished),
			"started": exec.StartedAt,
			"stopped": exec.StoppedAt,
		}
	case "scheduled":
		// "scheduled:<app>:<loop>:<ts>" — 4 segments (matches MeRuns RunID).
		parts := splitN(runID, ":", 4)
		if len(parts) != 4 {
			return map[string]any{"error": "invalid run id (expected scheduled:<app>:<loop>:<ts>)"}
		}
		app, loop, ts := parts[1], parts[2], parts[3]
		cycleDir, _ := resolveCycleDir(userID, app, loop, ts)
		resolvedTs := ts
		approximate := false
		if cycleDir == "" {
			// Tolerant drill: the caller's ts is often approximate (list_runs
			// derives it from the journal clock; Pattern-B loops write a
			// wrapper + a work dir seconds apart). Resolve to the nearest real
			// cycle so "walk me through run X" never dead-ends.
			cycleDir, resolvedTs = nearestCycleDir(userID, app, loop, ts)
			approximate = cycleDir != "" && resolvedTs != ts
		}
		if cycleDir == "" {
			return map[string]any{"error": "no cycles found for " + app + ":" + loop +
				" — check the app/loop name (list_workflows shows valid ones)"}
		}
		// The per-cycle summary is cycle.json (NOT summary.json). step_errors
		// is a top-level field of cycle.json for most apps, or a sidecar file
		// for a few — surface both so the agent can explain failures. For
		// Pattern-B two-dir cycles the summary may live in a sibling wrapper
		// dir; fall back to the nearest dir that actually has a cycle.json.
		summary := readJSONFile(cycleDir + "/cycle.json")
		if summary == nil {
			// Pattern-B work dir (no cycle.json) → pull the summary from the
			// nearest dir that actually has one (the wrapper). nearestCycleDir
			// would return THIS dir (diff 0, it exists), so use the dedicated
			// summary-bearing search instead.
			if wrap := nearestSummaryDir(userID, app, loop, resolvedTs); wrap != "" {
				if s := readJSONFile(wrap + "/cycle.json"); s != nil {
					summary = s
				}
			}
		}
		stepErrs := readJSONFile(cycleDir + "/step_errors.json")
		out := map[string]any{
			"run_id":      "scheduled:" + app + ":" + loop + ":" + resolvedTs,
			"kind":        "scheduled",
			"app":         app,
			"loop":        loop,
			"ts":          resolvedTs,
			"summary":     summary,
			"step_errors": stepErrs,
			// "what it LEARNED" — the memories this cycle's learn stage wrote
			// (correlated by time window). Learning lands in the agent banks,
			// not the cycle dir, so without this the agent can only report what
			// HAPPENED, never what was figured out.
			"memories_learned": memoriesLearnedInCycle(userID, app, loop, resolvedTs),
		}
		if approximate {
			out["note"] = "requested ts " + ts + " had no exact cycle; resolved to nearest run " + resolvedTs
		}
		return out
	default:
		return map[string]any{"error": "invalid run id"}
	}
}

// sortRunsByTimeDesc — small inline helper to avoid pulling sort
// into every caller's import list.
func sortRunsByTimeDesc(rows []RunRow) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j-1].StartedAt < rows[j].StartedAt; j-- {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}

// ── W2 Create-surface tools ───────────────────────────────────────

// toolSearchMarketplace wraps xpcloud's /api/v1/skills/catalog or
// /api/v1/skills/suggest depending on whether the query is short
// (keyword browse) or a longer intent. Returns trimmed cards.
func toolSearchMarketplace(c *gin.Context, query, forApp string, limit int) map[string]any {
	if limit < 1 || limit > 10 {
		limit = 5
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()

	// Use the suggest endpoint when the query is intent-like (>3 tokens
	// or starts with a verb). Otherwise hit the catalog with the query
	// as a search filter.
	if isIntentLike(query) {
		body, _ := json.Marshal(map[string]any{
			"intent":  query,
			"for_app": forApp,
			"max":     limit,
		})
		resp, err := httpPostJSON(ctx, xpcloudBaseURL()+"/api/v1/skills/suggest", body)
		if err != nil {
			return map[string]any{"error": "marketplace search: " + err.Error()}
		}
		suggestions, _ := resp["suggestions"].([]any)
		return map[string]any{
			"query":   query,
			"scorer":  resp["scorer"],
			"results": trimSuggestions(suggestions, limit),
			"count":   len(suggestions),
		}
	}

	url := xpcloudBaseURL() + "/api/v1/skills/catalog"
	if forApp != "" {
		url += "?for_app=" + forApp
	}
	resp, err := httpGetJSON(ctx, url)
	if err != nil {
		return map[string]any{"error": "marketplace browse: " + err.Error()}
	}
	cards, _ := resp["cards"].([]any)
	filtered := []map[string]any{}
	q := strings.ToLower(query)
	for _, raw := range cards {
		card, _ := raw.(map[string]any)
		if card == nil {
			continue
		}
		hay := strings.ToLower(fmt.Sprintf("%v %v %v",
			card["name"], card["display_name"], card["summary"]))
		if q == "" || strings.Contains(hay, q) {
			filtered = append(filtered, slimCard(card))
		}
		if len(filtered) >= limit {
			break
		}
	}
	return map[string]any{
		"query":   query,
		"results": filtered,
		"count":   len(filtered),
	}
}

// MeComposeWorkflow — POST /me/workflows/compose {intent, name?}
// Direct (non-chat) compose so the Studio composer gets the draft spec
// instantly + deterministically — no LLM round-trip to wait on. Reuses
// toolComposeWorkflow (trading branch + generic skill-suggest).
func MeComposeWorkflow(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		Intent string `json:"intent"`
		ForApp string `json:"for_app"`
		Name   string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Intent) == "" {
		fail(c, http.StatusBadRequest, 1400, "intent required")
		return
	}
	res := toolComposeWorkflow(c, userID, body.Intent, body.ForApp, body.Name)
	if errMsg, bad := res["error"].(string); bad {
		fail(c, http.StatusInternalServerError, 1500, errMsg)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": res})
}

// toolComposeWorkflow drafts a new tenant workflow from an intent.
// Stages an xpcloud.yaml + manifest.json under the tenant draft dir
// for the user to review in the composer. Doesn't install.
func toolComposeWorkflow(c *gin.Context, userID, intent, forApp, name string) map[string]any {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	if forApp == "" {
		forApp = guessForApp(intent)
	}

	// Always slugify — a name the chat agent supplies can carry spaces /
	// uppercase / punctuation (e.g. "RAG Research Digest"), and a long intent
	// can blow the 128-char install limit. slugify() lowercases, hyphenates,
	// and caps length, so the staged draft dir + the slug we hand to install
	// are always valid. (Install rejects anything non-[a-z0-9._/-] / >128.)
	slug := slugify(name)
	if slug == "" || slug == "new-workflow" {
		slug = slugify(intent)
	}

	// Auto-trading showcase: one curated, deterministic case so the live
	// assembly always renders a complete paper-mode trading bot.
	if isTradingIntent(intent) {
		return composeTradingDraft(userID, slug, intent)
	}

	// Step 1: ask xpcloud to suggest skills for the intent.
	// use_llm:false → the deterministic token scorer (instant, with synonym
	// mapping). The LLM scorer routinely blew the request budget and timed
	// out the whole compose; the token scorer is reliable and good enough to
	// seed a draft the user then refines in the composer.
	body, _ := json.Marshal(map[string]any{
		"intent":  intent,
		"for_app": forApp,
		"max":     5,
		"use_llm": false,
	})
	resp, err := httpPostJSON(ctx, xpcloudBaseURL()+"/api/v1/skills/suggest", body)
	if err != nil {
		return map[string]any{"error": "skill suggest: " + err.Error()}
	}
	suggestions, _ := resp["suggestions"].([]any)
	// No hard dead-end on an empty match: still stage a draft (with a note)
	// so the user can add skills in the composer instead of hitting a wall.
	noMatch := len(suggestions) == 0

	pickedSkills := []string{}
	skillSummaries := []map[string]any{}
	for _, raw := range suggestions {
		s, _ := raw.(map[string]any)
		if s == nil {
			continue
		}
		if n, ok := s["name"].(string); ok && n != "" {
			pickedSkills = append(pickedSkills, n)
			skillSummaries = append(skillSummaries, map[string]any{
				"name":         s["name"],
				"display_name": s["display_name"],
				"summary":      s["summary"],
				"why":          s["why"],
			})
		}
	}

	// Step 2: assemble a draft xpcloud.yaml + manifest.json.
	yaml := buildDraftXpcloudYaml(slug, intent, forApp, pickedSkills)
	manifest := map[string]any{
		"name":        slug,
		"kind":        "app",
		"version":     "0.1.0",
		"description": intent,
		"status":      "draft",
	}

	// Step 3: stage under ~/.tenants/<sub>/.xp/apps/<slug>-draft/.
	draftDir := filepath.Join(tenantAppsDir(userID), slug+"-draft")
	if err := os.MkdirAll(draftDir, 0o775); err != nil {
		return map[string]any{"error": "draft dir: " + err.Error()}
	}
	if err := os.WriteFile(SpecWritePath(draftDir), []byte(yaml), 0o644); err != nil {
		return map[string]any{"error": "write yaml: " + err.Error()}
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(ManifestWritePath(draftDir), manifestBytes, 0o644); err != nil {
		return map[string]any{"error": "write manifest: " + err.Error()}
	}
	makeDraftWritable(draftDir)

	note := "Drafted as a tenant workflow. Open Studio composer to review + adjust skills + schedule, then Save to install."
	if noMatch {
		note = "No catalog skill matched this intent yet — staged an empty draft. Add skills in the composer (or ask me to search the marketplace), then Save to install."
	}
	return map[string]any{
		"draft_slug":      slug + "-draft",
		"draft_dir":       draftDir,
		"intent":          intent,
		"for_app":         forApp,
		"skills_picked":   pickedSkills,
		"skill_summaries": skillSummaries,
		"no_match":        noMatch,
		"review_url":      "/studio/workflows/" + slug + "-draft:" + slug,
		"note":            note,
	}
}

// composeTradingDraft stages the curated paper-mode trading bot and returns a
// rich result the composer renders as a live assembly (pipeline + risk officer
// + schedule + goal), not just a skills list.
func composeTradingDraft(userID, slug, intent string) map[string]any {
	steps := tradingSteps()
	skills := []string{}
	summaries := []map[string]any{}
	stepOut := []map[string]any{}
	seen := map[string]bool{}
	humanize := func(s string) string {
		w := strings.Split(strings.ReplaceAll(s, "_", " "), " ")
		if len(w) > 0 && len(w[0]) > 0 {
			w[0] = strings.ToUpper(w[0][:1]) + w[0][1:]
		}
		return strings.Join(w, " ")
	}
	for _, st := range steps {
		stepOut = append(stepOut, map[string]any{
			"id": st.ID, "stage": st.Stage, "skill": st.Skill, "why": st.Why,
			"query": st.Query, "source": st.Source, "score": st.Score,
		})
		if !seen[st.Skill] {
			seen[st.Skill] = true
			skills = append(skills, st.Skill)
			summaries = append(summaries, map[string]any{
				"name": st.Skill, "display_name": humanize(st.Skill), "summary": st.Why, "why": st.Why,
				"query": st.Query, "source": st.Source, "score": st.Score,
			})
		}
	}

	draftDir := filepath.Join(tenantAppsDir(userID), slug+"-draft")
	if err := os.MkdirAll(draftDir, 0o775); err != nil {
		return map[string]any{"error": "draft dir: " + err.Error()}
	}
	if err := os.WriteFile(SpecWritePath(draftDir), []byte(buildTradingXpcloudYaml(slug, intent)), 0o644); err != nil {
		return map[string]any{"error": "write yaml: " + err.Error()}
	}
	manifest := map[string]any{"name": slug, "kind": "app", "version": "0.1.0", "description": intent, "status": "draft", "fork_of": "auto-quant"}
	mb, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(ManifestWritePath(draftDir), mb, 0o644)
	makeDraftWritable(draftDir)

	// Run the REAL search → match → verify procedure against live xp.io:
	// resolve each pipeline skill to its repo+path+sha (fork parent first,
	// then skill_imports — the runtime's own order) and produce a verify
	// checklist. Best-effort; on any xp.io hiccup the steps keep their
	// curated source and the trace is simply thinner.
	traceCtx, traceCancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer traceCancel()
	trace, enrichedSteps := buildAssemblyTrace(traceCtx, intent, stepOut)
	stepOut = enrichedSteps

	return map[string]any{
		"draft_slug":      slug + "-draft",
		"draft_dir":       draftDir,
		"intent":          intent,
		"for_app":         "auto-quant",
		"kind":            "trading",
		"skills_picked":   skills,
		"skill_summaries": summaries,
		"steps":           stepOut,
		"assembly_trace":  trace,
		"schedule":        "0 */12 * * *",
		"schedule_human":  "every 12 hours",
		"mode":            "paper",
		"risk_agent":      slug + "-risk",
		"goal": map[string]any{
			"primary": "maximize paper realized alpha vs buy-hold",
			"tracked": []string{"realized alpha vs BTC buy-hold", "max drawdown observed", "hit rate (risk-approved proposals)"},
		},
		"no_match":   false,
		"review_url": "/studio/workflows/" + slug + "-draft:" + slug,
		"note":       "Drafted a paper-mode momentum trading bot — review the pipeline + schedule, then install.",
	}
}

// makeDraftWritable makes a composed draft tree writable by the lumid-scheduler.
// identity runs as root in-container; the scheduler runs as a DIFFERENT uid and
// must rename `<slug>-draft` → `<slug>` on promote AND rewrite the manifests /
// copy skills into it. Root-owned 0o775 dirs + 0o644 files lock it out (the
// promote failed with EACCES on rename). Make the draft dir + files and the
// tenant app-tree ancestors world-writable — uid-agnostic, same rationale as
// writeIntent's 0o777 me-intents dir. rename needs write on the PARENT dir, so
// the ancestors up to (but not including) .tenants are chmod'd too.
func makeDraftWritable(draftDir string) {
	_ = os.Chmod(draftDir, 0o777)
	if entries, err := os.ReadDir(draftDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				_ = os.Chmod(filepath.Join(draftDir, e.Name()), 0o666)
			}
		}
	}
	// Walk ancestors (.xp/apps, .xp, <tenant-sub>) so the scheduler can create
	// the promoted dir + rename within them. Stop at the shared .tenants root.
	d := filepath.Dir(draftDir)
	for i := 0; i < 4 && d != "/" && d != "." && filepath.Base(d) != ".tenants"; i++ {
		_ = os.Chmod(d, 0o777)
		d = filepath.Dir(d)
	}
}

// toolAddSkillToWorkflow appends a skill to an existing tenant workflow's
// `skill_imports[]`. Writes back to the same xpcloud.yaml.
func toolAddSkillToWorkflow(userID, slug, skillName string) map[string]any {
	parts := splitN(slug, ":", 2)
	if len(parts) != 2 {
		return map[string]any{"error": "slug must be '<app>:<loop>'"}
	}
	app := parts[0]
	appDir := filepath.Join(tenantAppsDir(userID), app)
	xpcloudPath, ok := ResolveSpecPath(appDir)
	if !ok {
		return map[string]any{"error": fmt.Sprintf("tenant copy of '%s' not found; install the workflow first via compose_workflow or app_install", app)}
	}
	b, err := os.ReadFile(xpcloudPath)
	if err != nil {
		return map[string]any{"error": "read xpcloud.yaml: " + err.Error()}
	}
	// Minimal-touch YAML edit: append the skill name to skill_imports[]
	// if it's not already there. Round-trip parse would be cleaner but
	// pulls in a YAML lib for one append; this is good enough for v1.
	yamlContent := string(b)
	needle := "community/" + skillName
	if strings.Contains(yamlContent, needle) {
		return map[string]any{
			"status": "no-op",
			"note":   "skill already in skill_imports[]",
		}
	}
	// Append below an existing skill_imports: block; otherwise create one.
	updated := appendToSkillImports(yamlContent, needle)
	writePath := SpecWritePath(appDir)
	if err := os.WriteFile(writePath, []byte(updated), 0o644); err != nil {
		return map[string]any{"error": "write xpcloud.yaml: " + err.Error()}
	}
	// Avoid orphaning a pre-existing legacy spec: if we read from the legacy
	// name, drop it now that the canonical dotfile holds the updated content.
	if xpcloudPath != writePath {
		_ = os.Remove(xpcloudPath)
	}
	return map[string]any{
		"slug":  slug,
		"added": skillName,
		"note":  "Added to skill_imports[]. Re-install the app (app_update) or run a cycle to pick it up.",
	}
}

// ── Helpers ───────────────────────────────────────────────────────

func httpGetJSON(ctx context.Context, url string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	r, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", r.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func httpPostJSON(ctx context.Context, url string, body []byte) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("status %d", r.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func isIntentLike(q string) bool {
	if len(q) > 60 {
		return true
	}
	verbs := []string{"watch", "send", "draft", "remind", "find", "summariz", "monitor", "schedule", "build", "every"}
	low := strings.ToLower(q)
	for _, v := range verbs {
		if strings.Contains(low, v) {
			return true
		}
	}
	return false
}

func guessForApp(intent string) string {
	low := strings.ToLower(intent)
	switch {
	case strings.Contains(low, "trade") || strings.Contains(low, "market") || strings.Contains(low, "polymarket"):
		return "auto-quant"
	case strings.Contains(low, "case") || strings.Contains(low, "consulting"):
		return "mbb-ai"
	case strings.Contains(low, "annotat") || strings.Contains(low, "label"):
		return "eventx"
	case strings.Contains(low, "benchmark") || strings.Contains(low, "evaluate"):
		return "auto-sysresearch"
	default:
		return "personal-agent"
	}
}

func slugify(s string) string {
	out := []rune{}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		} else if r == ' ' || r == '-' || r == '_' {
			if len(out) > 0 && out[len(out)-1] != '-' {
				out = append(out, '-')
			}
		}
	}
	s2 := strings.Trim(string(out), "-")
	if s2 == "" {
		s2 = "new-workflow"
	}
	if len(s2) > 40 {
		s2 = s2[:40]
	}
	return s2
}

func trimSuggestions(raw []any, limit int) []map[string]any {
	out := []map[string]any{}
	for i, s := range raw {
		if i >= limit {
			break
		}
		m, _ := s.(map[string]any)
		if m == nil {
			continue
		}
		out = append(out, map[string]any{
			"name":         m["name"],
			"display_name": m["display_name"],
			"summary":      m["summary"],
			"category":     m["category"],
			"why":          m["why"],
		})
	}
	return out
}

func slimCard(c map[string]any) map[string]any {
	return map[string]any{
		"name":         c["name"],
		"display_name": c["display_name"],
		"summary":      c["summary"],
		"category":     c["category"],
		"step_count":   c["step_count"],
		"kind":         c["kind"],
	}
}

// buildDraftXpcloudYaml builds a minimal viable xpcloud.yaml for a
// new tenant workflow. The shape mirrors personal-agent's loops[]
// schema with one loop named after the slug.
func buildDraftXpcloudYaml(slug, intent, forApp string, skills []string) string {
	var sb strings.Builder
	sb.WriteString("# Draft workflow — review in Studio composer before installing.\n")
	sb.WriteString("# Generated by /me/agent/chat → compose_workflow.\n")
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "name: %s\n", slug)
	sb.WriteString("kind: app\n")
	sb.WriteString("version: 0.1.0\n")
	fmt.Fprintf(&sb, "description: %q\n", intent)
	fmt.Fprintf(&sb, "fork_of: %s\n", forApp)
	sb.WriteString("status: draft\n")
	sb.WriteString("\n")
	sb.WriteString("skill_imports:\n")
	for _, s := range skills {
		fmt.Fprintf(&sb, "  - community/%s\n", s)
	}
	sb.WriteString("\n")
	sb.WriteString("loops:\n")
	fmt.Fprintf(&sb, "  - name: %s\n", slug)
	sb.WriteString("    schedule: \"@trigger\"  # change to a cron string when ready, e.g. '0 8 * * *'\n")
	sb.WriteString("    description: |\n")
	fmt.Fprintf(&sb, "      %s\n", intent)
	sb.WriteString("    skills:\n")
	for _, s := range skills {
		fmt.Fprintf(&sb, "      - %s\n", s)
	}
	// steps[] make this a runnable Pattern A workflow (not just a skeleton):
	// the runner walks them in order, stage-tagged observe → act so B0
	// observability + the rest of the engine fire on install. First skill
	// is the observe (read) step; the rest are act (do) steps. The user
	// re-orders / re-stages in the composer before saving.
	idRepl := strings.NewReplacer("/", "_", "-", "_", ".", "_", " ", "_")
	if len(skills) == 0 {
		sb.WriteString("    steps: []  # no skills matched — add skills above, then list steps here\n")
	} else {
		sb.WriteString("    steps:\n")
		seen := map[string]int{}
		for i, s := range skills {
			id := idRepl.Replace(s)
			if seen[id] > 0 {
				id = fmt.Sprintf("%s_%d", id, seen[id])
			}
			seen[idRepl.Replace(s)]++
			stage := "act"
			if i == 0 {
				stage = "observe"
			}
			fmt.Fprintf(&sb, "      - {id: %s, stage: %s, skill: %s}\n", id, stage, s)
		}
	}
	return sb.String()
}

// ── Auto-trading showcase ──────────────────────────────────────────
// One curated, deterministic case: "spin up a crypto momentum trading bot".
// When the intent is trading-shaped we skip the generic skill-suggest path
// and emit the known-good auto-quant scaffold so the composer's live-assembly
// always renders a complete bot (market sense → signal → backtest → risk
// officer → journal) and installs as a runnable paper-mode fork.

type composeStep struct {
	ID, Stage, Skill, Why string
	// Substage drives the runner's auto-wiring of canonical kwargs
	// (sdk/apps/app_runner.py:_auto_wire_kwargs): `pre-flight` maps the
	// step's output to `backtest`, `risk-gate` maps it to `risk_decision`.
	// Without these, journal_trade fails with "missing risk_decision".
	Substage string
	// Args is an inline-YAML object string appended as `args: {...}` —
	// e.g. journal_trade's paper-mode `fill` (there's no live order step,
	// so the runner can't auto-wire `fill`; supply it explicitly).
	Args string
	// Provenance — surfaced by the inline assembly UI so the user watches
	// the AI actually *search* for each skill and see where it resolves
	// from. Query = the catalog search phrase; Source = the repo the skill
	// is published in (real: auto-quant fork + the lumid-lqa import);
	// Score = match confidence (curated for the deterministic showcase).
	Query  string
	Source string
	Score  float64
}

func tradingSteps() []composeStep {
	return []composeStep{
		// observe_crypto_market (NOT observe_market) — observe_market defaults
		// to the equity Mag7 universe and hits kv.run OHLC (401 / no crypto);
		// observe_crypto_market tracks BTCUSD/ETHUSD via the QA trading API,
		// which is what a crypto momentum bot needs.
		{ID: "observe_market", Stage: "observe", Skill: "observe_crypto_market", Why: "Pulls live BTC/ETH prices + momentum features so it trades on the current market state.",
			Query: "live crypto price + momentum features", Source: "lumid-lqa", Score: 0.95},
		{ID: "observe_holdings", Stage: "observe", Skill: "fetch_holdings", Why: "Reads your paper portfolio so sizing respects current exposure.",
			Query: "current paper portfolio + open positions", Source: "auto-quant", Score: 0.91},
		{ID: "propose_setup", Stage: "hypothesize", Skill: "propose_trade", Why: "The momentum signal — proposes a sized entry with a target and a stop.",
			Query: "momentum entry signal with target + stop", Source: "auto-quant", Score: 0.93},
		{ID: "preflight", Stage: "act", Substage: "pre-flight", Skill: "backtest_strategy", Why: "Backtests the proposed setup before risking any capital.",
			Query: "backtest a proposed setup before risking capital", Source: "auto-quant", Score: 0.90},
		{ID: "risk_gate", Stage: "act", Substage: "risk-gate", Skill: "score_proposal", Why: "The risk officer — vets size, drawdown and regime-fit; can veto the trade.",
			Query: "risk officer: size, drawdown, regime veto", Source: "auto-quant", Score: 0.96},
		{ID: "journal", Stage: "analyze", Skill: "journal_trade", Args: `{fill: {status: not_filled, mode: paper, note: "paper mode — proposal journaled, no live order placed"}}`, Why: "Records the decision + outcome so it learns which setups actually pay.",
			Query: "journal the decision + outcome to learn", Source: "auto-quant", Score: 0.89},
		{ID: "mark_to_market", Stage: "analyze", Skill: "mark_to_market", Why: "Marks paper positions to market and books realized PnL — emits the real alpha-vs-buy-hold + hit-rate curves.",
			Query: "mark paper positions, realized alpha vs buy-hold", Source: "auto-quant", Score: 0.92},
	}
}

func isTradingIntent(s string) bool {
	l := strings.ToLower(s)
	for _, kw := range []string{"trade", "trading", "crypto", "momentum", "alpha", "btc", "eth", "market", "position", "portfolio", "buy-hold", "quant"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

// buildTradingXpcloudYaml emits the curated paper-mode trading workflow,
// mirroring auto-quant's momentum_research loop (fork_of auto-quant, lumid-lqa
// market data, 5-stage steps, every-12h, alpha-vs-buy-hold goal, risk agent).
func buildTradingXpcloudYaml(slug, intent string) string {
	var sb strings.Builder
	sb.WriteString("# Draft auto-trading workflow — review in Studio, then install (paper mode).\n")
	sb.WriteString("# Generated by compose_workflow (trading case).\n\n")
	fmt.Fprintf(&sb, "name: %s\n", slug)
	sb.WriteString("kind: app\n")
	sb.WriteString("version: 0.1.0\n")
	fmt.Fprintf(&sb, "description: %q\n", intent)
	sb.WriteString("fork_of: auto-quant\n")
	sb.WriteString("status: draft\n")
	sb.WriteString("mode: paper\n\n")
	sb.WriteString("skill_imports:\n")
	sb.WriteString("  - repo: a3f48236-ffe9-4fb9-9548-6e044d5cd9c7/lumid-lqa\n")
	sb.WriteString("    version: ^0.3.0\n")
	sb.WriteString("  - repo: a3f48236-ffe9-4fb9-9548-6e044d5cd9c7/lumid-findata\n")
	sb.WriteString("    version: ^0.1.0\n\n")
	sb.WriteString("memory_agents:\n")
	fmt.Fprintf(&sb, "  - %s-trader\n", slug)
	fmt.Fprintf(&sb, "  - %s-risk\n\n", slug)
	sb.WriteString("roles:\n")
	fmt.Fprintf(&sb, "  - {name: trader, memory_agent: %s-trader}\n", slug)
	fmt.Fprintf(&sb, "  - {name: risk, memory_agent: %s-risk}\n\n", slug)
	sb.WriteString("loops:\n")
	fmt.Fprintf(&sb, "  - name: %s\n", slug)
	sb.WriteString("    schedule: \"0 */12 * * *\"  # every 12 hours\n")
	sb.WriteString("    mode: paper\n")
	sb.WriteString("    goal:\n")
	sb.WriteString("      primary: maximize paper realized alpha vs buy-hold\n")
	sb.WriteString("      tracked:\n")
	sb.WriteString("        - realized alpha vs BTC buy-hold\n")
	sb.WriteString("        - max drawdown observed\n")
	sb.WriteString("        - hit rate (risk-approved proposals)\n")
	sb.WriteString("    description: |\n")
	fmt.Fprintf(&sb, "      %s\n", intent)
	sb.WriteString("    skills:\n")
	seen := map[string]bool{}
	for _, st := range tradingSteps() {
		if !seen[st.Skill] {
			seen[st.Skill] = true
			fmt.Fprintf(&sb, "      - %s\n", st.Skill)
		}
	}
	sb.WriteString("    steps:\n")
	for _, st := range tradingSteps() {
		sb.WriteString("      - {id: " + st.ID + ", stage: " + st.Stage)
		if st.Substage != "" {
			sb.WriteString(", substage: " + st.Substage)
		}
		sb.WriteString(", skill: " + st.Skill)
		if st.Args != "" {
			sb.WriteString(", args: " + st.Args)
		}
		sb.WriteString("}\n")
	}
	return sb.String()
}

// appendToSkillImports appends `entry` to an existing skill_imports[]
// block; creates one if missing. Best-effort YAML edit — round-trip
// parser would be cleaner but a single append is fine for v1.
func appendToSkillImports(yamlContent, entry string) string {
	lines := strings.Split(yamlContent, "\n")
	idx := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "skill_imports:") {
			idx = i
			break
		}
	}
	newLine := "  - " + entry
	if idx == -1 {
		// No skill_imports[] block — append one near the top.
		return yamlContent + "\nskill_imports:\n" + newLine + "\n"
	}
	// Find the end of the block (next non-indented line OR EOF).
	insertAt := len(lines)
	for j := idx + 1; j < len(lines); j++ {
		stripped := strings.TrimRight(lines[j], " \t\r")
		if stripped == "" {
			continue
		}
		if !strings.HasPrefix(stripped, " ") && !strings.HasPrefix(stripped, "\t") && !strings.HasPrefix(stripped, "- ") {
			insertAt = j
			break
		}
	}
	out := append([]string{}, lines[:insertAt]...)
	out = append(out, newLine)
	out = append(out, lines[insertAt:]...)
	return strings.Join(out, "\n")
}

// ── W4 Improve-surface tools ──────────────────────────────────────

// toolWorkflowReportCard mirrors MeMindWorkflow but returns a slim
// chat-suitable payload (headline strings only; no nested numbers).
func toolWorkflowReportCard(c *gin.Context, userID, slug string) map[string]any {
	parts := splitN(slug, ":", 2)
	if len(parts) != 2 || parts[0] == "n8n" {
		return map[string]any{"error": "report cards only for scheduled workflows ('<app>:<loop>')"}
	}
	app, loop := parts[0], parts[1]
	now := time.Now().UTC()
	thisMonth := now.AddDate(0, -1, 0)
	prevMonth := now.AddDate(0, -2, 0)
	cur := buildLoopStats(userID, app, loop, thisMonth, now)
	prev := buildLoopStats(userID, app, loop, prevMonth, thisMonth)
	deltas := buildDeltas(cur, prev)
	// Trim deltas to plain-English headlines for the chat bubble.
	headlines := []string{}
	for _, d := range deltas {
		h := d.Headline
		if d.Detail != "" {
			h += " " + d.Detail
		}
		headlines = append(headlines, h)
	}
	return map[string]any{
		"slug":             slug,
		"runs_this_month":  cur.RunCount,
		"runs_prev_month":  prev.RunCount,
		"success_rate_now": cur.SuccessRate,
		"avg_duration_s":   cur.AvgDurationSec,
		"headlines":        headlines,
	}
}

// toolTriggerEvaluation appends a (skill, for_app) entry to skill-roster's
// evaluate queue; skill-roster picks it up within ~60s.
func toolTriggerEvaluation(userID, skillName, forApp string) map[string]any {
	queuePath := filepath.Join(operatorHome(), ".xp", "apps", "skill-roster", "data", "eval-queue.jsonl")
	if err := os.MkdirAll(filepath.Dir(queuePath), 0o775); err != nil {
		return map[string]any{"error": "queue dir: " + err.Error()}
	}
	entry := map[string]any{
		"skill":        skillName,
		"for_app":      forApp,
		"requested_by": userID,
		"requested_at": time.Now().UTC().Format(time.RFC3339),
		"status":       "queued",
	}
	row, _ := json.Marshal(entry)
	f, err := os.OpenFile(queuePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return map[string]any{"error": "open queue: " + err.Error()}
	}
	defer f.Close()
	if _, err := f.Write(append(row, '\n')); err != nil {
		return map[string]any{"error": "write queue: " + err.Error()}
	}
	return map[string]any{
		"queued":  true,
		"skill":   skillName,
		"for_app": forApp,
		"note":    "skill-roster picks up the queue within 60s; new attestation will land on xpcloud's community repo for the skill.",
	}
}

// toolSuggestImprovement looks at one workflow's recent runs + report
// card and proposes ONE concrete change. Best-effort heuristic for v1;
// the LLM around it (the chat agent) does the actual recommending —
// this tool gives it the data + a structured suggestion frame.
func toolSuggestImprovement(c *gin.Context, userID, slug string) map[string]any {
	parts := splitN(slug, ":", 2)
	if len(parts) != 2 || parts[0] == "n8n" {
		return map[string]any{"error": "suggest_workflow_improvement only supports scheduled workflows"}
	}
	app, loop := parts[0], parts[1]
	now := time.Now().UTC()
	cur := buildLoopStats(userID, app, loop, now.AddDate(0, -1, 0), now)

	suggestion := ""
	rationale := ""
	switch {
	case cur.RunCount == 0:
		suggestion = "Run this workflow at least once via Run-now to start gathering data."
		rationale = "no run history in the last month — there's nothing to optimise yet."
	case cur.SuccessRate < 0.5 && cur.FailureCount > 0:
		suggestion = "Open the latest failure in Runs to inspect the failing step; the error usually points at a missing secret, OAuth scope, or a stale skill version."
		rationale = fmt.Sprintf("success rate is %.0f%% (%d failed of %d runs).", cur.SuccessRate*100, cur.FailureCount, cur.RunCount)
	case cur.AvgDurationSec > 30 && cur.RunCount > 5:
		suggestion = "Try splitting the workflow — long-running steps benefit from sub-workflows so you can re-run just the slow piece."
		rationale = fmt.Sprintf("average cycle takes %.1fs; consider isolating the longest step.", cur.AvgDurationSec)
	case cur.DraftsCreated > 5 && cur.DraftAcceptRate < 0.4:
		suggestion = "Browse the marketplace for a different drafting skill (search 'draft' or 'email reply') — your accept-rate is below 40%."
		rationale = fmt.Sprintf("accepted %d of %d drafts this month.", cur.DraftsAccepted, cur.DraftsCreated)
	default:
		suggestion = "Workflow is steady. If you want to compound improvements, ask 'compose_workflow' for related intents (e.g., 'also surface tasks from emails I starred')."
		rationale = "no obvious failure mode in the last month."
	}

	return map[string]any{
		"slug":       slug,
		"stats":      cur,
		"suggestion": suggestion,
		"rationale":  rationale,
	}
}

// splitN — local alias for strings.SplitN so the agent dispatcher
// can share splitting logic without further imports.
func splitN(s, sep string, n int) []string {
	out := []string{}
	cur := ""
	count := 0
	for i := 0; i < len(s); i++ {
		if count < n-1 && i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			out = append(out, cur)
			cur = ""
			i += len(sep) - 1
			count++
			continue
		}
		cur += string(s[i])
	}
	out = append(out, cur)
	return out
}
