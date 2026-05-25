package handler

// W1 — workflow surface tools for the chat agent.
// Mirrors the MeWorkflows / MeRuns HTTP handlers but operates in-process
// (no HTTP round-trip from the agent back to its own server).

import (
	"context"
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
			"slug":        slug,
			"kind":        "visual",
			"name":        wf.Name,
			"step_count":  len(wf.Nodes),
			"active":      wf.Active,
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
				"slug":          slug,
				"kind":          "scheduled",
				"app":           parts[0],
				"loop":          L.Name,
				"source":        src,
				"schedule":      L.Schedule,
				"description":   L.Description,
				"primary_role":  L.PrimaryRole,
				"engine":        engine,
				"step_count":    len(L.Steps),
				"skills":        L.Skills,
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
			"run_id":         r.RunID,
			"workflow_slug":  r.WorkflowSlug,
			"kind":           r.Kind,
			"name":           r.Name,
			"app":            r.App,
			"state":          r.State,
			"started_iso":    r.StartedISO,
			"duration_s":     r.DurationSec,
			"reason":         r.Reason,
		})
	}
	return map[string]any{
		"runs":  slim,
		"count": len(slim),
	}
}

func toolRunDetail(c *gin.Context, userID, runID string) map[string]any {
	parts := splitN(runID, ":", 3)
	if len(parts) < 3 {
		return map[string]any{"error": "invalid run id"}
	}
	if parts[0] == "visual" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6*time.Second)
		defer cancel()
		cli := common.NewN8nClient()
		cookie, _ := c.Cookie("n8n-auth")
		exec, err := cli.GetExecution(ctx, parts[2], cookie)
		if err != nil {
			return map[string]any{"error": "n8n: " + err.Error()}
		}
		return map[string]any{
			"run_id":   runID,
			"kind":     "visual",
			"state":    n8nStateToOurs(exec.Status, exec.Finished),
			"started":  exec.StartedAt,
			"stopped":  exec.StoppedAt,
		}
	}
	wfParts := splitN(parts[1], ":", 2)
	if len(wfParts) != 2 {
		return map[string]any{"error": "invalid workflow slug in run id"}
	}
	app, loop, ts := wfParts[0], wfParts[1], parts[2]
	cycleDir, _ := resolveCycleDir(userID, app, loop, ts)
	if cycleDir == "" {
		return map[string]any{"error": "cycle not found"}
	}
	// Return a slim summary suitable for a chat bubble.
	summary := readJSONFile(cycleDir + "/summary.json")
	stepErrs := readJSONFile(cycleDir + "/step_errors.json")
	return map[string]any{
		"run_id":      runID,
		"kind":        "scheduled",
		"app":         app,
		"loop":        loop,
		"ts":          ts,
		"summary":     summary,
		"step_errors": stepErrs,
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
