package handler

// me_agent tool: spawn_agent — sub-agent delegation.
//
// The parent chat agent calls `spawn_agent(task, ...)` to delegate a
// focused job to a sub-LLM call with a curated tool subset and a
// fresh message history. The sub-agent runs its own tool-use loop
// (capped at 5 iterations + 45s) and returns its final reply. Used
// to keep the parent's context lean — research-heavy turns can fan
// out to a specialist that absorbs the tool_call noise.
//
// Safety:
//   - 1-level recursion only: spawn_agent is never in the sub-
//     agent's tool list, so it can't spawn nested sub-agents.
//   - Default tool whitelist is read-only + research. Side-effect
//     tools (send_email, create_calendar_event, install_app,
//     run_loop_now, save_artifact, remember_about_me) are NOT
//     exposed unless the caller explicitly opts in via `tools[]`.
//   - Independent token usage; charged to the same daily budget.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	subAgentMaxIterations = 10
	subAgentTimeout       = 180 * time.Second
	subAgentMaxTokens     = 8192
	maxParallelAgents     = 6  // concurrent sub-agents in spawn_agents
	maxAgentTasks         = 10 // total tasks accepted per spawn_agents call
)

// subAgentDefaultTools — sane read-only + research subset for a
// sub-agent that wasn't given an explicit `tools[]` filter. State-
// mutating tools (send_email, install_app, etc.) are intentionally
// excluded; parent agent owns those.
var subAgentDefaultTools = map[string]bool{
	"web_search":           true,
	"web_fetch":            true,
	"deep_research":        true,
	"query_findata":        true,
	"data_catalog":         true,
	"data_query":           true,
	"query_my_knowledge":   true,
	"code_run":             true,
	"list_apps":            true,
	"list_drafts":          true,
	"list_recent_cycles":   true,
	"list_marketplace":     true,
	"list_workflows":       true,
	"workflow_detail":      true,
	"list_runs":            true,
	"run_detail":           true,
	"workflow_report_card": true,
	"today_summary":        true,
	"search_marketplace":   true,
}

// filterTools returns a tool-defs slice containing only entries whose
// name is in `allowed`. spawn_agent is always excluded — sub-agents
// don't get to spawn sub-sub-agents.
func filterTools(all []map[string]any, allowed map[string]bool) []map[string]any {
	out := make([]map[string]any, 0, len(allowed))
	for _, t := range all {
		name, _ := t["name"].(string)
		if name == "spawn_agent" {
			continue
		}
		if allowed[name] {
			out = append(out, t)
		}
	}
	return out
}

// toolSpawnAgent — me_agent tool implementation. Args:
//
//	task         string  required — the focused job for the sub-agent
//	tools        []string optional — whitelist; default = subAgentDefaultTools
//	agent_id     string  optional — ground the sub-agent in this xpio agent
//	max_iter     int     optional — cap on tool-use loop (default 5, max 5)
func toolSpawnAgent(c *gin.Context, userID string, args map[string]any) (map[string]any, bool) {
	task, _ := args["task"].(string)
	task = strings.TrimSpace(task)
	if task == "" {
		return map[string]any{"error": "task required"}, false
	}

	// Tool filter.
	allowed := map[string]bool{}
	if raw, ok := args["tools"].([]any); ok && len(raw) > 0 {
		for _, x := range raw {
			if s, ok := x.(string); ok {
				allowed[s] = true
			}
		}
	} else {
		for k, v := range subAgentDefaultTools {
			allowed[k] = v
		}
	}
	delete(allowed, "spawn_agent")

	// Provider — pick the parent's default; sub-agent doesn't get a
	// per-call model override. (Future: read from role.default_model
	// when agent_id resolves to a role.)
	provider := defaultProvider()
	apiKey, err := provider.keyFn()
	if err != nil {
		return map[string]any{"error": "spawn: " + err.Error()}, false
	}

	// Cap iterations.
	maxIter := subAgentMaxIterations
	if v, ok := args["max_iter"].(float64); ok && int(v) > 0 && int(v) <= subAgentMaxIterations {
		maxIter = int(v)
	}

	// Build the sub-agent's system prompt — focused task + scope rules.
	agentID, _ := args["agent_id"].(string)
	systemPrompt := "You are a sub-agent dispatched by the parent chat assistant to handle one focused job.\n\n" +
		"## Your task\n" + task + "\n\n" +
		"## Rules\n" +
		"- Stay narrowly on task. Don't broaden scope.\n" +
		"- Use the tools you have to do the actual work (don't just describe what you'd do).\n" +
		"- Return a concise written answer at the end (1-4 paragraphs, or a small table).\n" +
		"- Don't ask follow-up questions; the parent agent isn't a human you can ask. Make reasonable assumptions and note them in the reply.\n"
	if agentID != "" {
		systemPrompt += renderAgentBankBlock(userID, agentID)
	}

	tools := filterTools(buildToolDefs(), allowed)
	if len(tools) == 0 {
		return map[string]any{"error": "no tools in filter — sub-agent would have nothing to do"}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), subAgentTimeout)
	defer cancel()
	finalText, toolCalls, inTok, outTok, runErr := runSubAgentLoop(
		ctx, c, userID, provider, apiKey, systemPrompt, task, tools, maxIter,
	)
	if runErr != nil {
		return map[string]any{
			"error":         runErr.Error(),
			"reply":         finalText, // partial reply if any
			"tool_calls":    toolCalls,
			"input_tokens":  inTok,
			"output_tokens": outTok,
		}, false
	}

	// Charge sub-agent tokens to the same daily budget. Best-effort.
	if inTok+outTok > 0 {
		_ = recordUsage(userID, "sub_agent", "/me/agent/chat/spawn", provider.upstreamModel, inTok, outTok)
	}

	return map[string]any{
		"reply":         finalText,
		"tool_calls":    toolCalls,
		"input_tokens":  inTok,
		"output_tokens": outTok,
		"model_used":    provider.id,
		"iterations":    len(toolCalls), // rough — one call per loop iter that fired tools
	}, true
}

// toolSpawnAgents — run several sub-agents concurrently and return all
// replies. Each task mirrors a spawn_agent call (fresh history, read-only +
// research tools by default, user-role tool dispatch inside runSubAgentLoop).
// Concurrency is capped at maxParallelAgents; tasks beyond maxAgentTasks are
// dropped (reported via `dropped`). Sub-agent tool calls don't mutate the
// gin.Context, so sharing it across goroutines is safe (read-only use).
func toolSpawnAgents(c *gin.Context, userID string, args map[string]any) (map[string]any, bool) {
	raw, ok := args["tasks"].([]any)
	if !ok || len(raw) == 0 {
		return map[string]any{"error": "tasks[] required (list of task strings or {task, tools, agent_id} objects)"}, false
	}
	dropped := 0
	if len(raw) > maxAgentTasks {
		dropped = len(raw) - maxAgentTasks
		raw = raw[:maxAgentTasks]
	}

	type spec struct {
		task    string
		allowed map[string]bool
		agentID string
	}
	specs := []spec{}
	for _, r := range raw {
		s := spec{allowed: map[string]bool{}}
		switch v := r.(type) {
		case string:
			s.task = strings.TrimSpace(v)
		case map[string]any:
			s.task, _ = v["task"].(string)
			s.task = strings.TrimSpace(s.task)
			s.agentID, _ = v["agent_id"].(string)
			if tl, ok := v["tools"].([]any); ok {
				for _, x := range tl {
					if str, ok := x.(string); ok {
						s.allowed[str] = true
					}
				}
			}
		}
		if s.task == "" {
			continue
		}
		if len(s.allowed) == 0 {
			for k, val := range subAgentDefaultTools {
				s.allowed[k] = val
			}
		}
		delete(s.allowed, "spawn_agent")
		delete(s.allowed, "spawn_agents")
		specs = append(specs, s)
	}
	if len(specs) == 0 {
		return map[string]any{"error": "no valid tasks (each needs a non-empty task)"}, false
	}

	provider := defaultProvider()
	apiKey, err := provider.keyFn()
	if err != nil {
		return map[string]any{"error": "spawn: " + err.Error()}, false
	}

	results := make([]map[string]any, len(specs))
	sem := make(chan struct{}, maxParallelAgents)
	var wg sync.WaitGroup
	var mu sync.Mutex
	totalIn, totalOut := 0, 0

	for i, sp := range specs {
		wg.Add(1)
		go func(i int, sp spec) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tools := filterTools(buildToolDefs(), sp.allowed)
			if len(tools) == 0 {
				results[i] = map[string]any{"task": sp.task, "error": "no tools in filter"}
				return
			}
			sysPrompt := "You are one of several parallel sub-agents dispatched by the parent chat assistant. Handle ONLY your task.\n\n" +
				"## Your task\n" + sp.task + "\n\n" +
				"## Rules\n" +
				"- Stay narrowly on task; don't broaden scope.\n" +
				"- Use your tools to do the actual work (don't just describe it).\n" +
				"- Return a concise written answer (1-4 paragraphs or a small table).\n" +
				"- Don't ask follow-up questions; make reasonable assumptions and note them.\n"
			if sp.agentID != "" {
				sysPrompt += renderAgentBankBlock(userID, sp.agentID)
			}
			ctx, cancel := context.WithTimeout(context.Background(), subAgentTimeout)
			defer cancel()
			finalText, toolCalls, inTok, outTok, runErr := runSubAgentLoop(
				ctx, c, userID, provider, apiKey, sysPrompt, sp.task, tools, subAgentMaxIterations,
			)
			mu.Lock()
			totalIn += inTok
			totalOut += outTok
			mu.Unlock()
			r := map[string]any{"task": sp.task, "reply": finalText, "tool_calls": len(toolCalls)}
			if runErr != nil {
				r["error"] = runErr.Error()
			}
			results[i] = r
		}(i, sp)
	}
	wg.Wait()

	if totalIn+totalOut > 0 {
		_ = recordUsage(userID, "sub_agent", "/me/agent/chat/spawn-parallel", provider.upstreamModel, totalIn, totalOut)
	}
	out := map[string]any{
		"agents":        results,
		"count":         len(results),
		"input_tokens":  totalIn,
		"output_tokens": totalOut,
	}
	if dropped > 0 {
		out["dropped"] = dropped
		out["note"] = fmt.Sprintf("%d task(s) beyond the %d-task limit were dropped", dropped, maxAgentTasks)
	}
	return out, true
}

// runSubAgentLoop — the inner tool-use loop. Mirrors the loop in
// MeAgentChat but with sub-agent-specific defaults (no thinking, no
// budget pre-check, capped iterations). Returns final text +
// tool_calls + token usage, plus an error on hard failure.
func runSubAgentLoop(
	ctx context.Context,
	c *gin.Context,
	userID string,
	provider llmProvider,
	apiKey string,
	systemPrompt string,
	initialTask string,
	tools []map[string]any,
	maxIter int,
) (string, []toolCallResult, int, int, error) {
	anthMsgs := []map[string]any{
		{"role": "user", "content": initialTask},
	}
	finalText := ""
	toolCalls := []toolCallResult{}
	inputTokens := 0
	outputTokens := 0

	for i := 0; i < maxIter; i++ {
		req := map[string]any{
			"model":      provider.upstreamModel,
			"max_tokens": subAgentMaxTokens,
			"system":     systemPrompt,
			"messages":   anthMsgs,
			"tools":      tools,
		}
		resp, err := callLLM(ctx, provider, apiKey, req)
		if err != nil {
			return finalText, toolCalls, inputTokens, outputTokens, fmt.Errorf("llm: %w", err)
		}
		if usage, ok := resp["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				inputTokens += int(v)
			}
			if v, ok := usage["output_tokens"].(float64); ok {
				outputTokens += int(v)
			}
		}

		content, _ := resp["content"].([]any)
		stopReason, _ := resp["stop_reason"].(string)

		toolUseBlocks := []map[string]any{}
		for _, block := range content {
			b, _ := block.(map[string]any)
			switch b["type"] {
			case "text":
				if t, ok := b["text"].(string); ok && t != "" {
					if finalText != "" {
						finalText += "\n\n"
					}
					finalText += t
				}
			case "tool_use":
				toolUseBlocks = append(toolUseBlocks, b)
			}
		}

		if stopReason != "tool_use" || len(toolUseBlocks) == 0 {
			return finalText, toolCalls, inputTokens, outputTokens, nil
		}

		anthMsgs = append(anthMsgs, map[string]any{"role": "assistant", "content": content})

		toolResultBlocks := []map[string]any{}
		for _, tu := range toolUseBlocks {
			toolName, _ := tu["name"].(string)
			toolID, _ := tu["id"].(string)
			args, _ := tu["input"].(map[string]any)
			result, callOK := dispatchTool(c, userID, "user", toolName, args)
			toolCalls = append(toolCalls, toolCallResult{
				Name: toolName, Args: args, Result: result, OK: callOK,
			})
			payload, _ := json.Marshal(result)
			toolResultBlocks = append(toolResultBlocks, map[string]any{
				"type":        "tool_result",
				"tool_use_id": toolID,
				"content":     string(payload),
				"is_error":    !callOK,
			})
		}
		anthMsgs = append(anthMsgs, map[string]any{"role": "user", "content": toolResultBlocks})
	}

	if finalText == "" {
		finalText = "(sub-agent hit max iterations without producing a final answer)"
	}
	return finalText, toolCalls, inputTokens, outputTokens, nil
}
