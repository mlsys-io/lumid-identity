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
	"time"

	"github.com/gin-gonic/gin"
)

const (
	subAgentMaxIterations = 5
	subAgentTimeout       = 45 * time.Second
	subAgentMaxTokens     = 4096
)

// subAgentDefaultTools — sane read-only + research subset for a
// sub-agent that wasn't given an explicit `tools[]` filter. State-
// mutating tools (send_email, install_app, etc.) are intentionally
// excluded; parent agent owns those.
var subAgentDefaultTools = map[string]bool{
	"web_search":          true,
	"web_fetch":           true,
	"deep_research":       true,
	"query_findata":       true,
	"query_my_knowledge":  true,
	"code_run":            true,
	"list_apps":           true,
	"list_drafts":         true,
	"list_recent_cycles":  true,
	"list_marketplace":    true,
	"list_workflows":      true,
	"workflow_detail":     true,
	"list_runs":           true,
	"run_detail":          true,
	"workflow_report_card":true,
	"today_summary":       true,
	"search_marketplace":  true,
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
//   task         string  required — the focused job for the sub-agent
//   tools        []string optional — whitelist; default = subAgentDefaultTools
//   agent_id     string  optional — ground the sub-agent in this xpio agent
//   max_iter     int     optional — cap on tool-use loop (default 5, max 5)
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
			"error":       runErr.Error(),
			"reply":       finalText, // partial reply if any
			"tool_calls":  toolCalls,
			"input_tokens": inTok,
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
			result, callOK := dispatchTool(c, userID, toolName, args)
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
