package handler

// /api/v1/me/agent/* — conversational shell. The "natural interaction"
// layer that replaces button-and-form crutches in the 5-tab dashboard.
//
// POST /api/v1/me/agent/chat
//   Body: {"messages": [{"role":"user","content":"..."}, ...]}
//   Returns: {"reply": "...", "tool_calls": [...], "usage": {...}}
//
// The user talks; the agent calls /me/* tools on their behalf. Same
// backend write surface that a hypothetical UI button would hit, just
// reached via natural-language intent instead of a click.
//
// Architecture:
//   1. We forward to Anthropic Messages API (api.anthropic.com/v1/messages)
//      with a system prompt + tools[] definitions + the user's
//      conversation history.
//   2. If Claude returns a tool_use block, we execute the tool locally
//      against the calling user's tenant root + the existing /me/*
//      handler logic, append the tool_result to the conversation, and
//      call Claude again. Loop until Claude returns a plain text block.
//   3. We track total tokens used + write to a usage_events row for
//      the per-user budget cap (P4 follow-up).
//
// Server-funded: every user's chat uses the operator's Anthropic key
// (ANTHROPIC_API_KEY env, or read from /home/webmaster/.api_keys/anthropic
// as a fallback). Per-user daily token budget enforcement lands as a
// follow-up — for now, every chat just hits the operator's account.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	anthropicEndpoint    = "https://api.anthropic.com/v1/messages"
	anthropicVersion     = "2023-06-01"
	anthropicModel       = "claude-haiku-4-5-20251001"
	maxToolLoopIterations = 6 // safety bound — agent shouldn't need >6 tool calls per turn
	maxTokensPerTurn     = 4096
)

type chatMessage struct {
	Role    string `json:"role"`              // "user" | "assistant"
	Content string `json:"content,omitempty"` // for the simple text-only frontend
	// content_blocks (Anthropic's structured form) is what we use
	// internally during the tool-use loop. The frontend sends only
	// flat `content` text; we promote to blocks server-side.
}

type meAgentChatBody struct {
	Messages []chatMessage `json:"messages" binding:"required"`
}

type toolCallResult struct {
	Name   string         `json:"name"`
	Args   map[string]any `json:"args"`
	Result map[string]any `json:"result"`
	OK     bool           `json:"ok"`
}

// POST /api/v1/me/agent/chat
func MeAgentChat(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body meAgentChatBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if len(body.Messages) == 0 {
		fail(c, http.StatusBadRequest, 1400, "messages required")
		return
	}
	if len(body.Messages) > 50 {
		fail(c, http.StatusBadRequest, 1400, "history too long (>50 turns)")
		return
	}

	apiKey, err := anthropicKey()
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503,
			"chat unavailable: "+err.Error()+
				". Operator must set ANTHROPIC_API_KEY or place key at /home/webmaster/.api_keys/anthropic.")
		return
	}

	// Daily token budget — server-funded LLM. Default 50K total
	// tokens/24h/user. Override via ANTHROPIC_DAILY_TOKEN_BUDGET env;
	// 0 disables the cap entirely (for operator/super_admin use).
	budget := dailyTokenBudget()
	if budget > 0 {
		used := tokensUsedLast24h(userID)
		if used >= budget {
			c.Header("X-Budget-Used", strconv.Itoa(used))
			c.Header("X-Budget-Limit", strconv.Itoa(budget))
			c.Header("X-Budget-Reset", time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339))
			fail(c, http.StatusTooManyRequests, 1429,
				fmt.Sprintf("daily chat budget exhausted (%d / %d tokens used in last 24h)", used, budget))
			return
		}
	}

	// Build Anthropic-format messages from the simple frontend shape.
	// Tool-use loop will append assistant + tool_result turns into this
	// list as it iterates.
	anthMsgs := make([]map[string]any, 0, len(body.Messages))
	for _, m := range body.Messages {
		anthMsgs = append(anthMsgs, map[string]any{
			"role":    m.Role,
			"content": m.Content,
		})
	}

	systemPrompt := buildSystemPrompt(userID)
	tools := buildToolDefs()
	toolCalls := []toolCallResult{}
	totalInputTokens := 0
	totalOutputTokens := 0
	finalText := ""

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Tool-use loop.
	for i := 0; i < maxToolLoopIterations; i++ {
		req := map[string]any{
			"model":      anthropicModel,
			"max_tokens": maxTokensPerTurn,
			"system":     systemPrompt,
			"messages":   anthMsgs,
			"tools":      tools,
		}
		resp, err := callAnthropic(ctx, apiKey, req)
		if err != nil {
			fail(c, http.StatusBadGateway, 1502, "anthropic call: "+err.Error())
			return
		}
		if usage, ok := resp["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				totalInputTokens += int(v)
			}
			if v, ok := usage["output_tokens"].(float64); ok {
				totalOutputTokens += int(v)
			}
		}

		content, _ := resp["content"].([]any)
		stopReason, _ := resp["stop_reason"].(string)

		// If the agent produced any text, capture it. Tool use can be
		// interleaved with text in Claude's responses.
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
			break // agent is done; finalText holds the reply
		}

		// Add the assistant turn (with tool_use blocks) to history.
		anthMsgs = append(anthMsgs, map[string]any{
			"role":    "assistant",
			"content": content,
		})

		// Execute each tool call and append tool_result blocks.
		toolResultBlocks := []map[string]any{}
		for _, tu := range toolUseBlocks {
			toolName, _ := tu["name"].(string)
			toolID, _ := tu["id"].(string)
			args, _ := tu["input"].(map[string]any)

			result, callOK := dispatchTool(c, userID, toolName, args)
			toolCalls = append(toolCalls, toolCallResult{
				Name:   toolName,
				Args:   args,
				Result: result,
				OK:     callOK,
			})
			payload, _ := json.Marshal(result)
			toolResultBlocks = append(toolResultBlocks, map[string]any{
				"type":        "tool_result",
				"tool_use_id": toolID,
				"content":     string(payload),
				"is_error":    !callOK,
			})
		}
		anthMsgs = append(anthMsgs, map[string]any{
			"role":    "user",
			"content": toolResultBlocks,
		})
		// Loop continues — Claude sees the tool results, may call more
		// tools or produce a text reply.
	}

	if finalText == "" && len(toolCalls) > 0 {
		finalText = "Done."
	}

	// Record usage for the daily-budget cap. Best-effort — a DB write
	// failure shouldn't fail the chat response.
	if totalInputTokens+totalOutputTokens > 0 {
		_ = recordUsage(userID, "chat", "/me/agent/chat", anthropicModel,
			totalInputTokens, totalOutputTokens)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"reply":      finalText,
			"tool_calls": toolCalls,
			"usage": gin.H{
				"input_tokens":  totalInputTokens,
				"output_tokens": totalOutputTokens,
				"budget_used":   tokensUsedLast24h(userID),
				"budget_limit":  dailyTokenBudget(),
			},
		},
	})
}

// dailyTokenBudget returns the per-user 24h cap on chat tokens, in
// total tokens (input + output). 0 means "no cap".
func dailyTokenBudget() int {
	v := strings.TrimSpace(os.Getenv("ANTHROPIC_DAILY_TOKEN_BUDGET"))
	if v == "" {
		return 50_000
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n
	}
	return 50_000
}

// tokensUsedLast24h sums input + output across all usage_events rows
// for this user with ts > now - 24h. Returns 0 on DB error so a
// transient failure doesn't lock the user out.
func tokensUsedLast24h(userSub string) int {
	cutoff := time.Now().Add(-24 * time.Hour)
	var totals struct {
		Inp int
		Out int
	}
	row := common.DB.
		Model(&models.UsageEvent{}).
		Where("user_sub = ? AND ts > ?", userSub, cutoff).
		Select("COALESCE(SUM(input_tokens), 0) as inp, COALESCE(SUM(output_tokens), 0) as out").
		Row()
	if row != nil {
		_ = row.Scan(&totals.Inp, &totals.Out)
	}
	return totals.Inp + totals.Out
}

// recordUsage appends one usage_events row. Safe to call concurrently.
func recordUsage(userSub, kind, endpoint, model string, inTok, outTok int) error {
	ev := models.UsageEvent{
		UserSub:      userSub,
		Kind:         kind,
		Endpoint:     endpoint,
		Model:        model,
		InputTokens:  inTok,
		OutputTokens: outTok,
		// Cost in cents — Haiku 4.5 is roughly $0.25/M input, $1.25/M
		// output (May 2026). Round up to integer cents; finer
		// accounting can come later if it matters.
		CostCents: (inTok*25 + outTok*125) / 1_000_000,
	}
	return common.DB.Create(&ev).Error
}

// anthropicKey resolves the API key from env first, then from
// /home/webmaster/.api_keys/anthropic on disk (mode 0600 file with the
// raw key as the first line).
func anthropicKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); k != "" {
		return k, nil
	}
	if b, err := os.ReadFile("/home/webmaster/.api_keys/anthropic"); err == nil {
		key := strings.TrimSpace(strings.Split(string(b), "\n")[0])
		if key != "" {
			return key, nil
		}
	}
	return "", fmt.Errorf("no ANTHROPIC_API_KEY set")
}

// callAnthropic POSTs to the Messages API. Returns the parsed JSON body
// on 2xx, or an error otherwise (including the response body for debug).
func callAnthropic(ctx context.Context, apiKey string, body map[string]any) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicEndpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	respBody, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("anthropic %d: %s", r.StatusCode, string(respBody[:min(400, len(respBody))]))
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildSystemPrompt — the agent's persona + a snapshot of the user's
// current app inventory so it has context without an extra tool call.
func buildSystemPrompt(userID string) string {
	apps := []string{}
	// Caller's tenant first.
	if entries, err := os.ReadDir(tenantAppsDir(userID)); err == nil {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				apps = append(apps, e.Name())
			}
		}
	}
	tenantList := "(none)"
	if len(apps) > 0 {
		tenantList = strings.Join(apps, ", ")
	}

	return `You are the LumidOS assistant — a focused helper that automates the user's intent via xpio apps.

You have tools to:
  - list, install, uninstall apps from xp.io
  - start, stop, or fire one-shot cycles on loops
  - record the user's feedback on cycles (Hook 2 — what worked, what to change)
  - query recent cycle results

When the user expresses an intent, prefer doing the work via tools over describing how they could do it themselves. Confirm what you did in 1-2 sentences after each action.

The user already has these apps installed in their tenant: ` + tenantList + `

When you don't know an app's slug, call list_marketplace first. When the user gives ambiguous feedback ("today was off"), capture it as a feedback note on the most recent cycle of the most likely loop and tell them you did so — they can refine later.

Stay grounded: don't invent apps, loops, or features. If a tool fails, surface the error briefly and suggest the next step.`
}

// buildToolDefs — the Anthropic-format tool schema.
func buildToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_apps",
			"description": "List the user's installed xpio apps (their tenant + operator-shared).",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "install_app",
			"description": "Install an xpio app from xp.io into the user's tenant. Use list_marketplace first if you don't know the slug.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string", "description": "owner_sub/name or first-party shorthand (e.g. 'personal-agent')"},
					"as":   map[string]any{"type": "string", "description": "optional rename"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "uninstall_app",
			"description": "Remove an installed app from the user's tenant.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "run_loop_now",
			"description": "Fire a one-shot cycle of a loop without waiting for the schedule.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string"},
					"loop": map[string]any{"type": "string"},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "give_feedback",
			"description": "Record the user's feedback on a cycle. Use after the user says something evaluative about a result. Rating: -1 bad, 0 neutral, +1 good.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":    map[string]any{"type": "string"},
					"loop":   map[string]any{"type": "string"},
					"ts":     map[string]any{"type": "string", "description": "Cycle timestamp dir name, e.g. 20260522T150000Z. Use 'latest' to target the most recent cycle of that loop."},
					"rating": map[string]any{"type": "integer", "enum": []int{-1, 0, 1}},
					"note":   map[string]any{"type": "string", "description": "The user's natural-language feedback. Quote them when possible."},
				},
				"required": []string{"app", "loop", "ts", "note"},
			},
		},
		{
			"name":        "list_recent_cycles",
			"description": "List the most recent cycle timestamps for a loop. Useful before give_feedback to find the right ts.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string"},
					"loop":  map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer", "default": 5},
				},
				"required": []string{"app", "loop"},
			},
		},
		{
			"name":        "list_marketplace",
			"description": "Browse the xp.io marketplace for apps to install. Returns slug + summary.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":     map[string]any{"type": "string", "description": "search keyword"},
					"limit": map[string]any{"type": "integer", "default": 10},
				},
			},
		},
		{
			"name":        "query_my_knowledge",
			"description": "Search the user's accumulated knowledge banks. Returns matching memory snippets with their agent/source. Use when the user asks 'what did I learn about X' or when you need prior context before suggesting an action.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":    map[string]any{"type": "string", "description": "search terms — keyword match for now"},
					"agent":    map[string]any{"type": "string", "description": "optional: scope to a specific agent (e.g. 'admin-personal-assistant')"},
					"limit":    map[string]any{"type": "integer", "default": 6},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "subscribe_to_bank",
			"description": "Subscribe to another tenant's public knowledge bank on xp.io. Memories from the source flow into the target agent on its next cycle, giving the user the benefit of other users' patterns without manual curation. Hook 3 (silent compounding intelligence).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"source_slug":      map[string]any{"type": "string", "description": "xp.io repo slug of the bank to subscribe to (owner_sub/bank-name)"},
					"target_agent_id": map[string]any{"type": "string", "description": "local agent id that should receive the imported memories. If absent, defaults to the agent whose name matches the source bank's name."},
				},
				"required": []string{"source_slug"},
			},
		},
		// Phase S6c — close the gap between "show me" and "do it for me".
		// Drafts, loop tuning, and the today summary are the natural-
		// language commands users reach for: "send Alice's draft",
		// "pause cc_watcher for the weekend", "what's pending?".
		{
			"name":        "today_summary",
			"description": "Return the user's headlines + recent cycles + drafts-pending count in one shot. Use when the user asks 'what's pending', 'what's new', or 'what did my AI do today?'.",
			"input_schema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "list_drafts",
			"description": "List the user's pending email/calendar drafts the AI has proposed but not yet sent. Each draft has id, subject, to, body, app. Use when the user asks about pending replies or wants you to act on a specific one.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string", "description": "optional — limit to one app's drafts"},
				},
			},
		},
		{
			"name":        "send_draft",
			"description": "Send a drafted email/event by id. The send goes through the user's OAuth grant — irreversible. Confirm with the user before calling unless they explicitly said 'send'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string", "description": "draft id from list_drafts"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "edit_draft",
			"description": "Rewrite a draft's body or subject. State resets to pending (the user still has to send it). Use when the user wants a tone shift, more detail, or a quick fix.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":      map[string]any{"type": "string"},
					"body":    map[string]any{"type": "string", "description": "new body text"},
					"subject": map[string]any{"type": "string", "description": "optional new subject"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "dismiss_draft",
			"description": "Mark a draft dismissed — no send, no further nudges. Use when the user says 'skip', 'ignore', 'not this one'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "patch_loop",
			"description": "Change a loop's schedule or pause/resume it. Writes to .user-overrides.yaml; the underlying app stays untouched. Use for 'pause cc_watcher', 'change morning_brief to 7am', 'resume hourly_triage'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string"},
					"loop":     map[string]any{"type": "string"},
					"schedule": map[string]any{"type": "string", "description": "cron expression, e.g. '0 8 * * *'"},
					"enabled":  map[string]any{"type": "boolean", "description": "true to resume, false to pause"},
				},
				"required": []string{"app", "loop"},
			},
		},
	}
}

// dispatchTool routes the agent's tool calls into local /me/* logic.
// Returns (result, ok). result is always a JSON-able map; on failure
// it contains {"error": "..."} and ok is false.
func dispatchTool(c *gin.Context, userID, name string, args map[string]any) (map[string]any, bool) {
	switch name {
	case "list_apps":
		return toolListApps(userID), true

	case "install_app":
		slug, _ := args["slug"].(string)
		asName, _ := args["as"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		id := writeIntentDirect(userID, "install", map[string]any{
			"slug": slug, "runtime": "local", "as": asName,
		})
		if id == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{"intent_id": id, "status": "pending", "note": "Tell the user the install is in progress; it usually finishes in 5-15 seconds."}, true

	case "uninstall_app":
		app, _ := args["app"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		id := writeIntentDirect(userID, "uninstall", map[string]any{"app": app})
		if id == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{"intent_id": id, "status": "pending"}, true

	case "run_loop_now":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		if app == "" || loop == "" {
			return map[string]any{"error": "app and loop required"}, false
		}
		jobID, err := agentEnqueueOneshot(userID, app, loop)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"job_id": jobID, "state": "queued"}, true

	case "give_feedback":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		ts, _ := args["ts"].(string)
		note, _ := args["note"].(string)
		rating := 0
		if v, ok := args["rating"].(float64); ok {
			rating = int(v)
		}
		if app == "" || loop == "" || ts == "" {
			return map[string]any{"error": "app/loop/ts required"}, false
		}
		if ts == "latest" {
			resolved, err := agentLatestCycleTs(userID, app, loop)
			if err != nil {
				return map[string]any{"error": "no recent cycles for " + app + "." + loop}, false
			}
			ts = resolved
		}
		if err := agentWriteFeedback(userID, app, loop, ts, rating, note); err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"saved": true, "app": app, "loop": loop, "ts": ts}, true

	case "list_recent_cycles":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		limit := 5
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		return map[string]any{"cycles": agentListCycles(userID, app, loop, limit)}, true

	case "list_marketplace":
		q, _ := args["q"].(string)
		limit := 10
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		return map[string]any{"items": agentListMarketplace(q, limit)}, true

	case "query_my_knowledge":
		query, _ := args["query"].(string)
		agent, _ := args["agent"].(string)
		limit := 6
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		if query == "" {
			return map[string]any{"error": "query required"}, false
		}
		hits := agentQueryKnowledge(userID, query, agent, limit)
		return map[string]any{"hits": hits, "count": len(hits)}, true

	case "subscribe_to_bank":
		src, _ := args["source_slug"].(string)
		target, _ := args["target_agent_id"].(string)
		if src == "" {
			return map[string]any{"error": "source_slug required"}, false
		}
		intentID := writeIntentDirect(userID, "subscribe_bank", map[string]any{
			"source_slug":     src,
			"target_agent_id": target,
		})
		if intentID == "" {
			return map[string]any{"error": "intent write failed"}, false
		}
		return map[string]any{
			"intent_id": intentID,
			"status":    "pending",
			"note":      "Subscribe queued — memories will flow on the next cycle. Tell the user it may take a moment.",
		}, true

	// ── Phase S6c new tools ────────────────────────────────────────

	case "today_summary":
		return toolTodaySummary(userID), true

	case "list_drafts":
		app, _ := args["app"].(string)
		return toolListDrafts(userID, app), true

	case "send_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		return toolDraftAction(userID, id, "send", nil), true

	case "dismiss_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		return toolDraftAction(userID, id, "dismiss", nil), true

	case "edit_draft":
		id, _ := args["id"].(string)
		if id == "" {
			return map[string]any{"error": "id required"}, false
		}
		body, _ := args["body"].(string)
		subject, _ := args["subject"].(string)
		patch := map[string]any{}
		if body != "" {
			patch["body"] = body
		}
		if subject != "" {
			patch["subject"] = subject
		}
		if len(patch) == 0 {
			return map[string]any{"error": "provide body or subject"}, false
		}
		return toolDraftAction(userID, id, "edit", patch), true

	case "patch_loop":
		app, _ := args["app"].(string)
		loop, _ := args["loop"].(string)
		if app == "" || loop == "" {
			return map[string]any{"error": "app and loop required"}, false
		}
		patch := map[string]any{}
		if v, ok := args["schedule"].(string); ok && v != "" {
			patch["schedule"] = v
		}
		if v, ok := args["enabled"].(bool); ok {
			patch["enabled"] = v
		}
		if len(patch) == 0 {
			return map[string]any{"error": "provide schedule or enabled"}, false
		}
		return toolPatchLoop(userID, app, loop, patch), true
	}
	return map[string]any{"error": "unknown tool: " + name}, false
}
