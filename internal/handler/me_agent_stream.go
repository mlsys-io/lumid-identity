package handler

// /api/v1/me/agent/chat/stream — SSE streaming variant of /me/agent/chat.
//
// Why HTTP streaming, not WebSocket:
//   - The interaction is "user sends message, server streams reply" —
//     unidirectional after the request. SSE/chunked HTTP fits this
//     better than the WS upgrade dance.
//   - Browser EventSource doesn't allow POST bodies, so we use
//     fetch() + response.body.getReader() on the client. Same effect,
//     no special server-side library.
//
// Wire format (server emits one JSON object per line, prefixed):
//   data: {"type":"text","delta":"Hello"}
//   data: {"type":"text","delta":" world"}
//   data: {"type":"tool_call","name":"...","args":{...},"result":{...},"ok":true}
//   data: {"type":"usage","input_tokens":N,"output_tokens":M,"budget_used":X,"budget_limit":Y}
//   data: {"type":"done"}
//   data: {"type":"error","message":"..."}
//
// Anthropic's own streaming format is parsed here; we re-emit a
// flattened shape so the client doesn't have to know Anthropic's
// content-block-delta protocol.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MeAgentChatStream is the streaming sibling of MeAgentChat. Same
// auth, body shape, tool-use loop, and budget enforcement — different
// transport.
func MeAgentChatStream(c *gin.Context) {
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
	stashViewingApp(c, body.Context)
	if len(body.Messages) == 0 || len(body.Messages) > 50 {
		fail(c, http.StatusBadRequest, 1400, "messages required, ≤50 turns")
		return
	}

	role := currentUserRole(c)
	provider := resolveProvider(body.Model, role)
	provider, autoRouted := autoRouteForTurn(body.Messages, provider, role, body.Context)
	apiKey, err := provider.keyFn()
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, "chat unavailable: "+err.Error())
		return
	}

	budget := effectiveDailyBudget(provider)
	if budget > 0 && role != "super_admin" {
		used := tokensUsedLast24h(userID)
		if used >= budget {
			c.Header("X-Budget-Used", strconv.Itoa(used))
			c.Header("X-Budget-Limit", strconv.Itoa(budget))
			fail(c, http.StatusTooManyRequests, 1429,
				fmt.Sprintf("daily chat budget exhausted (%d / %d)", used, budget))
			return
		}
	}

	// SSE headers + immediate flush so the browser doesn't buffer.
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	// Reverse-proxy hint: nginx in front of us would buffer otherwise.
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeader(http.StatusOK)
	c.Writer.Flush()

	emit := func(payload map[string]any) bool {
		b, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", b); err != nil {
			return false
		}
		c.Writer.Flush()
		return true
	}

	// Promote frontend's flat content (+ attachments) into Anthropic's
	// message shape — images become image blocks, text files become
	// fenced inline blocks, PDFs become document blocks on Claude or
	// pdftotext-extracted fenced text on non-Claude, the user's typed
	// text closes each turn.
	anthMsgs := make([]map[string]any, 0, len(body.Messages))
	for _, m := range body.Messages {
		anthMsgs = append(anthMsgs, chatMessageToAnthropic(m, provider))
	}

	basePrompt, tools, _ := resolvePromptAndTools(userID, role, body)
	systemPrompt := basePrompt + modeSystemSuffix(body.Mode) + toolHintSuffix(provider)
	totalInputTokens := 0
	totalOutputTokens := 0

	// 30 min — deep agentic loops (50 iterations), long claude-code Opus
	// runs, and pause-for-approval all need headroom; SSE keeps the
	// connection alive with deltas.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Minute)
	defer cancel()

	// Surface the routing decision immediately. When auto_routed=true,
	// the UI can show "answered by Claude (auto — has image)" instead
	// of the user's selected MiniMax. Sent once, before any text.
	emit(map[string]any{
		"type":        "route",
		"model_used":  provider.id,
		"auto_routed": autoRouted,
	})

	// claude-code-* delegates to the local claude CLI via the host proxy.
	// Claude's own built-in tools (Bash, Read, Write, WebSearch) replace the
	// me_agent tool list; the system prompt is passed as context only.
	if isClaudeCodeProvider(provider) {
		_ = tools // not used for this provider
		// This turn stayed in Claude Code mode (it wasn't a platform-control or
		// drill-in request — those auto-route to a tool-capable model upstream in
		// autoRouteForTurn). Claude's own file/shell tools are in play here; a
		// gentle, accurate note so an admin knows platform actions DO work — they
		// just hop to a standard model automatically when asked.
		if role == "admin" || role == "super_admin" {
			emit(map[string]any{
				"type":  "notice",
				"level": "info",
				"message": "Claude Code mode uses Claude's own file/shell tools. Ask it to install, " +
					"run, publish, or edit something and that action auto-runs on a standard model — " +
					"no need to switch manually.",
			})
		}
		if err := streamClaudeCodeViaProxy(ctx, c, userID, role, body.Messages, systemPrompt, provider.upstreamModel, body.ClaudeSessionID, emit); err != nil {
			emit(map[string]any{"type": "error", "message": err.Error()})
		}
		emit(map[string]any{"type": "done"})
		return
	}

	for i := 0; i < maxToolLoopIterations; i++ {
		// Stop the moment the client is gone — otherwise the loop keeps making
		// upstream LLM calls and dispatching (possibly destructive) tools for a
		// disconnected user, burning budget with nothing reading the result.
		if ctx.Err() != nil {
			return
		}
		maxTok := maxTokensPerTurn
		if provider.maxOutputTokens > 0 {
			maxTok = provider.maxOutputTokens
		}
		if body.Think && provider.addAnthropicVersion {
			maxTok = thinkingMaxTokens
		}
		req := map[string]any{
			"model":      provider.upstreamModel,
			"max_tokens": maxTok,
			"system":     systemPrompt,
			"messages":   anthMsgs,
			"tools":      tools,
			"stream":     true,
		}
		if body.Think && provider.addAnthropicVersion {
			req["thinking"] = map[string]any{
				"type":          "enabled",
				"budget_tokens": thinkingBudgetTokens,
			}
		}
		stopReason, toolUses, assistantBlocks, inTok, outTok, err := streamOneAnthropicTurn(
			ctx, provider, apiKey, req, emit,
		)
		totalInputTokens += inTok
		totalOutputTokens += outTok

		if err != nil {
			// Surface upstream detail server-side too — the browser gets a
			// friendly message, but ops needs the real provider/status/body to
			// debug a kv.run cold-start / MiniMax 503 / Anthropic 429.
			log.Printf("[me-agent] stream turn failed provider=%s user=%s err=%v", provider.id, userID, err)
			emit(map[string]any{"type": "error", "message": err.Error()})
			break
		}
		if stopReason != "tool_use" || len(toolUses) == 0 {
			break // done — final text already emitted as deltas
		}

		// Echo the assistant turn (with tool_use blocks) into history.
		anthMsgs = append(anthMsgs, map[string]any{"role": "assistant", "content": assistantBlocks})

		// Execute tools + emit + append tool_result blocks.
		toolResultBlocks := []map[string]any{}
		for _, tu := range toolUses {
			// The model emitted malformed tool arguments (truncated stream from a
			// thinking model, etc.). Don't dispatch with garbage input — report it
			// as an error tool_result so the model can retry with valid args,
			// instead of running e.g. an install/qa_call with no real fields.
			if _, bad := tu.input["_parse_error"]; bad {
				log.Printf("[me-agent] tool=%s user=%s — invalid tool arguments from model, skipping dispatch", tu.name, userID)
				result := map[string]any{"error": "the model produced invalid (unparseable) tool arguments — retry with valid JSON"}
				emit(map[string]any{"type": "tool_call", "name": tu.name, "args": tu.input, "result": result, "ok": false})
				payload, _ := json.Marshal(result)
				toolResultBlocks = append(toolResultBlocks, map[string]any{
					"type": "tool_result", "tool_use_id": tu.id,
					"content": string(payload), "is_error": true,
				})
				continue
			}
			// For destructive tools: pause and wait for user approval —
			// unless the user has a persistent "always allow" grant for
			// this tool (POST tool-approve with always=true; revocable
			// via DELETE /me/agent/tool-grants/:name).
			if destructiveTools[tu.name] && !hasToolGrant(userID, tu.name) {
				approvalID := uuid.New().String()
				ch := requestApproval(approvalID, userID, tu.name)
				emit(map[string]any{
					"type":        "tool_approval_required",
					"id":          tu.id,
					"approval_id": approvalID,
					"name":        tu.name,
					"args":        tu.input,
				})
				// Hybrid wait: local channel (same-pod) OR 1s DB poll (the
				// approve POST may land on the other replica), 10-min deadline.
				// awaitApproval tears down channel + row on every exit path.
				approved := awaitApproval(ctx, approvalID, ch)
				if !approved {
					// Audit the denial/timeout — dispatchTool never runs, so the
					// [app-ops] audit line can't cover this. Greppable as [me-agent].
					log.Printf("[me-agent] approval denied/timeout tool=%s user=%s", tu.name, userID)
					result := map[string]any{"error": "user denied permission for " + tu.name}
					emit(map[string]any{"type": "tool_call", "name": tu.name, "args": tu.input, "result": result, "ok": false})
					payload, _ := json.Marshal(result)
					toolResultBlocks = append(toolResultBlocks, map[string]any{
						"type": "tool_result", "tool_use_id": tu.id,
						"content": string(payload), "is_error": true,
					})
					continue
				}
			}
			// By here the tool is cleared to run (non-destructive, an "always"
			// grant, or freshly approved). Mark it so the dispatchTool backstop
			// (which fail-closes destructive tools on un-gated transports) lets
			// THIS call through. Per-tool + synchronous, so no cross-tool leak.
			c.Set("approved_tool", tu.name)
			result, callOK := dispatchTool(c, userID, role, tu.name, tu.input)
			ev := map[string]any{
				"type":   "tool_call",
				"name":   tu.name,
				"args":   tu.input,
				"result": result,
				"ok":     callOK,
			}
			// 3a — server-authoritative refetch: on a successful mutating tool,
			// tell the client which data scopes to invalidate so a new tool needs
			// no frontend wiring (the client falls back to its own map otherwise).
			if callOK {
				if scopes := toolDataScopesFor(tu.name); len(scopes) > 0 {
					ev["scopes"] = scopes
				}
			}
			emit(ev)
			payload, _ := json.Marshal(result)
			toolResultBlocks = append(toolResultBlocks, map[string]any{
				"type":        "tool_result",
				"tool_use_id": tu.id,
				"content":     string(payload),
				"is_error":    !callOK,
			})
		}
		anthMsgs = append(anthMsgs, map[string]any{"role": "user", "content": toolResultBlocks})
	}

	// Record usage (best-effort; failure doesn't break the stream).
	if totalInputTokens+totalOutputTokens > 0 {
		_ = recordUsage(userID, "chat", "/me/agent/chat/stream", provider.upstreamModel, totalInputTokens, totalOutputTokens)
	}

	emit(map[string]any{
		"type":          "usage",
		"input_tokens":  totalInputTokens,
		"output_tokens": totalOutputTokens,
		"budget_used":   tokensUsedLast24h(userID),
		"budget_limit":  budget,
		"model_used":    provider.id,
		"auto_routed":   autoRouted,
	})
	emit(map[string]any{"type": "done"})
}

// streamingToolUse captures a tool_use block built up across multiple
// content_block_delta events. Anthropic streams the tool's args as
// a sequence of partial_json deltas; we accumulate and parse at
// content_block_stop.
type streamingToolUse struct {
	id      string
	name    string
	jsonBuf strings.Builder
	input   map[string]any
}

// streamOneAnthropicTurn POSTs to /v1/messages with stream:true, reads
// the SSE response, forwards text deltas to the caller via emit(), and
// returns:
//   - stopReason ("end_turn" | "tool_use" | ...)
//   - the list of completed tool_use blocks (with parsed input)
//   - the assistant_blocks list for re-injection into anthMsgs on the
//     next tool-use iteration
//   - input/output token counts
//   - error (if any HTTP / parse failure)
func streamOneAnthropicTurn(
	ctx context.Context, p llmProvider, apiKey string, body map[string]any,
	emit func(map[string]any) bool,
) (string, []streamingToolUse, []map[string]any, int, int, error) {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(string(buf)))
	if err != nil {
		return "", nil, nil, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(p.authHeader, p.authPrefix+apiKey)
	if p.addAnthropicVersion {
		req.Header.Set("anthropic-version", anthropicVersion)
	}
	req.Header.Set("Accept", "text/event-stream")

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, nil, 0, 0, err
	}
	defer r.Body.Close()
	if r.StatusCode >= 300 {
		body, _ := io.ReadAll(r.Body)
		return "", nil, nil, 0, 0, fmt.Errorf("%s %d: %.300s", p.id, r.StatusCode, string(body))
	}

	// Parser state — Anthropic's SSE has fields by content_block index.
	currentBlocks := map[int]string{} // index -> "text" | "tool_use"
	toolUses := map[int]*streamingToolUse{}
	assistantBlocks := []map[string]any{} // text + tool_use blocks for next-turn reinjection
	stopReason := ""
	inputTokens := 0
	outputTokens := 0

	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var eventType string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			eventType = strings.TrimPrefix(line, "event: ")
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(payload), &msg); err != nil {
			continue // skip malformed line
		}

		switch eventType {
		case "message_start":
			if m, ok := msg["message"].(map[string]any); ok {
				if u, ok := m["usage"].(map[string]any); ok {
					if v, ok := u["input_tokens"].(float64); ok {
						inputTokens = int(v)
					}
				}
			}

		case "content_block_start":
			idx := intOf(msg["index"])
			block, _ := msg["content_block"].(map[string]any)
			bt, _ := block["type"].(string)
			currentBlocks[idx] = bt
			if bt == "tool_use" {
				id, _ := block["id"].(string)
				name, _ := block["name"].(string)
				toolUses[idx] = &streamingToolUse{id: id, name: name}
				// Tell the UI "agent is about to call this tool" so it
				// can render a spinner with the tool name before args
				// finish streaming. Args land via the matching
				// tool_call event after dispatchTool returns.
				emit(map[string]any{"type": "tool_start", "name": name, "id": id})
			} else if bt == "thinking" {
				// Open a thinking block in the UI. Deltas follow.
				emit(map[string]any{"type": "thinking_start"})
			}

		case "content_block_delta":
			idx := intOf(msg["index"])
			delta, _ := msg["delta"].(map[string]any)
			dt, _ := delta["type"].(string)
			switch dt {
			case "text_delta":
				if t, ok := delta["text"].(string); ok && t != "" {
					emit(map[string]any{"type": "text", "delta": t})
				}
			case "thinking_delta":
				// Extended thinking from Anthropic. kv.run/MiniMax emits
				// the same shape — both paths surface here.
				if t, ok := delta["thinking"].(string); ok && t != "" {
					emit(map[string]any{"type": "thinking", "delta": t})
				}
			case "input_json_delta":
				if pj, ok := delta["partial_json"].(string); ok {
					if tu := toolUses[idx]; tu != nil {
						tu.jsonBuf.WriteString(pj)
					}
				}
			}

		case "content_block_stop":
			idx := intOf(msg["index"])
			bt := currentBlocks[idx]
			if bt == "thinking" {
				// Close the thinking block — UI can collapse it now.
				emit(map[string]any{"type": "thinking_stop"})
			}
			if bt == "tool_use" {
				tu := toolUses[idx]
				if tu == nil {
					continue
				}
				raw := tu.jsonBuf.String()
				if raw == "" {
					raw = "{}"
				}
				if err := json.Unmarshal([]byte(raw), &tu.input); err != nil {
					tu.input = map[string]any{"_parse_error": err.Error(), "_raw": raw}
				}
				assistantBlocks = append(assistantBlocks, map[string]any{
					"type":  "tool_use",
					"id":    tu.id,
					"name":  tu.name,
					"input": tu.input,
				})
			}

		case "message_delta":
			if d, ok := msg["delta"].(map[string]any); ok {
				if sr, ok := d["stop_reason"].(string); ok && sr != "" {
					stopReason = sr
				}
			}
			if u, ok := msg["usage"].(map[string]any); ok {
				if v, ok := u["output_tokens"].(float64); ok {
					outputTokens = int(v)
				}
			}

		case "message_stop":
			// End of this turn's stream — fall through; outer loop
			// decides whether to fire another turn or stop.
		}
	}
	if err := sc.Err(); err != nil {
		return stopReason, nil, assistantBlocks, inputTokens, outputTokens, err
	}

	// Collect the completed tool_use blocks (those with non-nil input
	// AND a name) in index order so the caller fires them deterministically.
	completed := []streamingToolUse{}
	indices := []int{}
	for k := range toolUses {
		indices = append(indices, k)
	}
	// Sort ascending — same order Anthropic emitted them.
	for i := 0; i < len(indices); i++ {
		for j := i + 1; j < len(indices); j++ {
			if indices[j] < indices[i] {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}
	for _, idx := range indices {
		if tu := toolUses[idx]; tu != nil && tu.name != "" {
			completed = append(completed, *tu)
		}
	}

	return stopReason, completed, assistantBlocks, inputTokens, outputTokens, nil
}

// intOf coerces a JSON-decoded any to int (it'll be float64).
func intOf(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	}
	return 0
}
