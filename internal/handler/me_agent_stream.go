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
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Input ceilings for the streaming chat endpoint. Messages + base64
// attachments ride in one JSON document, so the body cap bounds both;
// the content caps stop a hostile turn from pushing megabytes of "text"
// into every downstream prompt build even when the body fits.
const (
	chatStreamMaxBodyBytes   = 1536 * 1024 // 1.5 MiB request body
	chatMaxMessageBytes      = 256 * 1024  // per-message typed content
	chatMaxTotalContentBytes = 1024 * 1024 // content summed across all turns
)

// Per-user live-stream ceiling. Per-pod counter — identity runs 2 replicas
// with no session affinity, so the effective cap is up to 2×; acceptable
// for an abuse backstop, not an exact quota.
const maxConcurrentChatStreams = 3

var (
	chatStreamsMu sync.Mutex
	chatStreams   = map[string]int{}
)

func acquireChatStream(userID string) bool {
	chatStreamsMu.Lock()
	defer chatStreamsMu.Unlock()
	if chatStreams[userID] >= maxConcurrentChatStreams {
		return false
	}
	chatStreams[userID]++
	return true
}

func releaseChatStream(userID string) {
	chatStreamsMu.Lock()
	if chatStreams[userID] > 1 {
		chatStreams[userID]--
	} else {
		delete(chatStreams, userID)
	}
	chatStreamsMu.Unlock()
}

// MeAgentChatStream is the streaming sibling of MeAgentChat. Same
// auth, body shape, tool-use loop, and budget enforcement — different
// transport.
func MeAgentChatStream(c *gin.Context) {
	// Stamped before the turn runs: run_ts should be when the user asked, not
	// when the last token arrived.
	turnStartedAt := time.Now()
	var turnToolCalls []toolCallResult
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	// Cap the body BEFORE decode — an unbounded JSON document is an OOM
	// lever on the auth authority.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, chatStreamMaxBodyBytes)
	var body meAgentChatBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	c.Set(ctxModeKey, chatMode(body.Context))
	stashViewingApp(c, body.Context)
	if len(body.Messages) == 0 || len(body.Messages) > 50 {
		fail(c, http.StatusBadRequest, 1400, "messages required, ≤50 turns")
		return
	}
	totalContent := 0
	for _, m := range body.Messages {
		if len(m.Content) > chatMaxMessageBytes {
			fail(c, http.StatusBadRequest, 1400,
				fmt.Sprintf("message content too large (max %d KiB per message)", chatMaxMessageBytes/1024))
			return
		}
		totalContent += len(m.Content)
	}
	if totalContent > chatMaxTotalContentBytes {
		fail(c, http.StatusBadRequest, 1400,
			fmt.Sprintf("conversation content too large (max %d KiB total)", chatMaxTotalContentBytes/1024))
		return
	}

	role := currentUserRole(c)
	provider, providerNote := resolveProviderWhy(body.Model, role)
	// Never let a downgrade be silent. A 200 carrying a model the caller
	// did not ask for is indistinguishable from success.
	if providerNote != "" {
		log.Printf("me_agent: provider downgrade: %s", providerNote)
	}
	provider, autoRouted := autoRouteForTurn(body.Messages, provider, role, body.Context, body.Mode)
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

	// Serialized: the pre-headers pinger (claude-code path) and the
	// direct-path heartbeat goroutine both write through this closure
	// alongside the main loop, and the SSE writer is not safe for
	// concurrent use.
	var emitMu sync.Mutex
	emit := func(payload map[string]any) bool {
		emitMu.Lock()
		defer emitMu.Unlock()
		b, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", b); err != nil {
			return false
		}
		c.Writer.Flush()
		return true
	}

	// Forced tool — run it, don't ask.
	//
	// tool_choice is passed to the provider, but the lumid-llm gateway (which
	// serves the default kvrun-gemma4) does not honour it: the parameter is
	// accepted and silently dropped, so a forced tool never fires. Measured —
	// tool_choice=app_answer returns a normal reply with tool_calls empty. That
	// makes model-side forcing unreliable by provider, which is exactly what a
	// UI control cannot depend on.
	//
	// So execute it here instead. The args these app tools need are already
	// known without the model: the app comes from the viewing context the client
	// sent, and the question/note is the user's own last message. Deterministic,
	// provider-independent, and one fewer round trip.
	if forced := strings.TrimSpace(body.ToolChoice); forced != "" {
		if res, handled := runForcedAppTool(c, userID, role, forced, body); handled {
			emit(map[string]any{"type": "tool_call", "name": forced, "result": res})
			if txt, _ := res["answer"].(string); txt != "" {
				emit(map[string]any{"type": "text", "text": txt})
			} else if nxt, _ := res["next"].(string); nxt != "" {
				emit(map[string]any{"type": "text", "text": nxt})
			} else if e, _ := res["error"].(string); e != "" {
				emit(map[string]any{"type": "text", "text": "That didn't work: " + e})
			}
			emit(map[string]any{"type": "done"})
			return
		}
	}

	// Record the correction before the model gets a say — see
	// autoStageCorrection. The turn then continues normally, so the user gets
	// both the draft and a real reply.
	stagedNote := ""
	if res, ok := autoStageCorrection(userID, body); ok {
		emit(map[string]any{"type": "tool_call", "name": "app_feedback", "result": res})
		stagedNote = stagedCorrectionNote(res)
	}

	if !acquireChatStream(userID) {
		emit(map[string]any{
			"type": "error", "code": "concurrent_streams",
			"message": fmt.Sprintf("too many simultaneous chats (max %d) — close one and retry", maxConcurrentChatStreams),
		})
		emit(map[string]any{"type": "done"})
		return
	}
	defer releaseChatStream(userID)

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
	// me_agent tool list, and the CLI reads files through its own tools —
	// so neither the tool catalog nor the Anthropic message promotion
	// (which forks pdftotext/pandoc per document attachment) is built on
	// this path. The system prompt IS used (passed as context).
	if isClaudeCodeProvider(provider) {
		basePrompt, _, _ := resolvePromptAndTools(userID, role, body, false)
		systemPrompt := basePrompt + modeSystemSuffix(body.Mode) + stagedNote
		// Liveness before the first upstream byte: the PAT mint (argon2id)
		// + a sandbox cold-start precede any NDJSON.
		if !emit(map[string]any{"type": "status", "status": "starting"}) {
			return
		}
		if err := streamClaudeCodeViaProxy(ctx, c, userID, role, body.Messages, systemPrompt, provider.upstreamModel, body.ClaudeSessionID, struct{ XpioRepo, ClusterID, DataApp string }{body.XpioRepo, body.ClusterID, body.DataApp}, emit); err != nil {
			emit(map[string]any{"type": "error", "message": err.Error()})
		}
		emit(map[string]any{"type": "done"})
		return
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

	basePrompt, tools, _ := resolvePromptAndTools(userID, role, body, true)
	systemPrompt := basePrompt + modeSystemSuffix(body.Mode) + stagedNote
	totalInputTokens := 0
	totalOutputTokens := 0

	// The approval wait (up to 10 min) and long tool dispatches write zero
	// bytes; nginx's proxy_read_timeout (300s) would cut the stream first.
	// emit is mutex-serialized, so a background pinger covers the whole
	// direct-path loop.
	pingDone := make(chan struct{})
	defer close(pingDone)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pingDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if !emit(map[string]any{"type": "ping"}) {
					return
				}
			}
		}
	}()

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
				ch := requestApproval(approvalID)
				emit(map[string]any{
					"type":        "tool_approval_required",
					"id":          tu.id,
					"approval_id": approvalID,
					"name":        tu.name,
					"args":        tu.input,
				})
				approved := false
				select {
				case approved = <-ch:
				case <-time.After(10 * time.Minute):
					toolApprovals.Delete(approvalID)
				case <-ctx.Done():
					toolApprovals.Delete(approvalID)
				}
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
			// Same shape the non-stream handler collects, so one cycle recorder
			// serves both paths — the UI streams, so wiring only the JSON handler
			// would have recorded nothing in practice.
			turnToolCalls = append(turnToolCalls, toolCallResult{
				Name: tu.name, Args: tu.input, Result: result, OK: callOK,
			})
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

	// An app-grounded turn is a cycle of the app's @trigger loop. Best-effort,
	// after the stream's content is already delivered — telemetry never costs
	// the user their answer.
	if body.Context != nil && len(turnToolCalls) > 0 {
		if app, ok := body.Context["app"].(string); ok && app != "" {
			if loop := triggerLoopFor(userID, app); loop != "" {
				recordChatCycle(userID, app, loop, provider.id, turnToolCalls, turnStartedAt)
			}
		}
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

	// 16 MiB per-line cap — same ceiling as the claude-code path: one big
	// base64 image in a tool_result must not fail Scan() and kill the turn.
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
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
