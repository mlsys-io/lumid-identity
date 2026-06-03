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

// llmProvider describes an upstream LLM endpoint that speaks
// Anthropic's /v1/messages wire format (including streaming SSE
// events). New options just need an entry here — the tool-use loop
// + stream parser don't change.
type llmProvider struct {
	id            string // stable id passed from the frontend
	displayName   string // human label (e.g. "Claude Haiku 4.5")
	endpoint      string // upstream URL
	upstreamModel string // the model name sent to the upstream API
	authHeader    string // "x-api-key" (Anthropic) | "Authorization" (kv.run)
	authPrefix    string // "" (Anthropic) | "Bearer " (kv.run)
	keyFn         func() (string, error)
	// addAnthropicVersion — Anthropic's API needs the "anthropic-version"
	// header; kv.run's /v1/messages does not. Set to true for Anthropic.
	addAnthropicVersion bool
	// supportsVision — can read `image` content blocks. gemma4 (verified
	// through the kv.run gateway) + Anthropic do; MiniMax is text-only.
	supportsVision bool
	// minRole — minimum role allowed to SELECT this provider in the panel.
	// "" / "user" = everyone; "admin"; "super_admin". Policy: gemma4 for
	// all, minimax for admin+, claude (Anthropic) for super_admin only.
	minRole string
}

// First entry is the default (defaultProvider() returns llmProviders[0]).
// Order: in-cluster GPU first (no per-call API charge to Anthropic, the
// fleet is already paid for), Anthropic as the hosted fallback.
var llmProviders = []llmProvider{
	{
		// kv.run:5000 gemma4 — default. Same Anthropic /v1/messages
		// gateway, model id from GET kv.run:5000/v1/models. Reasoning
		// model (emits thinking deltas, handled by the SSE parser).
		id:                  "kvrun-gemma4",
		displayName:         "Gemma-4-26B-A4B (kv.run GPU)",
		endpoint:            "https://kv.run:5000/v1/messages",
		upstreamModel:       "unsloth/gemma-4-26B-A4B-it-GGUF:UD-Q4_K_XL",
		authHeader:          "Authorization",
		authPrefix:          "Bearer ",
		keyFn:               kvrunPAT,
		addAnthropicVersion: false,
		supportsVision:      true, // multimodal; image blocks verified via kv.run
		minRole:             "user", // everyone
	},
	{
		// kv.run:5000 in-cluster inference gateway. Speaks Anthropic
		// /v1/messages including SSE streaming — drop-in for the
		// existing parser. See /proj/CLAUDE.md "Cloud LLM inference".
		id:                  "kvrun-minimax",
		displayName:         "MiniMax-M2.7 (kv.run GPU)",
		endpoint:            "https://kv.run:5000/v1/messages",
		upstreamModel:       "cyankiwi/MiniMax-M2.7-AWQ-4bit",
		authHeader:          "Authorization",
		authPrefix:          "Bearer ",
		keyFn:               kvrunPAT,
		addAnthropicVersion: false,
		supportsVision:      false, // MiniMax is text-only
		minRole:             "admin", // admin + super_admin
	},
	{
		id:                  "claude-haiku",
		displayName:         "Claude Haiku 4.5",
		endpoint:            anthropicEndpoint,
		upstreamModel:       anthropicModel,
		authHeader:          "x-api-key",
		authPrefix:          "",
		keyFn:               anthropicKey,
		addAnthropicVersion: true,
		supportsVision:      true,
		minRole:             "super_admin", // super_admin only (Claude Code / all models)
	},
}

// roleRank ranks the role hierarchy for provider gating.
func roleRank(role string) int {
	switch role {
	case "super_admin":
		return 2
	case "admin":
		return 1
	default:
		return 0 // user / unknown
	}
}

// providerAllowed reports whether a caller of the given role may select p.
func providerAllowed(userRole string, p llmProvider) bool {
	return roleRank(userRole) >= roleRank(p.minRole)
}

// currentUserRole resolves the caller's role from the JWT claim, falling
// back to a DB lookup for PAT-authed callers (whose token carries no role).
// Defaults to "user" so gating fails closed to the least privilege.
func currentUserRole(c *gin.Context) string {
	if tok := bearerToken(c); tok != "" {
		if claims, err := common.VerifyJWT(tok); err == nil && claims.Role != "" {
			return claims.Role
		}
	}
	if uid, ok := currentUserID(c); ok {
		var u models.User
		if err := common.DB.Select("role").Where("id = ?", uid).First(&u).Error; err == nil && u.Role != "" {
			return u.Role
		}
	}
	return "user"
}

// defaultProviderFor returns the highest-listed provider the role may use.
// gemma4 is first and allowed to everyone, so this is gemma4 for all roles
// unless the registry changes.
func defaultProviderFor(role string) llmProvider {
	for _, p := range llmProviders {
		if providerAllowed(role, p) {
			return p
		}
	}
	return defaultProvider()
}

func defaultProvider() llmProvider { return llmProviders[0] }

// MeAgentModels — GET /api/v1/me/agent/models.
// Lists the LLM backends StudioChat can target. Public-shape only —
// no keys, no endpoints. Reflects the llmProviders registry; new
// entries auto-surface in the UI dropdown without frontend changes.
func MeAgentModels(c *gin.Context) {
	type item struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Default     bool   `json:"default"`
	}
	role := currentUserRole(c)
	out := make([]item, 0, len(llmProviders))
	def := defaultProviderFor(role).id
	for _, p := range llmProviders {
		if !providerAllowed(role, p) {
			continue // policy: hide providers above the caller's role
		}
		out = append(out, item{ID: p.id, DisplayName: p.displayName, Default: p.id == def})
	}
	c.JSON(http.StatusOK, gin.H{"models": out})
}

// providerSupportsVision returns true for providers that can read
// `image` content blocks. Only Anthropic-shape endpoints in our
// registry today — kv.run/MiniMax-M2.7 is text-only ("is not a
// multimodal model" error from the upstream). If we add new
// providers later, gate on this flag rather than ad-hoc matching.
func providerSupportsVision(p llmProvider) bool {
	return p.supportsVision
}

// containsImageAttachment scans every message in the request for an
// image attachment. Used to auto-route to a vision-capable provider
// when the user's selected model can't read images.
func containsImageAttachment(msgs []chatMessage) bool {
	for _, m := range msgs {
		for _, a := range m.Attachments {
			if a.Kind == "image" {
				return true
			}
		}
	}
	return false
}

// autoRouteForTurn — if the resolved provider can't handle the
// content in the current request, override to claude-haiku (the only
// vision-capable provider today). Returns (provider, autoRouted)
// where autoRouted is true when we overrode. Used to surface the
// override in the usage event so the UI can show "answered by
// Claude (auto)" instead of pretending the user's selection ran.
func autoRouteForTurn(req []chatMessage, picked llmProvider, role string) (llmProvider, bool) {
	if containsImageAttachment(req) && !providerSupportsVision(picked) {
		// Route to the first vision-capable provider the caller's role
		// allows. gemma4 is first + allowed to everyone + multimodal, so
		// this lands on gemma4 for all roles (no policy escalation).
		for _, p := range llmProviders {
			if providerSupportsVision(p) && providerAllowed(role, p) {
				return p, true
			}
		}
	}
	return picked, false
}

// resolveProvider picks the provider for a chat request. Falls back
// to the default (Claude) on empty or unrecognized model strings so
// clients that don't pass `model` keep working.
func resolveProvider(modelID, role string) llmProvider {
	if modelID != "" {
		for _, p := range llmProviders {
			if p.id == modelID {
				if providerAllowed(role, p) {
					return p
				}
				// Requested a provider above the caller's role → fall back
				// to their default (gemma4) rather than 403, so the panel
				// degrades gracefully if a stale id is sent.
				return defaultProviderFor(role)
			}
		}
	}
	return defaultProviderFor(role)
}

type chatMessage struct {
	Role    string `json:"role"`              // "user" | "assistant"
	Content string `json:"content,omitempty"` // for the simple text-only frontend
	// content_blocks (Anthropic's structured form) is what we use
	// internally during the tool-use loop. The frontend sends only
	// flat `content` text; we promote to blocks server-side.
	//
	// Optional file attachments — the chat footer's paperclip lets
	// users drop images + small text files into a turn. Images turn
	// into an Anthropic `image` content block (Claude vision); text
	// files are inlined as a fenced code block in front of the user
	// text so the LLM sees them as context.
	Attachments []chatAttachment `json:"attachments,omitempty"`
}

// chatAttachment — one file the user dropped into the chat input.
//
//   - kind=image:    Mime + DataB64. Anthropic source.media_type expects
//                    "image/png" | "image/jpeg" | "image/gif" | "image/webp".
//   - kind=text:     Text carries the raw content (txt, md, csv, json, yaml,
//                    log, etc — anything the frontend can read as a string).
//   - kind=document: Mime + DataB64 for binary documents. Server routes
//                    by Mime through extractDocumentText():
//                      application/pdf                   → pdftotext
//                      application/vnd.openxmlformats-...
//                                          .wordprocess  → pandoc (docx)
//                      application/vnd.openxmlformats-...
//                                          .spreadsheet  → openpyxl (xlsx)
//                      application/vnd.openxmlformats-...
//                                          .presentation → pandoc (pptx)
//                      application/rtf, application/vnd.oasis.opendocument.*,
//                      application/epub+zip              → pandoc
//                    On Claude (Anthropic) provider, PDFs ship as a native
//                    `document` content block instead of going through
//                    extraction — preserves tables, layout, embedded images.
type chatAttachment struct {
	Kind     string `json:"kind"`               // "image" | "text" | "document"
	Name     string `json:"name,omitempty"`     // filename hint
	Mime     string `json:"mime,omitempty"`     // image + document
	DataB64  string `json:"data_b64,omitempty"` // image + document — base64-encoded bytes
	Text     string `json:"text,omitempty"`     // text-files only — raw content
}

type meAgentChatBody struct {
	Messages []chatMessage `json:"messages" binding:"required"`
	// Optional: id from llmProviders. Empty → default (Claude).
	Model string `json:"model,omitempty"`
	// Optional UI hint: "search" | "deep_research" | "".
	// When set, an extra line is appended to the system prompt asking
	// the agent to call the matching tool for this turn. The agent
	// can still skip if the question genuinely doesn't need search,
	// but the strong nudge mirrors what ChatGPT/Claude do with their
	// "Search" buttons.
	Mode string `json:"mode,omitempty"`
	// Independent toggle: enable extended thinking on Anthropic
	// providers (Claude shows its reasoning before the answer).
	// kv.run/MiniMax always emits thinking deltas by default; this
	// flag is a no-op there. Combinable with Mode.
	Think bool `json:"think,omitempty"`
	// Optional: id of an installed xpio agent. When set,
	// buildSystemPrompt swaps the me-prefs context for that agent's
	// most-recent bank entries; the chat acts as that agent's
	// spokesperson. See me_agent_agents.go.
	AgentID string `json:"agent_id,omitempty"`
	// Optional: id of a user-defined persona. When set, the persona's
	// system_prompt REPLACES the LumidOS assistant base, allowed_tools[]
	// filters the tool catalog, and preferred_model overrides the
	// picker if no explicit model was passed. Mutually exclusive with
	// agent_id — persona_id wins when both are set. See
	// me_agent_personas.go.
	PersonaID string `json:"persona_id,omitempty"`
}

// thinkingBudgetTokens — Anthropic's extended thinking budget. Pulled
// out so we can adjust per-provider later if needed. Must leave room
// in max_tokens for the actual response.
const thinkingBudgetTokens = 4000
const thinkingMaxTokens = 8192 // max_tokens when thinking is enabled

// chatMessageToAnthropic promotes one chatMessage into the Anthropic
// /v1/messages content shape. With no attachments it stays as a plain
// `content: "<text>"`. With attachments it becomes a list of content
// blocks — text-files inlined as fenced code, images as image blocks,
// PDFs as document blocks (Claude) or pdftotext-extracted fenced
// text (non-Claude providers).
// Returns the {role, content} map suitable for direct append.
func chatMessageToAnthropic(m chatMessage, provider llmProvider) map[string]any {
	if len(m.Attachments) == 0 {
		return map[string]any{"role": m.Role, "content": m.Content}
	}
	blocks := make([]map[string]any, 0, len(m.Attachments)+1)
	for _, a := range m.Attachments {
		switch a.Kind {
		case "image":
			if a.DataB64 == "" || a.Mime == "" {
				continue
			}
			blocks = append(blocks, map[string]any{
				"type": "image",
				"source": map[string]any{
					"type":       "base64",
					"media_type": a.Mime,
					"data":       a.DataB64,
				},
			})
		case "document":
			if a.DataB64 == "" {
				continue
			}
			name := a.Name
			if name == "" {
				name = "document"
			}
			// Claude path + PDF: ship as a native document content
			// block. Preserves layout, tables, and embedded images
			// for vision. Other doc formats still go through text
			// extraction even on Claude.
			if provider.addAnthropicVersion && a.Mime == "application/pdf" {
				blocks = append(blocks, map[string]any{
					"type": "document",
					"source": map[string]any{
						"type":       "base64",
						"media_type": "application/pdf",
						"data":       a.DataB64,
					},
					"title": name,
				})
				continue
			}
			// Everything else: server-side text extraction routed by mime.
			text, extractor, err := extractDocumentText(a.Mime, a.DataB64)
			if err != nil {
				blocks = append(blocks, map[string]any{
					"type": "text",
					"text": "Attached document `" + name + "` (" + a.Mime + ") — extraction failed: " + err.Error(),
				})
				continue
			}
			blocks = append(blocks, map[string]any{
				"type": "text",
				"text": "Attached document `" + name + "` (extracted via " + extractor + "):\n```\n" + text + "\n```",
			})
		case "text":
			if a.Text == "" {
				continue
			}
			name := a.Name
			if name == "" {
				name = "attachment"
			}
			fence := "```\n"
			blocks = append(blocks, map[string]any{
				"type": "text",
				"text": "Attached file `" + name + "`:\n" + fence + a.Text + "\n```",
			})
		}
	}
	if m.Content != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
	}
	return map[string]any{"role": m.Role, "content": blocks}
}

// modeSystemSuffix returns the line to append to the system prompt
// when the user has flipped a tool-forcing toggle in the chat UI.
// Empty string for "" / unknown modes (no-op).
func modeSystemSuffix(mode string) string {
	citationRules := "\n\nCITATIONS: cite every fact that came from a web tool using GitHub-flavored markdown footnotes. This is mandatory — a reply with sourced facts and no inline citations is broken. EXACT SHAPE:\n\n  The S&P 500 closed at 6420 yesterday[^1], up 0.4% on the week[^2].\n\n  [^1]: https://example.com/markets-page\n  [^2]: https://other.com/weekly-recap\n\nRules:\n- One `[^n]` marker per claim, attached without a space to the word it cites.\n- Define every `[^n]` you reference at the very end of the reply, one per line.\n- URLs verbatim from the tool — never paraphrase or invent.\n- Reuse the same number for repeated sources; don't duplicate definitions.\n- Skip footnotes entirely only if you didn't actually use a source.\n- Do NOT add a `## Sources` heading — the frontend builds the footnotes block automatically from the `[^n]:` definitions."
	switch mode {
	case "search":
		return "\n\nFor this turn, the user has explicitly enabled web search. Call the `web_search` tool to ground your answer in current web sources before replying. If the question is purely about the user's own knowledge or tenant state and search would be irrelevant, you may skip it — but err on the side of searching." + citationRules
	case "deep_research":
		return "\n\nFor this turn, the user has explicitly enabled deep research. Call the `deep_research` tool with a focused question derived from the user's message, then synthesize a brief from the returned sources." + citationRules
	}
	return ""
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

	role := currentUserRole(c)
	provider := resolveProvider(body.Model, role)
	provider, autoRouted := autoRouteForTurn(body.Messages, provider, role)
	_ = autoRouted // surfaced via usage event in the stream handler; non-streaming response also signals via the model field below.
	apiKey, err := provider.keyFn()
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503,
			"chat unavailable: "+err.Error())
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
		anthMsgs = append(anthMsgs, chatMessageToAnthropic(m, provider))
	}

	basePrompt, tools, _ := resolvePromptAndTools(userID, body)
	systemPrompt := basePrompt + modeSystemSuffix(body.Mode)
	toolCalls := []toolCallResult{}
	totalInputTokens := 0
	totalOutputTokens := 0
	finalText := ""

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	// Tool-use loop.
	for i := 0; i < maxToolLoopIterations; i++ {
		maxTok := maxTokensPerTurn
		if body.Think && provider.addAnthropicVersion {
			maxTok = thinkingMaxTokens
		}
		req := map[string]any{
			"model":      provider.upstreamModel,
			"max_tokens": maxTok,
			"system":     systemPrompt,
			"messages":   anthMsgs,
			"tools":      tools,
		}
		if body.Think && provider.addAnthropicVersion {
			req["thinking"] = map[string]any{
				"type":          "enabled",
				"budget_tokens": thinkingBudgetTokens,
			}
		}
		resp, err := callLLM(ctx, provider, apiKey, req)
		if err != nil {
			fail(c, http.StatusBadGateway, 1502, "llm call: "+err.Error())
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
		_ = recordUsage(userID, "chat", "/me/agent/chat", provider.upstreamModel,
			totalInputTokens, totalOutputTokens)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"reply":      finalText,
			"tool_calls": toolCalls,
			"model_used": provider.id,
			"auto_routed": autoRouted,
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

// kvrunPAT resolves the operator's Lumid PAT used to authenticate
// against kv.run:5000/v1/*. Env first (KVRUN_LLM_TOKEN), then
// /home/webmaster/.lumilake/pat on disk.
func kvrunPAT() (string, error) {
	if k := strings.TrimSpace(os.Getenv("KVRUN_LLM_TOKEN")); k != "" {
		return k, nil
	}
	if b, err := os.ReadFile("/home/webmaster/.lumilake/pat"); err == nil {
		tok := strings.TrimSpace(strings.Split(string(b), "\n")[0])
		if tok != "" {
			return tok, nil
		}
	}
	return "", fmt.Errorf("no KVRUN_LLM_TOKEN set")
}

// callLLM POSTs to the provider's /v1/messages endpoint with
// Anthropic-shaped JSON. Provider determines auth header + key source.
// Returns the parsed JSON body on 2xx, or an error otherwise
// (including the response body for debug).
func callLLM(ctx context.Context, p llmProvider, apiKey string, body map[string]any) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(p.authHeader, p.authPrefix+apiKey)
	if p.addAnthropicVersion {
		req.Header.Set("anthropic-version", anthropicVersion)
	}

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	respBody, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %d: %s", p.id, r.StatusCode, string(respBody[:min(400, len(respBody))]))
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
// resolvePromptAndTools — single decision point for the chat's
// system prompt + tool catalog. Three modes, in priority order:
//
//  1. PersonaID set → persona's system_prompt + allowed_tools filter
//     (mutually exclusive with agent_id).
//  2. AgentID set   → standard LumidOS prompt + agent-bank block
//     replacing me-prefs.
//  3. Default       → standard LumidOS prompt + me-prefs block.
//
// Returns (systemPrompt, tools, preferredModel). preferredModel is
// honored only when the request didn't set Model explicitly (handler-
// level concern, not done here).
func resolvePromptAndTools(userID string, body meAgentChatBody) (string, []map[string]any, string) {
	tools := buildToolDefs()
	if body.PersonaID != "" {
		p, _ := loadPersona(userID, body.PersonaID)
		if p != nil {
			if len(p.AllowedTools) > 0 {
				allow := map[string]bool{}
				for _, t := range p.AllowedTools {
					allow[t] = true
				}
				tools = filterTools(tools, allow)
			}
			return p.SystemPrompt, tools, p.PreferredModel
		}
		// Fall through if persona id is invalid — chat still works.
	}
	return buildSystemPrompt(userID, body.AgentID), tools, ""
}

// buildSystemPrompt assembles the assistant's persona + a snapshot
// of the user's current tenant. When agentID is set, the trailing
// memory block swaps from the user's me-prefs to that agent's bank
// (see renderAgentBankBlock); empty agentID falls through to the
// default me-prefs path.
func buildSystemPrompt(userID, agentID string) string {
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
  - search the web (web_search), fetch one URL (web_fetch), or run deep research (deep_research)
  - look up financial data by symbol (query_findata)
  - remember things about the user long-term (remember_about_me) — call this whenever the user shares a preference, fact about themselves, or a working style hint that should persist

When the user expresses an intent, prefer doing the work via tools over describing how they could do it themselves. Confirm what you did in 1-2 sentences after each action.

The user already has these apps installed in their tenant: ` + tenantList + `

When you don't know an app's slug, call list_marketplace first. When the user gives ambiguous feedback ("today was off"), capture it as a feedback note on the most recent cycle of the most likely loop and tell them you did so — they can refine later.

Stay grounded: don't invent apps, loops, or features. If a tool fails, surface the error briefly and suggest the next step.` + func() string {
		if agentID != "" {
			return renderAgentBankBlock(userID, agentID)
		}
		return renderPrefsBlock(userID)
	}()
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
			"name":        "intent_audit",
			"description": "Show what's changed about an intent over a time window — across the six improvement axes (examples=cases learned from, standard=metrics & rubric, recipe=workflow steps, pieces=skills, memory=banks, rules=patterns figured out). Use when the user asks 'what changed this week?', 'why did the metric move?', 'show me the audit', or when explaining how the AI is adapting. Returns events newest-first + a per-axis movement summary.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":   map[string]any{"type": "string", "description": "intent id (xpio app name, e.g. personal-agent)"},
					"loop":  map[string]any{"type": "string", "description": "optional: scope to one loop"},
					"since": map[string]any{"type": "string", "description": "either 'Nd' (last N days) or an RFC3339 timestamp. Default: last 7d."},
					"limit": map[string]any{"type": "integer", "default": 30, "description": "max events to return"},
				},
				"required": []string{"app"},
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

		// ── Workflow surface (W1) ─────────────────────────────────
		// In the user-facing vocabulary, "workflow" replaces "loop" /
		// "app" / "n8n DAG" — all three are kinds of workflow. The
		// old list_apps / run_loop_now / patch_loop tools stay above
		// for back-compat; the new tools below are the canonical
		// surface the chat should prefer.
		{
			"name":        "list_workflows",
			"description": "List the user's workflows across kinds (scheduled = xpio loop; visual = n8n DAG). Returns slug, kind, trigger, last-run state, enabled flag. Prefer this over list_apps.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind": map[string]any{
						"type":        "string",
						"description": "optional filter: 'scheduled' or 'visual'",
						"enum":        []string{"scheduled", "visual"},
					},
				},
			},
		},
		{
			"name":        "workflow_detail",
			"description": "Full definition + last runs for one workflow. Slug shape: '<app>:<loop>' for scheduled or 'n8n:<id>' for visual.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "list_runs",
			"description": "List recent workflow runs across all kinds. Filter by state ('succeeded'/'failed'/'running'/'skipped') and/or workflow slug. Default window: last 24h.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"state":    map[string]any{"type": "string", "description": "comma-separated states to include"},
					"workflow": map[string]any{"type": "string", "description": "filter to one workflow slug"},
					"limit":    map[string]any{"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
				},
			},
		},
		{
			"name":        "run_detail",
			"description": "Per-step details for one run (steps, error, artifacts). run_id shape: 'scheduled:<app>:<loop>:<ts>' or 'visual:n8n:<exec_id>'.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"run_id": map[string]any{"type": "string"},
				},
				"required": []string{"run_id"},
			},
		},
		{
			"name":        "pause_workflow",
			"description": "Pause (enabled=false) or resume (enabled=true) a workflow. Equivalent to patch_loop with the enabled flag, but accepts the workflow's slug directly.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":    map[string]any{"type": "string", "description": "<app>:<loop> for scheduled workflows"},
					"enabled": map[string]any{"type": "boolean"},
				},
				"required": []string{"slug", "enabled"},
			},
		},

		// ── Create surface (W2) — chat-driven workflow composition.
		// These are the highest-value Create tools; they hide the
		// marketplace-mechanics from the user (they ask "build me X",
		// the agent picks skills + drafts a workflow).
		{
			"name":        "search_marketplace",
			"description": "Search the curated marketplace for skills / workflows matching a natural-language query. Use this when the user is browsing or you need to know what's available before composing.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":   map[string]any{"type": "string"},
					"for_app": map[string]any{"type": "string", "description": "optional — narrow to one xpio app's catalog (personal-agent / mbb-ai / auto-quant / eventx / auto-sysresearch)"},
					"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "compose_workflow",
			"description": "Draft a new workflow from a natural-language intent. Calls /api/v1/skills/suggest to pick the right skills, builds an xpcloud.yaml workflow stitching them together, and stages it under the user's tenant draft directory. The user can then review + adjust in the composer UI.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"intent":   map[string]any{"type": "string", "description": "plain-English description, e.g. 'watch my Slack every hour and draft replies'"},
					"for_app": map[string]any{"type": "string", "description": "which xpio shape to target — personal-agent is the default for assistant-style intents"},
					"name":    map[string]any{"type": "string", "description": "optional — friendly name for the new workflow (defaults to a slug derived from the intent)"},
				},
				"required": []string{"intent"},
			},
		},
		{
			"name":        "add_skill_to_workflow",
			"description": "Add a skill from the marketplace to an existing scheduled workflow's skill_imports[]. Updates the tenant's .user-overrides.yaml. Use after compose_workflow when the user wants to extend an already-installed workflow.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug":       map[string]any{"type": "string", "description": "workflow slug, e.g. 'personal-agent:morning_brief'"},
					"skill_name": map[string]any{"type": "string", "description": "marketplace skill name, e.g. 'tavily-search'"},
				},
				"required": []string{"slug", "skill_name"},
			},
		},

		// ── Improve surface (W4) ──────────────────────────────────
		{
			"name":        "workflow_report_card",
			"description": "Plain-English progress card for one workflow over the last month vs the month before. Headlines cover reliability, latency, draft accept-rate. Use this for 'how is my morning brief getting better?' or 'is X workflow improving?' questions.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string", "description": "workflow slug, e.g. 'personal-agent:morning_brief'"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "trigger_evaluation",
			"description": "Enqueue an on-demand evaluation of a marketplace skill against an xpio app's casebook. Skill-roster picks it up within ~60s and posts an attestation to xpcloud. Use when the user wants a fresh score (e.g., right after installing a new skill).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"skill_name": map[string]any{"type": "string"},
					"for_app":    map[string]any{"type": "string", "description": "personal-agent / mbb-ai / eventx / auto-quant / auto-sysresearch"},
				},
				"required": []string{"skill_name", "for_app"},
			},
		},
		{
			"name":        "suggest_workflow_improvement",
			"description": "Look at one workflow's recent failures + report card and recommend ONE concrete change (swap skill, add a step, change schedule). Use when the user asks 'how can I improve X?' or after surfacing a failure they want to fix.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"slug": map[string]any{"type": "string"},
				},
				"required": []string{"slug"},
			},
		},
		{
			"name":        "web_search",
			"description": "Search the open web for a short query. Returns 5-10 result snippets with URLs. Use for current events, factual lookups, or to find authoritative sources to follow up with web_fetch. For multi-source synthesis with a written-up answer, prefer deep_research instead.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":       map[string]any{"type": "string", "description": "Search terms — natural language is fine."},
					"num_results": map[string]any{"type": "integer", "description": "Optional, default 5, max 10."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "web_fetch",
			"description": "Fetch one URL and return its readable content as markdown. Use after web_search when the user wants the actual content of a specific page, not just snippets.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "Absolute URL (https://…)."},
				},
				"required": []string{"url"},
			},
		},
		{
			"name":        "deep_research",
			"description": "Multi-source web research with a synthesized answer. Returns a written brief plus the supporting result list. Use when the user asks a question that needs research across multiple sources (e.g. 'what's the current state of X?', 'compare A and B', 'summarize recent developments on Z'). Slower (10-30s) than web_search; choose web_search for simple lookups.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"question":    map[string]any{"type": "string", "description": "The research question, in natural language."},
					"max_results": map[string]any{"type": "integer", "description": "Optional, default 8, max 10. Lower is faster."},
				},
				"required": []string{"question"},
			},
		},
		{
			"name":        "query_findata",
			"description": "Look up financial data for a stock/ETF symbol via the kv.run:5000 warehouse. Faster + cheaper than web_search for price + corporate-action queries. Kinds: quote (current price + volume), news (recent headlines), earnings (calendar + results), peers (similar tickers), filings (SEC filings), ohlc (30-day daily bars).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"kind":   map[string]any{"type": "string", "enum": []string{"quote", "news", "earnings", "peers", "filings", "ohlc"}, "description": "What to fetch."},
					"symbol": map[string]any{"type": "string", "description": "Ticker symbol, e.g. AAPL, NVDA, BTCUSD."},
					"limit":  map[string]any{"type": "integer", "description": "Optional row cap (for news/earnings/filings). Default 10, max 50."},
				},
				"required": []string{"kind", "symbol"},
			},
		},
		{
			"name":        "remember_about_me",
			"description": "Save a fact, preference, or working-style note about the user to long-term memory. Use whenever the user explicitly shares something they want you to remember (\"I prefer terse summaries\", \"my main symbol is NVDA\", \"never ping me before 9am\"). Each call appends one row to the me-prefs knowledge bank; recent rows are injected into your system prompt on every subsequent chat, so saved facts shape future replies automatically. Do NOT use for ephemeral session state.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"note": map[string]any{"type": "string", "description": "The fact or preference, in the user's own framing when possible. One sentence ideal."},
					"tags": map[string]any{"type": "string", "description": "Optional comma-separated retrieval hints, e.g. 'preference,style' or 'fact,trading'."},
				},
				"required": []string{"note"},
			},
		},
		{
			"name":        "code_run",
			"description": "Run a short Python 3 snippet in a sandboxed environment and return stdout/stderr/exit_code. Use for math/data calculations, CSV/JSON parsing, quick chart-style aggregation, or any task that's easier to compute than describe. The sandbox is network-isolated, capped at 30s CPU + 512MB memory + 10MB file output, and runs as 'nobody' with no host filesystem access. The standard library is available; no third-party packages.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code":        map[string]any{"type": "string", "description": "Python 3 source. Use print() to emit results — only stdout/stderr are returned."},
					"timeout_sec": map[string]any{"type": "integer", "description": "Optional wall-clock timeout, default 30, max 60."},
				},
				"required": []string{"code"},
			},
		},
		{
			"name":        "send_email",
			"description": "Send an email from the user's connected Gmail account. The user must have linked Google at /dashboard/account/connect/google (the same OAuth grant that powers personal-agent); if not, the tool returns a clean error pointing them there. ALWAYS read back the subject + recipients in your reply so the user can confirm what was sent. Use plain text bodies — markdown won't render in email.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to":      map[string]any{"type": "string", "description": "Comma-separated recipient(s). Required."},
					"subject": map[string]any{"type": "string", "description": "Email subject line. Required, max ~80 chars ideal."},
					"body":    map[string]any{"type": "string", "description": "Plain text body. Required."},
					"cc":      map[string]any{"type": "string", "description": "Optional comma-separated CC recipients."},
					"bcc":     map[string]any{"type": "string", "description": "Optional comma-separated BCC recipients."},
				},
				"required": []string{"to", "subject", "body"},
			},
		},
		{
			"name":        "create_calendar_event",
			"description": "Create an event on the user's primary Google Calendar. Requires Google connected at /dashboard/account/connect/google. Use ISO-8601 datetimes with offsets (2026-06-01T14:00:00-07:00) for timed events, or YYYY-MM-DD strings for all-day events. Confirm details (title, when, who) back to the user in your reply.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string", "description": "Event title. Required."},
					"start":       map[string]any{"type": "string", "description": "ISO 8601 datetime OR YYYY-MM-DD for all-day. Required."},
					"end":         map[string]any{"type": "string", "description": "ISO 8601 datetime OR YYYY-MM-DD. Required."},
					"description": map[string]any{"type": "string", "description": "Optional details. Plain text."},
					"location":    map[string]any{"type": "string", "description": "Optional location or videoconf URL."},
					"attendees":   map[string]any{"type": "string", "description": "Optional comma-separated email list. Invitations are sent automatically."},
					"timezone":    map[string]any{"type": "string", "description": "Optional IANA timezone for timed events, e.g. 'America/Los_Angeles'. Defaults to America/Los_Angeles."},
				},
				"required": []string{"title", "start", "end"},
			},
		},
		{
			"name":        "spawn_agent",
			"description": "Delegate a focused job to a sub-agent. The sub-agent runs its own short tool-use loop (max 5 iterations, 45s) with a curated tool subset, and returns its final reply. Use this when a research-heavy or analysis-heavy sub-task would otherwise clutter your own context with many tool calls — e.g. 'spawn a sub-agent to investigate X across 5 sources and return a 3-paragraph brief'. The sub-agent gets a fresh message history; it doesn't see this conversation. By default the sub-agent gets read-only + research tools (web_search, web_fetch, deep_research, query_findata, query_my_knowledge, code_run, list_*, today_summary). To restrict further, pass tools=[...].",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task":     map[string]any{"type": "string", "description": "The focused job, in natural language. Include enough context for a fresh agent to understand."},
					"tools":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional whitelist of tool names the sub-agent may use. Defaults to a read-only + research subset."},
					"agent_id": map[string]any{"type": "string", "description": "Optional xpio agent id to ground the sub-agent in (same effect as the user's agent picker — see /me/agents)."},
					"max_iter": map[string]any{"type": "integer", "description": "Optional cap on tool-use iterations, default 5, max 5."},
				},
				"required": []string{"task"},
			},
		},
		{
			"name":        "save_artifact",
			"description": "Save a piece of output (markdown brief, code listing, JSON dataset, plain text) as a persistent artifact in the user's tenant. The artifact appears in the Studio artifact panel and survives across sessions. Use this when the chat produces a long-form deliverable the user is likely to revisit: a research brief from deep_research, a generated script from code_run, a structured summary they asked you to compile. Always set a clear `title` (e.g. 'AAPL Q1 earnings brief' — not 'untitled'). The returned `id` + `url` can be referenced in follow-up turns.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string", "description": "Human-readable name for the artifact, max ~80 chars ideal."},
					"content":     map[string]any{"type": "string", "description": "Body of the artifact. Plain text, markdown, code, or JSON — match the `kind`."},
					"kind":        map[string]any{"type": "string", "enum": []string{"markdown", "code", "json", "text"}, "description": "Rendering hint. Default: markdown."},
					"language":    map[string]any{"type": "string", "description": "For kind=code: source language (python, go, js, sql, …)."},
					"source_tool": map[string]any{"type": "string", "description": "Optional — which prior tool produced this content (e.g. deep_research, code_run). Surfaces as a badge in the panel."},
				},
				"required": []string{"title", "content"},
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

	case "intent_audit":
		app, _ := args["app"].(string)
		if app == "" {
			return map[string]any{"error": "app required"}, false
		}
		loop, _ := args["loop"].(string)
		since, _ := args["since"].(string)
		if since == "" {
			since = "7d"
		}
		limit := 30
		if v, ok := args["limit"].(float64); ok && int(v) > 0 {
			limit = int(v)
		}
		events, err := readImprovements(userID, app, loop, since, limit)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{
			"intent_id":      app,
			"loop":           loop,
			"since":          since,
			"event_count":    len(events),
			"axis_movements": summarizeImprovements(events),
			"events":         events,
		}, true

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

	// ── Workflow surface (W1) — delegate to MeWorkflows / MeRuns
	// handlers via thin Go wrappers that bypass the HTTP layer.
	case "list_workflows":
		kind, _ := args["kind"].(string)
		return toolListWorkflows(c, userID, kind), true

	case "workflow_detail":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolWorkflowDetail(c, userID, slug), true

	case "list_runs":
		state, _ := args["state"].(string)
		workflow, _ := args["workflow"].(string)
		limit := 25
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return toolListRuns(c, userID, state, workflow, limit), true

	case "run_detail":
		runID, _ := args["run_id"].(string)
		if runID == "" {
			return map[string]any{"error": "run_id required"}, false
		}
		return toolRunDetail(c, userID, runID), true

	case "pause_workflow":
		slug, _ := args["slug"].(string)
		enabled, _ := args["enabled"].(bool)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		// scheduled workflows only — slug shape "<app>:<loop>".
		parts := strings.SplitN(slug, ":", 2)
		if len(parts) != 2 || parts[0] == "n8n" {
			return map[string]any{"error": "pause_workflow only supports scheduled workflows (slug '<app>:<loop>'); use n8n's UI to toggle visual workflows"}, false
		}
		return toolPatchLoop(userID, parts[0], parts[1], map[string]any{"enabled": enabled}), true

	// ── Create surface (W2) ───────────────────────────────────
	case "search_marketplace":
		query, _ := args["query"].(string)
		forApp, _ := args["for_app"].(string)
		limit := 5
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		if query == "" {
			return map[string]any{"error": "query required"}, false
		}
		return toolSearchMarketplace(c, query, forApp, limit), true

	case "compose_workflow":
		intent, _ := args["intent"].(string)
		forApp, _ := args["for_app"].(string)
		name, _ := args["name"].(string)
		if intent == "" {
			return map[string]any{"error": "intent required"}, false
		}
		return toolComposeWorkflow(c, userID, intent, forApp, name), true

	case "add_skill_to_workflow":
		slug, _ := args["slug"].(string)
		skillName, _ := args["skill_name"].(string)
		if slug == "" || skillName == "" {
			return map[string]any{"error": "slug and skill_name required"}, false
		}
		return toolAddSkillToWorkflow(userID, slug, skillName), true

	// ── Improve surface (W4) ──────────────────────────────────
	case "workflow_report_card":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolWorkflowReportCard(c, userID, slug), true

	case "trigger_evaluation":
		skillName, _ := args["skill_name"].(string)
		forApp, _ := args["for_app"].(string)
		if skillName == "" || forApp == "" {
			return map[string]any{"error": "skill_name and for_app required"}, false
		}
		return toolTriggerEvaluation(userID, skillName, forApp), true

	case "suggest_workflow_improvement":
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false
		}
		return toolSuggestImprovement(c, userID, slug), true

	case "web_search":
		query, _ := args["query"].(string)
		num := 0
		if v, ok := args["num_results"].(float64); ok {
			num = int(v)
		}
		return toolWebSearch(query, num)

	case "web_fetch":
		url, _ := args["url"].(string)
		return toolWebFetch(url)

	case "deep_research":
		question, _ := args["question"].(string)
		maxResults := 0
		if v, ok := args["max_results"].(float64); ok {
			maxResults = int(v)
		}
		return toolDeepResearch(question, maxResults)

	case "query_findata":
		kind, _ := args["kind"].(string)
		symbol, _ := args["symbol"].(string)
		limit := 0
		if v, ok := args["limit"].(float64); ok {
			limit = int(v)
		}
		return toolQueryFindata(kind, symbol, limit)

	case "remember_about_me":
		note, _ := args["note"].(string)
		return toolRememberAboutMe(userID, note, args["tags"])

	case "code_run":
		code, _ := args["code"].(string)
		timeout := 0
		if v, ok := args["timeout_sec"].(float64); ok {
			timeout = int(v)
		}
		return toolCodeRun(code, timeout)

	case "save_artifact":
		return toolSaveArtifact(userID, args)

	case "spawn_agent":
		return toolSpawnAgent(c, userID, args)

	case "send_email":
		return toolSendEmail(userID, args)

	case "create_calendar_event":
		return toolCreateCalendarEvent(userID, args)
	}
	return map[string]any{"error": "unknown tool: " + name}, false
}
