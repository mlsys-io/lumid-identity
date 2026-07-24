package handler

// me_agent providers: claude-code-* (Claude Code via the in-cluster sandbox)
//
// Routes chat turns to the claude-sandbox service (deploy_infra
// k8s-lift/claude-sandbox), which spawns the real claude CLI:
//   claude -p --output-format stream-json --include-partial-messages ...
// and streams back NDJSON events. We parse those events and re-emit them
// as our SSE format so the frontend receives the same shape as any other
// provider.
//
// Model access rides the POOLED account proxy (lum.id/claude): the sandbox
// runs the CLI with ANTHROPIC_BASE_URL=claude-proxy and a per-user ephemeral
// PAT we mint here (claudeSandboxPAT). That means per-user 5h/7d pool quota,
// role→model tiers (user→sonnet, admin→+opus, super_admin→+fable), and
// /claude-sessions recording all apply automatically — attributed to the
// real end user, not a service account.
//
// The old host-side shim (claude-proxy.py on luyaomini5:9201) is dead —
// lost in the UKS migration. CLAUDE_SANDBOX_URL points at its in-cluster
// replacement; the legacy CLAUDE_PROXY_URL env is honored as a fallback.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// claudeSandboxURL returns the in-cluster claude-sandbox base URL.
func claudeSandboxURL() string {
	if u := os.Getenv("CLAUDE_SANDBOX_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	if u := os.Getenv("CLAUDE_PROXY_URL"); u != "" { // legacy name
		return strings.TrimRight(u, "/")
	}
	return "http://claude-sandbox:9201"
}

// claudeCodeKeyFn satisfies llmProvider.keyFn. Real auth is the per-user
// ephemeral PAT minted by claudeSandboxPAT and passed in the request body.
func claudeCodeKeyFn() (string, error) { return "claude-code", nil }

// isClaudeCodeProvider reports whether a provider routes through the
// claude-sandbox runner (no HTTP endpoint) rather than an Anthropic-wire
// endpoint. Covers claude-code-{sonnet,opus,fable}.
func isClaudeCodeProvider(p llmProvider) bool {
	return strings.HasPrefix(p.id, "claude-code")
}

// ── ephemeral per-user sandbox PATs ─────────────────────────────────────────
//
// The sandbox subprocess authenticates to the pooled claude-proxy as the
// real end user so quota/tiering/recording attribute correctly. We mint a
// short-lived PAT (claude:proxy scope only — useless against any other
// endpoint) per user and cache it per pod; StartClaudeSandboxPATSweep
// clears expired rows.

const (
	claudeSandboxPATTTL   = 6 * time.Hour
	claudeSandboxPATFresh = 30 * time.Minute // re-mint when less than this remains
	claudeSandboxSource   = "claude_sandbox"
)

var (
	sandboxPATMu    sync.Mutex
	sandboxPATCache = map[string]struct {
		token string
		exp   time.Time
	}{}
)

// claudeSandboxPAT returns a live claude:proxy-scoped PAT for the user,
// minting a fresh one when the cached token is near expiry. Deliberately
// bypasses canGrant + the mint rate limit: policy is "every user gets the
// sandbox", and these rows are hidden from the user's token list.
func claudeSandboxPAT(userID string) (string, error) {
	sandboxPATMu.Lock()
	defer sandboxPATMu.Unlock()
	if e, ok := sandboxPATCache[userID]; ok && time.Until(e.exp) > claudeSandboxPATFresh {
		return e.token, nil
	}
	exp := time.Now().Add(claudeSandboxPATTTL)
	cleartext, _, err := mintPATForUser(userID, "claude sandbox (auto)",
		[]string{"claude:proxy"}, &exp, claudeSandboxSource)
	if err != nil {
		return "", err
	}
	sandboxPATCache[userID] = struct {
		token string
		exp   time.Time
	}{cleartext, exp}
	return cleartext, nil
}

// StartClaudeSandboxPATSweep deletes expired auto-minted sandbox PATs
// hourly (they are hidden from the token list, so nothing else cleans them).
func StartClaudeSandboxPATSweep() {
	go func() {
		for {
			time.Sleep(time.Hour)
			if common.DB == nil {
				continue
			}
			common.DB.Where("source = ? AND expires_at < ?",
				claudeSandboxSource, time.Now().Add(-24*time.Hour)).
				Delete(&models.Token{})
		}
	}()
}

// ── transport ───────────────────────────────────────────────────────────────

// streamClaudeCodeViaProxy sends the conversation to the claude-sandbox
// runner, reads its streaming NDJSON, and re-emits as SSE events.
func streamClaudeCodeViaProxy(
	ctx context.Context,
	_ *gin.Context,
	userID string,
	role string, // caller role — super_admin gets the shared workspaces root
	messages []chatMessage,
	systemPrompt string,
	model string, // claude CLI --model alias or full claude-* id
	sessionID string, // optional claude session to resume (must be owned by userID)
	emit func(map[string]any) bool,
) error {
	if model == "" {
		model = "sonnet"
	}
	// Session continuity: resume the prior claude CLI session when the
	// client passes one back. Only sessions THIS user was previously
	// issued (recorded by recordClaudeSession below) are honored —
	// anything else is silently ignored and starts fresh, so a caller
	// can't graft someone else's transcript into their context.
	if sessionID != "" && !userOwnsClaudeSession(userID, sessionID) {
		sessionID = ""
	}
	pat, err := claudeSandboxPAT(userID)
	if err != nil {
		return fmt.Errorf("sandbox credential mint failed: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"messages":        proxyMessages(messages),
		"model":           model,
		"system":          systemPrompt,
		"role":            role,
		"user_id":         userID,
		"session_id":      sessionID,
		"anthropic_token": pat,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		claudeSandboxURL()+"/claude/stream", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", os.Getenv("LUMID_IDENTITY_BRIDGE_SECRET"))

	// No client-level timeout — the stream runs until claude finishes
	// (the sandbox enforces its own per-session hard timeout).
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("claude sandbox unreachable at %s: %w", claudeSandboxURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable {
		return fmt.Errorf("Claude Code sandbox is at capacity — try again in a minute")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("claude sandbox returned HTTP %d", resp.StatusCode)
	}

	// toolNameByID maps tool_use id → name for emitting tool_call events
	// when we later see the corresponding tool_result from the user turn.
	toolNameByID := map[string]string{}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		switch event["type"] {

		case "system":
			// init event carries the session_id of this run. Record it
			// against the user (authorizes future --resume) and surface
			// it to the client so the next turn can pass it back.
			if sub, _ := event["subtype"].(string); sub == "init" {
				if sid, _ := event["session_id"].(string); sid != "" {
					recordClaudeSession(userID, sid)
					emit(map[string]any{"type": "claude_session", "session_id": sid})
				}
			}

		case "stream_event":
			// Inner Anthropic API SSE event.
			inner, _ := event["event"].(map[string]any)
			switch inner["type"] {
			case "content_block_delta":
				delta, _ := inner["delta"].(map[string]any)
				if delta["type"] == "text_delta" {
					text, _ := delta["text"].(string)
					if text != "" {
						emit(map[string]any{"type": "text", "delta": text})
					}
				}
				// input_json_delta — tool input streaming; we emit the full
				// input only once we have the complete assistant message below.
			}

		case "assistant":
			// Complete assistant message. Use it to emit tool_start events
			// (now we have the full, valid JSON input for each tool call).
			// Skip partial messages — we already streamed text via stream_event.
			isPartial, _ := event["is_partial"].(bool)
			if isPartial {
				continue
			}
			msg, _ := event["message"].(map[string]any)
			content, _ := msg["content"].([]any)
			for _, raw := range content {
				b, _ := raw.(map[string]any)
				if b["type"] != "tool_use" {
					continue
				}
				id, _ := b["id"].(string)
				name, _ := b["name"].(string)
				input, _ := b["input"].(map[string]any)
				toolNameByID[id] = name
				emit(map[string]any{
					"type": "tool_start",
					"id":   id,
					"name": name,
					"args": input,
				})
			}

		case "user":
			// Tool results returned to the model after execution.
			msg, _ := event["message"].(map[string]any)
			content, _ := msg["content"].([]any)
			for _, raw := range content {
				b, _ := raw.(map[string]any)
				if b["type"] != "tool_result" {
					continue
				}
				id, _ := b["tool_use_id"].(string)
				isError, _ := b["is_error"].(bool)
				name := toolNameByID[id]
				if name == "" {
					name = id
				}
				emit(map[string]any{
					"type":   "tool_call",
					"id":     id,
					"name":   name,
					"result": b["content"],
					"ok":     !isError,
				})
			}

		case "result":
			subtype, _ := event["subtype"].(string)
			if subtype == "error" {
				msg, _ := event["result"].(string)
				// Pool quota exhaustion surfaces as an Anthropic
				// rate_limit_error inside the CLI's error text — rewrite it
				// to something actionable for the chat user.
				low := strings.ToLower(msg)
				if strings.Contains(low, "rate_limit") || strings.Contains(low, "quota") {
					msg = "Pooled Claude quota reached — usage windows and reset times are at lum.id/code. " + msg
				}
				emit(map[string]any{"type": "error", "message": msg})
			}
			// "success" → text already streamed via stream_event deltas.
		}
	}

	return scanner.Err()
}

// proxyMessages converts chatMessage slice to plain {role, content} maps.
// Attachments are dropped — the claude CLI handles vision via its own
// file-read tools, and binary data doesn't travel well over a text prompt.
func proxyMessages(msgs []chatMessage) []map[string]any {
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, map[string]any{
			"role":    m.Role,
			"content": m.Content,
		})
	}
	return out
}
