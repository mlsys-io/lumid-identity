package handler

// me_agent provider: claude-code-opus
//
// Routes chat turns to the local claude CLI binary via a host-side proxy
// (claude-proxy.py on 172.17.0.1:9201). The proxy calls:
//   claude -p --output-format stream-json --include-partial-messages ...
// and streams back NDJSON events. We parse those events and re-emit them
// as our SSE format so the frontend receives the same shape as any other
// provider.
//
// Why a proxy instead of calling claude directly from this container:
//   lumid-identity runs on Alpine (musl libc); the claude binary is a glibc
//   ELF. Rather than change the base image, a tiny Python shim on the host
//   bridges the gap. The container reaches it via host.docker.internal
//   (extra_hosts → 172.17.0.1).
//
// Why Claude Code instead of direct Anthropic API:
//   Uses the operator's Claude Code subscription — no ANTHROPIC_API_KEY
//   needed. Opus 4.8 with full Claude Code tool set (Bash, Read, Write,
//   WebSearch, etc.) plus /proj filesystem access for super_admin.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// claudeProxyURL returns the host-side claude-proxy.py base URL.
func claudeProxyURL() string {
	if u := os.Getenv("CLAUDE_PROXY_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://host.docker.internal:9201"
}

// claudeCodeKeyFn satisfies llmProvider.keyFn. Auth flows through
// ~/.claude/ credentials read by the proxy on the host — no API key.
func claudeCodeKeyFn() (string, error) { return "claude-code", nil }

// isClaudeCodeProvider reports whether a provider routes through the local
// claude CLI proxy (no HTTP endpoint) rather than an Anthropic-wire endpoint.
// Covers both claude-code-opus and claude-code-sonnet.
func isClaudeCodeProvider(p llmProvider) bool {
	return strings.HasPrefix(p.id, "claude-code")
}

// streamClaudeCodeViaProxy sends the conversation to the host proxy,
// reads its streaming NDJSON, and re-emits as SSE events.
func streamClaudeCodeViaProxy(
	ctx context.Context,
	_ *gin.Context,
	userID string,
	role string, // caller role — gates filesystem access at the proxy
	messages []chatMessage,
	systemPrompt string,
	model string, // claude CLI --model alias ("opus" | "sonnet")
	emit func(map[string]any) bool,
) error {
	if model == "" {
		model = "opus"
	}
	// Access policy mirrored from the in-house file tools (writeRoot):
	// only super_admin operates the /proj deployment tree with full
	// write + skip-permissions. Everyone else (admins included) gets a
	// READ-ONLY claude scoped to their OWN tenant workspace — the proxy
	// drops --allow-dangerously-skip-permissions, points --add-dir at this
	// workspace instead of /proj, and disallows the mutating/exec tools.
	// This keeps "admin = read-only on the deployment workspace" intact
	// even though claude-code-sonnet is admin-selectable.
	workspace := ""
	if role != "super_admin" {
		workspace = ownWorkspace(userID)
	}
	body, _ := json.Marshal(map[string]any{
		"messages":  proxyMessages(messages),
		"model":     model,
		"system":    systemPrompt,
		"role":      role,
		"workspace": workspace,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		claudeProxyURL()+"/claude/stream", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// No client-level timeout — the stream runs until claude finishes.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("claude proxy unreachable at %s: %w\n"+
			"(start: nohup python3 /home/luyao/bin/claude-proxy.py >> /tmp/claude-proxy.log 2>&1 &)",
			claudeProxyURL(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("claude proxy returned HTTP %d", resp.StatusCode)
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
