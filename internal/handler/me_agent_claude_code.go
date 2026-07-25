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
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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

// ── live turn registry (cooperative interrupt) ──────────────────────────────
//
// The sandbox returns an X-Turn-Id for each streaming run and accepts
// POST /claude/control to steer it. We keep a per-pod map of live turns so
// POST /me/agent/chat/interrupt (a SEPARATE request from the stream) can find
// the right run, and so the stream goroutine knows the stop was requested —
// otherwise a user-initiated stop surfaces as the CLI's
// `error_during_execution` and reads as an internal failure.

type claudeTurn struct {
	userID      string
	interrupted bool
}

var (
	claudeTurnsMu sync.Mutex
	claudeTurns   = map[string]*claudeTurn{}
)

func registerClaudeTurn(turnID, userID string) *claudeTurn {
	t := &claudeTurn{userID: userID}
	claudeTurnsMu.Lock()
	claudeTurns[turnID] = t
	claudeTurnsMu.Unlock()
	return t
}

func unregisterClaudeTurn(turnID string) {
	claudeTurnsMu.Lock()
	delete(claudeTurns, turnID)
	claudeTurnsMu.Unlock()
}

// claudeStoppedKey marks a turn as user-stopped ACROSS PODS.
//
// identity runs multiple replicas with no session affinity, so the interrupt
// request routinely lands on a different pod than the one holding the stream —
// measured 2 of 3 in a live test. An in-memory flag therefore cannot tell the
// streaming goroutine that the user pressed Stop, and the turn's terminal
// event would render as "stopped with an internal error". Redis is the shared
// signal; the local map stays as a same-pod fast path and as the fallback when
// Redis is unavailable.
func claudeStoppedKey(turnID string) string { return "claude:stopped:" + turnID }

const claudeStoppedTTL = 30 * time.Minute

// markClaudeTurnInterrupted records the stop locally (best effort) and
// cross-pod via Redis. Authorization is NOT done here — see
// InterruptClaudeTurn.
func markClaudeTurnInterrupted(turnID, userID string) {
	claudeTurnsMu.Lock()
	if t := claudeTurns[turnID]; t != nil && t.userID == userID {
		t.interrupted = true
	}
	claudeTurnsMu.Unlock()

	if common.Redis != nil {
		_ = common.Redis.Set(context.Background(), claudeStoppedKey(turnID), userID, claudeStoppedTTL).Err()
	}
}

// claudeTurnInterrupted reports whether the user asked to stop this turn,
// checking the same-pod flag first and then the cross-pod Redis marker.
func claudeTurnInterrupted(turnID string, t *claudeTurn) bool {
	if t != nil {
		claudeTurnsMu.Lock()
		local := t.interrupted
		claudeTurnsMu.Unlock()
		if local {
			return true
		}
	}
	if turnID == "" || common.Redis == nil {
		return false
	}
	n, err := common.Redis.Exists(context.Background(), claudeStoppedKey(turnID)).Result()
	return err == nil && n > 0
}

// InterruptClaudeTurn asks the sandbox to stop a live turn cooperatively.
func InterruptClaudeTurn(ctx context.Context, turnID, userID string) error {
	markClaudeTurnInterrupted(turnID, userID)
	// ALWAYS forward. This used to early-return when the turn wasn't in this
	// pod's map, which made the Stop button a silent no-op whenever the request
	// landed on the pod that wasn't streaming (2 of 3 attempts, measured).
	// Ownership is enforced by the sandbox, which is single-replica and holds
	// the only consistent turn→owner mapping; it answers 403 on a mismatch.
	body, _ := json.Marshal(map[string]any{
		"turn_id": turnID, "action": "interrupt", "user_id": userID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		claudeSandboxURL()+"/claude/control", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", os.Getenv("LUMID_IDENTITY_BRIDGE_SECRET"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("claude sandbox unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("that turn belongs to another user")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sandbox control returned HTTP %d", resp.StatusCode)
	}
	return nil
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
	// Pre-assign the session UUID on a fresh run so the id is known BEFORE the
	// stream starts, instead of being scraped out of system/init.
	newSessionID := ""
	if sessionID == "" {
		newSessionID = uuid.NewString()
		recordClaudeSession(userID, newSessionID)
	}
	body, _ := json.Marshal(map[string]any{
		"messages":        proxyMessages(messages),
		"model":           model,
		"system":          systemPrompt,
		"role":            role,
		"user_id":         userID,
		"session_id":      sessionID,
		"new_session_id":  newSessionID,
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

	// The sandbox names this run; POST /me/agent/chat/interrupt targets it.
	turnID := resp.Header.Get("X-Turn-Id")
	var turn *claudeTurn
	if turnID != "" {
		turn = registerClaudeTurn(turnID, userID)
		defer unregisterClaudeTurn(turnID)
		if !emit(map[string]any{"type": "turn_id", "turn_id": turnID}) {
			return nil
		}
	}

	tr := newClaudeTranslator(userID, emit)
	tr.stopped = func() bool { return claudeTurnInterrupted(turnID, turn) }

	// Read lines on a goroutine so the main loop can also fire heartbeats.
	// All emit() calls stay on THIS goroutine — the SSE writer is not
	// safe for concurrent use.
	//
	// bufio.Reader, not bufio.Scanner: Scanner has a hard per-line ceiling
	// (we used to set 2 MiB), and a single oversized event — one big Read
	// result, a base64 image in a tool_result — made Scan() fail, stopped
	// the drain, and killed the rest of the turn.
	type lineRead struct {
		line string
		err  error
	}
	lines := make(chan lineRead, 64)
	readerDone := make(chan struct{})
	defer close(readerDone)
	go func() {
		rd := bufio.NewReader(resp.Body)
		for {
			s, err := rd.ReadString('\n')
			select {
			case lines <- lineRead{s, err}:
			case <-readerDone:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Long tool calls emit nothing for minutes; without a periodic byte an
	// idle-timeout in any intermediary drops the stream.
	beat := time.NewTicker(15 * time.Second)
	defer beat.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-beat.C:
			if !emit(map[string]any{"type": "ping"}) {
				return nil // client gone
			}

		case lr := <-lines:
			if line := strings.TrimSpace(lr.line); line != "" {
				var event map[string]any
				if err := json.Unmarshal([]byte(line), &event); err == nil {
					if !tr.handle(event) {
						return nil // client gone
					}
				}
			}
			if lr.err != nil {
				if lr.err == io.EOF {
					return nil
				}
				return lr.err
			}
		}
	}
}

// ── NDJSON → SSE translation ────────────────────────────────────────────────
//
// The claude CLI emits far more than we used to forward. Everything below is
// present in a real 2.1.x stream and was previously dropped on the floor:
// thinking deltas, content-block boundaries, streaming tool arguments,
// sub-agent lifecycle + attribution, context compaction, and the whole
// result telemetry payload.
//
// Held as a struct (rather than inline in the read loop) so a recorded
// stream can be replayed through handle() in a test without a live CLI —
// see claude-sandbox BUILD.md.

type claudeTranslator struct {
	userID string
	emit   func(map[string]any) bool
	// stopped reports whether the user asked to stop this turn. An interrupted
	// run ends as `error_during_execution`, which must NOT be shown as an
	// internal failure when the user pressed Stop.
	stopped func() bool
	// A stopped turn produces TWO terminal events (the CLI's
	// error_during_execution, then the sandbox's synthesized non-zero exit), so
	// the notice has to be emitted once.
	sentStopped bool

	toolNameByID map[string]string // tool_use id → name, for the later tool_result
	blockKind    map[string]string // scoped block index → "text"|"thinking"|"tool_use"
	blockToolID  map[string]string // scoped block index → tool_use id
	// system/task_* covers BOTH sub-agents (task_type local_agent) AND
	// backgrounded Bash commands (local_bash) — and only task_started carries
	// task_type, so the agent ids have to be remembered. Without this a
	// backgrounded `sleep` renders as a sub-agent panel.
	agentTasks map[string]bool
}

func newClaudeTranslator(userID string, emit func(map[string]any) bool) *claudeTranslator {
	return &claudeTranslator{
		userID:       userID,
		emit:         emit,
		toolNameByID: map[string]string{},
		blockKind:    map[string]string{},
		blockToolID:  map[string]string{},
		agentTasks:   map[string]bool{},
	}
}

// send attaches sub-agent attribution before emitting. parent_id is the
// parent Task's tool_use id: present on every event a sub-agent produced,
// absent on the main agent's own events.
func (t *claudeTranslator) send(m map[string]any, parentID string) bool {
	if parentID != "" {
		m["parent_id"] = parentID
	}
	return t.emit(m)
}

// blockRef scopes a content-block index by its owner. Block indices restart
// per message and a sub-agent streams concurrently with its parent, so the
// index alone is ambiguous.
func blockRef(parentID string, idx int) string {
	return fmt.Sprintf("%s#%d", parentID, idx)
}

func intField(m map[string]any, k string) int {
	f, _ := m[k].(float64)
	return int(f)
}

func (t *claudeTranslator) handle(event map[string]any) bool {
	parentID, _ := event["parent_tool_use_id"].(string)

	switch event["type"] {

	case "system":
		return t.handleSystem(event)

	case "stream_event":
		return t.handleStreamEvent(event, parentID)

	case "assistant":
		// Complete assistant message. Text and thinking already streamed as
		// deltas via stream_event, so only tool_use blocks are new here —
		// and only here do we have the fully-parsed argument JSON.
		if isPartial, _ := event["is_partial"].(bool); isPartial {
			return true
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
			t.toolNameByID[id] = name
			if !t.send(map[string]any{
				"type": "tool_start",
				"id":   id,
				"name": name,
				"args": input,
			}, parentID) {
				return false
			}
		}

	case "user":
		// Tool results handed back to the model.
		msg, _ := event["message"].(map[string]any)
		content, _ := msg["content"].([]any)
		for _, raw := range content {
			b, _ := raw.(map[string]any)
			if b["type"] != "tool_result" {
				continue
			}
			id, _ := b["tool_use_id"].(string)
			isError, _ := b["is_error"].(bool)
			name := t.toolNameByID[id]
			if name == "" {
				name = id
			}
			out := map[string]any{
				"type":   "tool_call",
				"id":     id,
				"name":   name,
				"result": b["content"],
				"ok":     !isError,
			}
			// The CLI also ships a TYPED result alongside the flattened
			// content — Bash splits stdout/stderr and flags `interrupted`,
			// Task reports token/tool counts. Far richer than the string.
			//
			// Only on the main agent's own results: the `user` messages the
			// CLI forwards on a SUB-AGENT's behalf omit tool_use_result, so
			// nested tool cards get the flattened string only.
			if typed, ok := event["tool_use_result"]; ok && typed != nil {
				out["result_typed"] = typed
			}
			if !t.send(out, parentID) {
				return false
			}
		}

	case "result":
		return t.handleResult(event)
	}

	return true
}

func (t *claudeTranslator) handleSystem(event map[string]any) bool {
	sub, _ := event["subtype"].(string)
	switch sub {

	case "init":
		// Carries this run's session_id (authorizes a future --resume) plus
		// the full capability surface of the session.
		sid, _ := event["session_id"].(string)
		if sid != "" {
			recordClaudeSession(t.userID, sid)
			if !t.emit(map[string]any{"type": "claude_session", "session_id": sid}) {
				return false
			}
		}
		return t.emit(map[string]any{
			"type":            "capabilities",
			"model":           event["model"],
			"cwd":             event["cwd"],
			"permission_mode": event["permissionMode"],
			"tools":           event["tools"],
			"agents":          event["agents"],
			"skills":          event["skills"],
			"slash_commands":  event["slash_commands"],
			"version":         event["claude_code_version"],
		})

	case "status":
		// Upstream request state ("requesting"), for a liveness indicator.
		return t.emit(map[string]any{"type": "status", "status": event["status"]})

	case "thinking_tokens":
		// The CLI's OWN running estimate of reasoning tokens. The client had
		// been inferring this from text length at ~4 chars/token.
		return t.emit(map[string]any{
			"type":   "thinking_tokens",
			"tokens": event["estimated_tokens"],
			"delta":  event["estimated_tokens_delta"],
		})

	case "compact_boundary":
		// The CLI compacted its context mid-session.
		return t.emit(map[string]any{
			"type":    "compaction",
			"trigger": event["trigger"],
			"pre":     event["pre_tokens"],
		})

	// ── sub-agent lifecycle (Task tool) ──────────────────────────────────
	// task_id keys these events; tool_use_id ties them to the parent Task
	// tool call. The consumer correlates on EITHER, because these arrive on
	// a different channel than the assistant/user messages and the two are
	// not ordered relative to each other.

	case "task_started":
		taskID, _ := event["task_id"].(string)
		if tt, _ := event["task_type"].(string); tt != "local_agent" {
			// A backgrounded shell command, not a sub-agent. Forwarded under its
			// own name so the client can surface it later without mistaking it
			// for agent activity.
			return t.emit(map[string]any{
				"type":        "background_task",
				"task_id":     taskID,
				"tool_use_id": event["tool_use_id"],
				"description": event["description"],
				"task_type":   event["task_type"],
			})
		}
		t.agentTasks[taskID] = true
		return t.emit(map[string]any{
			"type":          "subagent_start",
			"task_id":       event["task_id"],
			"tool_use_id":   event["tool_use_id"],
			"subagent_type": event["subagent_type"],
			"description":   event["description"],
			"prompt":        event["prompt"],
		})

	case "task_progress":
		if id, _ := event["task_id"].(string); !t.agentTasks[id] {
			return true // background shell task — see task_started
		}
		return t.emit(map[string]any{
			"type":           "subagent_progress",
			"task_id":        event["task_id"],
			"tool_use_id":    event["tool_use_id"],
			"description":    event["description"],
			"last_tool_name": event["last_tool_name"],
			"usage":          event["usage"],
		})

	case "task_updated":
		if id, _ := event["task_id"].(string); !t.agentTasks[id] {
			return true // background shell task — see task_started
		}
		patch, _ := event["patch"].(map[string]any)
		return t.emit(map[string]any{
			"type":     "subagent_progress",
			"task_id":  event["task_id"],
			"status":   patch["status"],
			"end_time": patch["end_time"],
		})

	case "task_notification":
		if id, _ := event["task_id"].(string); !t.agentTasks[id] {
			return true // background shell task — see task_started
		}
		return t.emit(map[string]any{
			"type":        "subagent_done",
			"task_id":     event["task_id"],
			"tool_use_id": event["tool_use_id"],
			"status":      event["status"],
			"summary":     event["summary"],
			"usage":       event["usage"],
		})
	}
	return true
}

func (t *claudeTranslator) handleStreamEvent(event map[string]any, parentID string) bool {
	inner, _ := event["event"].(map[string]any)

	switch inner["type"] {

	case "content_block_start":
		cb, _ := inner["content_block"].(map[string]any)
		kind, _ := cb["type"].(string)
		idx := intField(inner, "index")
		ref := blockRef(parentID, idx)
		t.blockKind[ref] = kind
		if id, _ := cb["id"].(string); id != "" {
			t.blockToolID[ref] = id
		}
		if !t.send(map[string]any{
			"type": "block_start", "index": idx, "kind": kind,
		}, parentID) {
			return false
		}
		// thinking_start / thinking_stop are the event names the existing
		// client already understands from the direct-Anthropic path, so
		// reasoning renders with no client change.
		if kind == "thinking" {
			return t.send(map[string]any{"type": "thinking_start"}, parentID)
		}

	case "content_block_delta":
		delta, _ := inner["delta"].(map[string]any)
		idx := intField(inner, "index")
		switch delta["type"] {

		case "text_delta":
			if text, _ := delta["text"].(string); text != "" {
				return t.send(map[string]any{"type": "text", "delta": text}, parentID)
			}

		case "thinking_delta":
			if think, _ := delta["thinking"].(string); think != "" {
				return t.send(map[string]any{"type": "thinking", "delta": think}, parentID)
			}

		case "input_json_delta":
			// Tool arguments as they are generated. The complete args still
			// arrive on the assistant message; this only lets the UI show
			// the command materializing instead of an empty pending chip.
			if pj, _ := delta["partial_json"].(string); pj != "" {
				return t.send(map[string]any{
					"type":         "tool_args_delta",
					"id":           t.blockToolID[blockRef(parentID, idx)],
					"partial_json": pj,
				}, parentID)
			}

			// signature_delta is the opaque thinking attestation — nothing
			// to render, and it must not be shown as reasoning text.
		}

	case "content_block_stop":
		idx := intField(inner, "index")
		ref := blockRef(parentID, idx)
		kind := t.blockKind[ref]
		if !t.send(map[string]any{"type": "block_stop", "index": idx, "kind": kind}, parentID) {
			return false
		}
		delete(t.blockKind, ref)
		delete(t.blockToolID, ref)
		if kind == "thinking" {
			return t.send(map[string]any{"type": "thinking_stop"}, parentID)
		}

		// message_start / message_delta / message_stop carry no per-block
		// content we don't already have from the blocks themselves.
	}

	return true
}

func (t *claudeTranslator) handleResult(event map[string]any) bool {
	subtype, _ := event["subtype"].(string)
	isErr, _ := event["is_error"].(bool)

	if subtype == "success" && !isErr {
		// Turn telemetry: cost, wall/API duration, time-to-first-token,
		// turn count, and cache hit/creation split. Named turn_stats rather
		// than usage so it can't be confused with the per-user budget
		// `usage` event the direct-Anthropic path emits.
		return t.emit(map[string]any{
			"type":              "turn_stats",
			"cost_usd":          event["total_cost_usd"],
			"duration_ms":       event["duration_ms"],
			"duration_api_ms":   event["duration_api_ms"],
			"ttft_ms":           event["ttft_ms"],
			"num_turns":         event["num_turns"],
			"usage":             event["usage"],
			"model_usage":       event["modelUsage"],
			"permission_denies": event["permission_denials"],
		})
	}

	// A user-requested stop also lands here (the CLI reports an interrupted
	// turn as error_during_execution, and the sandbox then synthesizes a
	// non-zero-exit result). Report it as what it was, not as a failure.
	if t.stopped != nil && t.stopped() {
		if t.sentStopped {
			return true
		}
		t.sentStopped = true
		return t.emit(map[string]any{"type": "stopped"})
	}

	// Every non-success terminal state. Previously only the literal
	// subtype "error" was handled — which the sandbox synthesizes on a
	// non-zero exit — so the CLI's OWN failure subtypes fell through and
	// the turn silently reported success.
	msg, _ := event["result"].(string)
	switch subtype {
	case "error_max_turns":
		if msg == "" {
			msg = "The agent reached its step limit before finishing."
		}
	case "error_during_execution":
		if msg == "" {
			msg = "The agent stopped with an internal error."
		}
	}
	if msg == "" {
		msg = "The Claude Code session ended unexpectedly (" + subtype + ")."
	}
	// Pool quota exhaustion surfaces as an Anthropic rate_limit_error inside
	// the CLI's error text — rewrite it to something actionable.
	low := strings.ToLower(msg)
	if strings.Contains(low, "rate_limit") || strings.Contains(low, "quota") {
		msg = "Pooled Claude quota reached — usage windows and reset times are at lum.id/code. " + msg
	}
	return t.emit(map[string]any{"type": "error", "message": msg})
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

// ── POST /me/agent/chat/interrupt ───────────────────────────────────────────

// MeAgentChatInterrupt stops a live Claude Code turn cooperatively.
//
// The Stop button used to only abort the browser's fetch, which cancelled the
// request context and SIGKILLed the CLI process group — tearing the stream and
// discarding whatever the turn had done so far. Going through the sandbox's
// control channel instead lets the CLI finish its current tool, flush a real
// `result`, and persist session state, so the turn stays resumable.
func MeAgentChatInterrupt(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok || userID == "" {
		c.JSON(401, gin.H{"code": 401, "message": "unauthorized"})
		return
	}
	var body struct {
		TurnID string `json:"turn_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.TurnID == "" {
		c.JSON(400, gin.H{"code": 400, "message": "turn_id required"})
		return
	}
	// Ownership is enforced inside markClaudeTurnInterrupted — a caller cannot
	// stop another user's run, and an unknown turn is a no-op rather than an
	// error so the button is never a dead end.
	if err := InterruptClaudeTurn(c.Request.Context(), body.TurnID, userID); err != nil {
		c.JSON(502, gin.H{"code": 502, "message": err.Error()})
		return
	}
	c.JSON(200, gin.H{"code": 0, "message": "ok", "data": gin.H{"ok": true}})
}
