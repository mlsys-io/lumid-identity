package handler

// Replay tests for the claude CLI stream-json → SSE translator.
//
// testdata/claude_stream_subagent.ndjson is a REAL capture from claude CLI
// 2.1.220 (`-p --output-format stream-json --include-partial-messages`) of a
// prompt that dispatched a Task sub-agent which ran a Bash command, then ran
// one itself. 93 events. The `tools` list in system/init was trimmed for
// readability; nothing else was altered.
//
// This is the regression gate for stream-json shape: the format is documented
// but not versioned, so a CLI bump can silently change it. Re-capture and
// re-run these on every pin bump (see claude-sandbox BUILD.md).

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// replayFixture feeds every line of a capture through a fresh translator and
// returns the SSE events it produced, in order.
func replayFixture(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	var got []map[string]any
	tr := newClaudeTranslator("test-user", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("fixture line is not JSON: %v", err)
		}
		if !tr.handle(event) {
			t.Fatal("handle returned false; the test emit never fails")
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	return got
}

func countByType(events []map[string]any) map[string]int {
	n := map[string]int{}
	for _, e := range events {
		s, _ := e["type"].(string)
		n[s]++
	}
	return n
}

// The headline regression: every event class the old translator dropped must
// now reach the client. Each of these was silently discarded before.
func TestTranslatorEmitsPreviouslyDroppedEvents(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")
	n := countByType(got)

	for _, want := range []string{
		"claude_session",    // was the ONLY thing system/init produced
		"capabilities",      // tools/agents/model/cwd — all dropped
		"status",            // upstream request state
		"block_start",       // content-block boundaries
		"block_stop",        //   "
		"tool_args_delta",   // streaming tool arguments
		"subagent_start",    // Task lifecycle
		"subagent_progress", //   "
		"subagent_done",     //   "
		"turn_stats",        // cost/duration/turns/cache
		"tool_start",        // (already worked)
		"tool_call",         // (already worked)
		"text",              // (already worked)
	} {
		if n[want] == 0 {
			t.Errorf("no %q event emitted; got %v", want, n)
		}
	}
}

// A sub-agent's inner work must be attributable to the Task that spawned it,
// or the UI cannot nest it and shows it as the main agent's own tool call.
func TestSubagentEventsCarryParentAttribution(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")

	var parentedTool map[string]any
	for _, e := range got {
		if e["type"] == "tool_call" && e["parent_id"] != nil {
			parentedTool = e
			break
		}
	}
	if parentedTool == nil {
		t.Fatal("no tool_call carried parent_id; sub-agent tool results are unattributable")
	}
	if parentedTool["name"] != "Bash" {
		t.Errorf("expected the sub-agent's Bash result, got name=%v", parentedTool["name"])
	}

	// subagent_start must expose both correlation keys: the consumer matches
	// on EITHER because system/task_* and assistant/user arrive unordered.
	var start map[string]any
	for _, e := range got {
		if e["type"] == "subagent_start" {
			start = e
			break
		}
	}
	if start == nil {
		t.Fatal("no subagent_start emitted")
	}
	if s, _ := start["task_id"].(string); s == "" {
		t.Error("subagent_start missing task_id")
	}
	if s, _ := start["tool_use_id"].(string); s == "" {
		t.Error("subagent_start missing tool_use_id")
	}
	if start["subagent_type"] != "general-purpose" {
		t.Errorf("subagent_type = %v, want general-purpose", start["subagent_type"])
	}

	// The parent_id on the child's events must equal the Task's tool_use_id.
	if parentedTool["parent_id"] != start["tool_use_id"] {
		t.Errorf("parent_id %v does not match subagent tool_use_id %v",
			parentedTool["parent_id"], start["tool_use_id"])
	}
}

// The main agent's tool results ship a typed payload (Bash splits
// stdout/stderr and flags `interrupted`) next to the flattened string; a
// renderer needs the typed form to split the streams.
func TestToolCallForwardsTypedResult(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")

	for _, e := range got {
		// Top-level only — see TestSubagentToolResultsHaveNoTypedPayload.
		if e["type"] != "tool_call" || e["name"] != "Bash" || e["parent_id"] != nil {
			continue
		}
		typed, ok := e["result_typed"].(map[string]any)
		if !ok {
			t.Fatalf("main-agent Bash tool_call has no typed result: %v", e)
		}
		if _, ok := typed["stdout"]; !ok {
			t.Errorf("typed Bash result missing stdout: %v", typed)
		}
		if _, ok := typed["stderr"]; !ok {
			t.Errorf("typed Bash result missing stderr: %v", typed)
		}
		return
	}
	t.Fatal("no top-level Bash tool_call found in fixture")
}

// Documents a real asymmetry in the CLI, discovered from the capture: the
// `user` messages the CLI forwards on a sub-agent's behalf (those carrying
// subagent_type + task_description) do NOT include tool_use_result — only
// the main agent's own tool results do. So a nested tool card can render the
// flattened string but cannot split stdout/stderr.
//
// If this test starts failing, the CLI began sending typed results for
// sub-agents too: delete the test and let the richer renderer light up.
func TestSubagentToolResultsHaveNoTypedPayload(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")

	var checked int
	for _, e := range got {
		if e["type"] != "tool_call" || e["parent_id"] == nil {
			continue
		}
		checked++
		if _, ok := e["result_typed"]; ok {
			t.Errorf("sub-agent tool_call now HAS a typed result — see doc comment: %v", e)
		}
	}
	if checked == 0 {
		t.Fatal("fixture has no sub-agent tool_call to check")
	}
}

// signature_delta is the opaque thinking attestation. Leaking it as reasoning
// text would render a base64 blob into the user's thinking block.
func TestSignatureDeltaIsNotEmittedAsThinking(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")
	for _, e := range got {
		if e["type"] != "thinking" {
			continue
		}
		d, _ := e["delta"].(string)
		if len(d) > 120 && !strings.Contains(d, " ") {
			t.Errorf("thinking delta looks like a signature blob: %.60s…", d)
		}
	}
}

// A thinking content block must bracket its deltas with the same event names
// the client already understands from the direct-Anthropic path.
func TestThinkingBlockIsBracketed(t *testing.T) {
	got := replayFixture(t, "testdata/claude_stream_subagent.ndjson")
	var starts, stops int
	for _, e := range got {
		switch e["type"] {
		case "thinking_start":
			starts++
		case "thinking_stop":
			stops++
		}
	}
	if starts == 0 {
		t.Fatal("fixture contains a thinking block but no thinking_start was emitted")
	}
	if starts != stops {
		t.Errorf("unbalanced thinking bracket: %d starts, %d stops", starts, stops)
	}
}

// The bug this fixes: only the literal subtype "error" was handled, so the
// CLI's own terminal failure modes fell through and the turn reported success.
func TestResultErrorSubtypesAllSurface(t *testing.T) {
	cases := []struct {
		name    string
		event   map[string]any
		wantSub string
	}{
		{"max_turns", map[string]any{
			"type": "result", "subtype": "error_max_turns", "is_error": true,
		}, "step limit"},
		{"during_execution", map[string]any{
			"type": "result", "subtype": "error_during_execution", "is_error": true,
		}, "internal error"},
		{"sandbox_synthesized", map[string]any{
			"type": "result", "subtype": "error", "result": "claude exited: boom",
		}, "boom"},
		{"unknown_subtype", map[string]any{
			"type": "result", "subtype": "error_something_new", "is_error": true,
		}, "ended unexpectedly"},
		{"success_flagged_error", map[string]any{
			"type": "result", "subtype": "success", "is_error": true, "result": "partial failure",
		}, "partial failure"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []map[string]any
			tr := newClaudeTranslator("u", func(m map[string]any) bool {
				got = append(got, m)
				return true
			})
			tr.handle(tc.event)

			if len(got) != 1 || got[0]["type"] != "error" {
				t.Fatalf("expected exactly one error event, got %v", got)
			}
			msg, _ := got[0]["message"].(string)
			if !strings.Contains(msg, tc.wantSub) {
				t.Errorf("message %q does not mention %q", msg, tc.wantSub)
			}
		})
	}
}

// Quota exhaustion arrives as an Anthropic rate_limit_error buried in CLI
// error text; the user needs to be pointed at their pool windows.
func TestQuotaErrorIsRewritten(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})
	tr.handle(map[string]any{
		"type": "result", "subtype": "error",
		"result": `{"type":"rate_limit_error","message":"limit reached"}`,
	})
	msg, _ := got[0]["message"].(string)
	if !strings.Contains(msg, "lum.id/code") {
		t.Errorf("quota error not rewritten with a pointer to the pool page: %q", msg)
	}
}

// A successful turn must yield the telemetry the footer renders, and must NOT
// masquerade as the per-user budget `usage` event from the Anthropic path.
func TestSuccessEmitsTurnStatsNotUsage(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})
	tr.handle(map[string]any{
		"type": "result", "subtype": "success",
		"total_cost_usd": 0.0421, "duration_ms": float64(8123),
		"num_turns": float64(3),
		"usage":     map[string]any{"cache_read_input_tokens": float64(49340)},
	})

	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0]["type"] != "turn_stats" {
		t.Errorf("type = %v, want turn_stats", got[0]["type"])
	}
	if got[0]["cost_usd"] != 0.0421 {
		t.Errorf("cost_usd = %v, want 0.0421", got[0]["cost_usd"])
	}
	if got[0]["num_turns"] != float64(3) {
		t.Errorf("num_turns = %v, want 3", got[0]["num_turns"])
	}
}

// Block indices restart per message and a sub-agent streams concurrently with
// its parent, so an unscoped index map would cross-wire their tool arguments.
func TestBlockIndicesAreScopedByParent(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})

	blockStart := func(parent, toolID string) map[string]any {
		e := map[string]any{"type": "stream_event", "event": map[string]any{
			"type": "content_block_start", "index": float64(1),
			"content_block": map[string]any{"type": "tool_use", "id": toolID, "name": "Bash"},
		}}
		if parent != "" {
			e["parent_tool_use_id"] = parent
		}
		return e
	}
	argsDelta := func(parent string) map[string]any {
		e := map[string]any{"type": "stream_event", "event": map[string]any{
			"type": "content_block_delta", "index": float64(1),
			"delta": map[string]any{"type": "input_json_delta", "partial_json": `{"c":1}`},
		}}
		if parent != "" {
			e["parent_tool_use_id"] = parent
		}
		return e
	}

	// Parent and sub-agent each open a tool_use at index 1.
	tr.handle(blockStart("", "toolu_parent"))
	tr.handle(blockStart("toolu_task", "toolu_child"))
	tr.handle(argsDelta("toolu_task"))
	tr.handle(argsDelta(""))

	var ids []string
	for _, e := range got {
		if e["type"] == "tool_args_delta" {
			id, _ := e["id"].(string)
			ids = append(ids, id)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("want 2 tool_args_delta, got %v", ids)
	}
	if ids[0] != "toolu_child" {
		t.Errorf("sub-agent args attributed to %q, want toolu_child", ids[0])
	}
	if ids[1] != "toolu_parent" {
		t.Errorf("parent args attributed to %q, want toolu_parent", ids[1])
	}
}

// A user-requested stop must NOT read as a failure. The CLI reports an
// interrupted turn as error_during_execution and the sandbox then synthesizes a
// non-zero-exit result — both would otherwise surface as "internal error".
func TestInterruptedTurnReportsStoppedNotError(t *testing.T) {
	// Emitted exactly ONCE across both terminal shapes — a stopped turn
	// produces the CLI's error_during_execution AND the sandbox's synthesized
	// non-zero-exit result, and two "Stopped" notices read as a glitch.
	var all []map[string]any
	trOnce := newClaudeTranslator("u", func(m map[string]any) bool {
		all = append(all, m)
		return true
	})
	trOnce.stopped = func() bool { return true }
	trOnce.handle(map[string]any{"type": "result", "subtype": "error_during_execution", "is_error": true})
	trOnce.handle(map[string]any{"type": "result", "subtype": "error", "result": "claude exited: exit status 1"})
	if len(all) != 1 {
		t.Errorf("want exactly 1 stopped event across both terminal shapes, got %d: %v", len(all), all)
	}

	for _, ev := range []map[string]any{
		{"type": "result", "subtype": "error_during_execution", "is_error": true},
		{"type": "result", "subtype": "error", "result": "claude exited: exit status 1"},
	} {
		var got []map[string]any
		tr := newClaudeTranslator("u", func(m map[string]any) bool {
			got = append(got, m)
			return true
		})
		tr.stopped = func() bool { return true }
		tr.handle(ev)

		if len(got) != 1 {
			t.Fatalf("want 1 event, got %v", got)
		}
		if got[0]["type"] != "stopped" {
			t.Errorf("subtype %v produced %v, want type=stopped", ev["subtype"], got[0])
		}
	}
}

// The same events with no stop requested must still surface as errors — the
// stopped predicate must not swallow real failures.
func TestUninterruptedFailureStillErrors(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})
	tr.stopped = func() bool { return false }
	tr.handle(map[string]any{"type": "result", "subtype": "error_during_execution", "is_error": true})

	if len(got) != 1 || got[0]["type"] != "error" {
		t.Fatalf("want a single error event, got %v", got)
	}
}

// The CLI ships its own reasoning-token count; the client had been inferring it
// from text length at ~4 chars/token.
func TestThinkingTokensForwarded(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})
	tr.handle(map[string]any{
		"type": "system", "subtype": "thinking_tokens",
		"estimated_tokens": float64(69), "estimated_tokens_delta": float64(19),
	})
	if len(got) != 1 || got[0]["type"] != "thinking_tokens" {
		t.Fatalf("want thinking_tokens, got %v", got)
	}
	if got[0]["tokens"] != float64(69) || got[0]["delta"] != float64(19) {
		t.Errorf("tokens/delta not forwarded: %v", got[0])
	}
}

// The same-pod stop flag: only the owner's stop flips it.
//
// Ownership is ENFORCED by the sandbox (single-replica, authoritative), not
// here — identity runs multiple replicas with no session affinity, so an
// in-memory map is not a consistent view. This only checks the local fast path.
func TestLocalStopFlagRespectsOwner(t *testing.T) {
	turn := registerClaudeTurn("t-own", "alice")
	defer unregisterClaudeTurn("t-own")

	markLocalStop("t-own", "bob")
	if claudeTurnInterrupted("", turn) {
		t.Error("bob's stop flipped alice's turn flag")
	}
	markLocalStop("t-own", "alice")
	if !claudeTurnInterrupted("", turn) {
		t.Error("alice's own stop did not flip the flag")
	}
}

// A nil turn (no X-Turn-Id, or a stream on another pod) must not panic and must
// not claim a stop happened when there is no Redis marker either.
func TestStopFlagNilTurnIsFalse(t *testing.T) {
	if claudeTurnInterrupted("t-nowhere", nil) {
		t.Error("unknown turn reported as stopped")
	}
}

// system/task_* covers BOTH sub-agents (task_type local_agent) and
// backgrounded Bash commands (local_bash). Only task_started carries
// task_type, so the agent ids must be remembered — otherwise a backgrounded
// `sleep` renders as a sub-agent panel (observed live before this fix).
func TestBackgroundBashIsNotASubagent(t *testing.T) {
	var got []map[string]any
	tr := newClaudeTranslator("u", func(m map[string]any) bool {
		got = append(got, m)
		return true
	})

	// A backgrounded shell command.
	tr.handle(map[string]any{"type": "system", "subtype": "task_started",
		"task_id": "bg1", "task_type": "local_bash", "description": "Sleep for 120 seconds"})
	tr.handle(map[string]any{"type": "system", "subtype": "task_progress", "task_id": "bg1"})
	tr.handle(map[string]any{"type": "system", "subtype": "task_notification",
		"task_id": "bg1", "status": "completed"})

	for _, e := range got {
		if s, _ := e["type"].(string); strings.HasPrefix(s, "subagent") {
			t.Errorf("background bash leaked as %s: %v", s, e)
		}
	}
	if len(got) != 1 || got[0]["type"] != "background_task" {
		t.Fatalf("want a single background_task event, got %v", got)
	}

	// A real sub-agent, same follow-up shapes, must still come through.
	got = nil
	tr.handle(map[string]any{"type": "system", "subtype": "task_started",
		"task_id": "ag1", "task_type": "local_agent", "subagent_type": "general-purpose"})
	tr.handle(map[string]any{"type": "system", "subtype": "task_progress",
		"task_id": "ag1", "last_tool_name": "Bash"})
	tr.handle(map[string]any{"type": "system", "subtype": "task_notification",
		"task_id": "ag1", "status": "completed"})

	var kinds []string
	for _, e := range got {
		kinds = append(kinds, e["type"].(string))
	}
	want := []string{"subagent_start", "subagent_progress", "subagent_done"}
	if len(kinds) != 3 || kinds[0] != want[0] || kinds[1] != want[1] || kinds[2] != want[2] {
		t.Errorf("sub-agent lifecycle = %v, want %v", kinds, want)
	}
}
