package handler

import (
	"encoding/json"
	"testing"
)

// TestCountToolUseOnStreamingTurn is the regression for tool_use_count reading 0
// on every streaming session. claude-proxy stores SSE responses as a JSON
// STRING (raw event-stream bytes are not valid JSON), so unmarshalling into a
// {content:[...]} struct always failed and the count silently fell to 0 —
// observed live on 75- and 85-turn Claude Code sessions of heavy tool use.
func TestCountToolUseOnStreamingTurn(t *testing.T) {
	sse := `event: message_start
data: {"type":"message_start","message":{"id":"msg_1","content":[]}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tu_1","name":"Bash","input":{}}}

event: content_block_start
data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"tu_2","name":"Read","input":{}}}

event: message_stop
data: {"type":"message_stop"}
`
	stored, err := json.Marshal(sse) // exactly what postTranscript stores
	if err != nil {
		t.Fatal(err)
	}
	if got := countToolUse(stored); got != 2 {
		t.Fatalf("streaming turn: want 2 tool_use, got %d", got)
	}
}

// TestCountToolUseOnNonStreamingTurn pins that the object path still works.
func TestCountToolUseOnNonStreamingTurn(t *testing.T) {
	body := json.RawMessage(`{"content":[{"type":"text"},{"type":"tool_use"},{"type":"tool_use"}]}`)
	if got := countToolUse(body); got != 2 {
		t.Fatalf("non-streaming turn: want 2, got %d", got)
	}
	if got := countToolUse(json.RawMessage(`{"content":[{"type":"text"}]}`)); got != 0 {
		t.Fatalf("text-only turn: want 0, got %d", got)
	}
	if got := countToolUse(json.RawMessage(`not json`)); got != 0 {
		t.Fatalf("garbage: want 0, got %d", got)
	}
}
