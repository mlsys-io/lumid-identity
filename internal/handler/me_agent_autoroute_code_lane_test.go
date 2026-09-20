package handler

// A turn that names a sandbox-only tool must STAY on the claude-code lane.
//
// autoRouteForTurn exists because the CLI cannot see the me_agent registry, so
// a platform-control turn is moved to a tool-capable provider. That is still
// right. What it must not do is move a turn whose whole request is for a tool
// that ONLY the sandbox has — there, routing away does not rescue the turn, it
// guarantees the failure.
//
// Measured 2026-09-19 before this guard: selecting claude-code-sonnet and
// asking for mcp__lumid__app_detail + mcp__lumid__stage_proposals produced
// {"auto_routed":true,"model_used":"deepseek-v4-flash"}, and the model answered
// — correctly — "I have no tools whose names start with mcp__lumid__ at all".

import "testing"

func codeLaneProvider(t *testing.T) llmProvider {
	t.Helper()
	for _, p := range llmProviders {
		if isClaudeCodeProvider(p) {
			return p
		}
	}
	t.Fatal("no claude-code provider in the catalog")
	return llmProvider{}
}

// The regression itself: a control-shaped prompt that names an MCP tool.
func TestNamingAnMCPToolKeepsTheTurnOnTheCodeLane(t *testing.T) {
	code := codeLaneProvider(t)
	msg := userMsg(`Use mcp__lumid__app_detail on quant-research, then run the experiment ` +
		`and call mcp__lumid__stage_proposals with the four candidates.`)

	// Precondition: this prompt DOES look like platform control. Without it the
	// test could pass because controlIntent simply never fired, which would
	// prove nothing.
	if !controlIntent(msg) {
		t.Fatal("prompt no longer reads as control intent — the guard is untested by this case")
	}

	got, routed := autoRouteForTurn(msg, code, "super_admin", nil, "")
	if routed {
		t.Fatalf("turn was stolen to %q; the mcp__ tools it asks for exist only in the sandbox", got.id)
	}
	if got.id != code.id {
		t.Fatalf("provider changed to %q", got.id)
	}
}

// The guard must be narrow: control turns that do NOT name an MCP tool still
// route, because the CLI genuinely cannot serve them.
func TestOrdinaryControlTurnsStillRoute(t *testing.T) {
	code := codeLaneProvider(t)
	// Phrases verified to trigger controlIntent on this build. "install the
	// <app> app" deliberately is NOT among them — it does not match today, a
	// pre-existing gap in controlIntentPhrases unrelated to this guard, and
	// asserting it here would test the phrase list rather than the routing.
	for _, m := range []string{
		"run the arm panel_median3 on mbb-consultant",
		"publish my app",
		"run the experiment judge_panel_parity",
	} {
		if _, routed := autoRouteForTurn(userMsg(m), code, "super_admin", nil, ""); !routed {
			t.Errorf("control turn should still route away from the CLI: %q", m)
		}
	}
}

// An explicit search toggle outranks an mcp__ mention: its failure on the code
// lane is SILENT (NetworkPolicy blocks the CLI's WebSearch), so a user who
// flipped the switch must still reach the Tavily-backed tools.
func TestSearchModeOutranksAnMCPMention(t *testing.T) {
	code := codeLaneProvider(t)
	msg := userMsg("use mcp__lumid__data_query and search the web for context")
	for _, mode := range []string{"search", "deep_research"} {
		if _, routed := autoRouteForTurn(msg, code, "super_admin", nil, mode); !routed {
			t.Errorf("mode=%s must still route; its failure on the CLI lane is silent", mode)
		}
	}
}

func TestGuardMatchesOnlyRealToolSpellings(t *testing.T) {
	yes := []string{
		"call mcp__lumid__stage_proposals please",
		"MCP__LUMID__APP_DETAIL on quant-research",
		"use mcp__other__some_tool",
	}
	for _, m := range yes {
		if !namesSandboxOnlyTool(userMsg(m)) {
			t.Errorf("should match: %q", m)
		}
	}
	// A bare mention of MCP is not a tool name. Widening this to the word "mcp"
	// would pin ordinary conversation to the sandbox.
	no := []string{
		"how does mcp work?",
		"the mcp server is down",
		"run the arm on mbb-consultant",
		"mcp__lumid__",
	}
	for _, m := range no {
		if namesSandboxOnlyTool(userMsg(m)) {
			t.Errorf("should NOT match: %q", m)
		}
	}
}

// Only the LAST user message counts, matching controlIntent. An mcp__ name
// mentioned earlier must not pin every later turn to the sandbox.
func TestOnlyTheLatestUserMessageIsConsidered(t *testing.T) {
	msgs := []chatMessage{
		{Role: "user", Content: "call mcp__lumid__stage_proposals"},
		{Role: "assistant", Content: "done"},
		{Role: "user", Content: "now install the mbb-consultant app"},
	}
	if namesSandboxOnlyTool(msgs) {
		t.Fatal("a stale mention pinned a later turn to the sandbox")
	}
}
