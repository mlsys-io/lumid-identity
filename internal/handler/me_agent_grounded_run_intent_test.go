package handler

// A chat GROUNDED on an app must hear "run <that app's workflow>" in plain
// words and move the turn off the claude-code sandbox (no workflow_run there).
//
// Regression: 2026-11-25, mlsys-research, admin on claude-code-sonnet —
// "Run the baseline design for 9.2 and explain each number to me" stayed in
// the sandbox and nothing ran.

import (
	"sync/atomic"
	"testing"
)

func groundedOn(app string) map[string]any { return map[string]any{"app": app} }

func loopsFixed(names ...string) func(string) []string {
	return func(string) []string { return names }
}

func TestGroundedRunIntent(t *testing.T) {
	cases := []struct {
		name  string
		msg   string
		ctx   map[string]any
		loops []string
		want  bool
	}{
		// ── positives ───────────────────────────────────────────────────
		{"student prompt, generic noun", "Run the baseline design for 9.2 and explain each number to me",
			groundedOn("mlsys-research"), []string{"simulate"}, true},
		{"loop id as a word", "kick off simulate", groundedOn("mlsys-research"), []string{"simulate"}, true},
		{"rerun + loop id", "rerun the backtest", groundedOn("quant-research"), []string{"backtest", "harvest"}, true},
		{"re-run hyphenated", "please re-run the backtest on AAPL", groundedOn("quant-research"), []string{"backtest"}, true},
		{"underscored loop spelled as words", "launch the case eval now", groundedOn("mbb-consultant"), []string{"case_eval"}, true},
		{"underscored loop raw", "execute regression_sweep", groundedOn("mbb-ai"), []string{"regression_sweep"}, true},
		{"polite request phrased as a question", "can you run the baseline?", groundedOn("mlsys-research"), nil, true},
		{"do the design", "do the baseline design for chapter 4", groundedOn("mlsys-research"), nil, true},
		{"could you … ? is a request", "Could you kick off simulate for 9.2?", groundedOn("mlsys-research"), []string{"simulate"}, true},
		{"start a cycle", "start a cycle with the new prompt", groundedOn("mbb-ai"), nil, true},
		{"question then request", "What is 9.2 about? Run it as the baseline design.", groundedOn("mlsys-research"), nil, true},

		// ── negatives ───────────────────────────────────────────────────
		{"ungrounded generic", "run the baseline", nil, []string{"simulate"}, false},
		{"ungrounded loop id", "kick off simulate", map[string]any{}, []string{"simulate"}, false},
		{"run the tests", "run the tests", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"npm install", "run npm install", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"how do I run this", "how do I run this?", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"how would I run the experiment", "how would I run the experiment?", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"should we rerun simulate", "should we rerun simulate?", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"what does the baseline design do", "what does the baseline design do when I run it", groundedOn("mlsys-research"), nil, false},
		{"loop named test is too generic", "run the test", groundedOn("x-app"), []string{"test"}, false},
		{"programming loop", "start the event loop in main.go", groundedOn("mlsys-research"), nil, false},
		{"github workflow", "run the github workflow again", groundedOn("mlsys-research"), nil, false},
		{"no verb", "explain the baseline design", groundedOn("mlsys-research"), []string{"simulate"}, false},
		{"noun too far from verb", "run the formatter over every file in the repository and then explain the cycle", groundedOn("mlsys-research"), nil, false},
		{"aux-led yes/no question", "Do the experiment results look right?", groundedOn("mlsys-research"), nil, false},
		{"is it ok to rerun", "is it ok to rerun the cycle?", groundedOn("mbb-ai"), nil, false},
		{"loop name, no verb", "what did simulate produce", groundedOn("mlsys-research"), []string{"simulate"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var lf func(string) []string
			if tc.loops != nil {
				lf = loopsFixed(tc.loops...)
			}
			if got := groundedRunIntent(userMsg(tc.msg), tc.ctx, lf); got != tc.want {
				t.Fatalf("groundedRunIntent(%q, ctx=%v, loops=%v) = %v, want %v", tc.msg, tc.ctx, tc.loops, got, tc.want)
			}
		})
	}
}

// The full router: the exact regression routes off claude-code for an admin;
// the coding-lane negatives stay put.
func TestGroundedRunRoutesOffTheCodeLane(t *testing.T) {
	code := codeLaneProvider(t)
	loops := loopsFixed("simulate")
	grounded := groundedOn("mlsys-research")

	student := userMsg("Run the baseline design for 9.2 and explain each number to me")
	if controlIntent(student) {
		t.Fatal("precondition: the student prompt must NOT match controlIntent, else this test proves nothing")
	}
	for _, m := range []string{
		"Run the baseline design for 9.2 and explain each number to me",
		"kick off simulate",
	} {
		got, routed := autoRouteForTurnLoops(userMsg(m), code, "admin", grounded, "", loops)
		if !routed || isClaudeCodeProvider(got) {
			t.Errorf("%q grounded on mlsys-research stayed on %q (routed=%v)", m, got.id, routed)
		}
	}
	// Ungrounded: unchanged behaviour, stays on the code lane.
	if got, routed := autoRouteForTurnLoops(student, code, "admin", nil, "", loops); routed {
		t.Errorf("ungrounded student prompt was routed to %q", got.id)
	}
	for _, m := range []string{
		"run the tests", "run npm install", "how do I run this?", "how would I run the baseline?",
	} {
		if got, routed := autoRouteForTurnLoops(userMsg(m), code, "admin", grounded, "", loops); routed {
			t.Errorf("%q grounded was stolen from the code lane to %q", m, got.id)
		}
	}
	// Documented, NOT changed here: controlIntent's pre-existing literal "run
	// the experiment" already matches inside a question, so this one routes
	// through that arm regardless of the grounded-question rule.
	if !controlIntent(userMsg("how would I run the experiment?")) {
		t.Log("note: controlIntent no longer matches the question form of 'run the experiment'")
	}
	// The sandbox-only-tool guard still wins over the grounded arm.
	msg := userMsg("run the baseline design via mcp__lumid__run_workflow")
	if _, routed := autoRouteForTurnLoops(msg, code, "admin", grounded, "", loops); routed {
		t.Error("naming an mcp__ tool must keep the turn on the code lane")
	}
}

// A non-code-lane provider never pays for the loop lookup.
func TestGroundedRunSkipsLookupOffTheCodeLane(t *testing.T) {
	var calls int32
	lf := func(string) []string { atomic.AddInt32(&calls, 1); return []string{"simulate"} }
	var other llmProvider
	for _, p := range llmProviders {
		if !isClaudeCodeProvider(p) {
			other = p
			break
		}
	}
	autoRouteForTurnLoops(userMsg("kick off simulate"), other, "admin", groundedOn("mlsys-research"), "", lf)
	if calls != 0 {
		t.Fatalf("loop resolver called %d times for a tool-capable provider", calls)
	}
	// And a turn the generic arm already matches does not need it either.
	code := codeLaneProvider(t)
	autoRouteForTurnLoops(userMsg("run the baseline design"), code, "admin", groundedOn("mlsys-research"), "", lf)
	if calls != 0 {
		t.Fatalf("loop resolver called %d times for a generic-noun match", calls)
	}
}

func TestCachedAppLoopNames(t *testing.T) {
	var calls int32
	prev := appLoopNamesLoader
	appLoopNamesLoader = func(u, a string) []string { atomic.AddInt32(&calls, 1); return []string{"simulate"} }
	t.Cleanup(func() { appLoopNamesLoader = prev })
	appLoopNamesMu.Lock()
	appLoopNamesCache = map[string]appLoopNamesEntry{}
	appLoopNamesMu.Unlock()

	for i := 0; i < 5; i++ {
		if got := cachedAppLoopNames("u1", "mlsys-research"); len(got) != 1 || got[0] != "simulate" {
			t.Fatalf("got %v", got)
		}
	}
	if calls != 1 {
		t.Fatalf("loader called %d times, want 1 (cached)", calls)
	}
	cachedAppLoopNames("u2", "mlsys-research")
	if calls != 2 {
		t.Fatalf("cache must be per user; loader calls = %d", calls)
	}
	if cachedAppLoopNames("", "x") != nil || calls != 2 {
		t.Fatal("empty user must not load")
	}
}
