package handler

// `dispatch.ask` means the run needs a SUBJECT the dispatcher cannot know.
//
// The panel has honoured it since per-arm dispatch shipped: it hands the
// dispatch to the chat rail with the app's question instead of firing. The
// chat tool never read it — so the one path with nowhere left to defer to was
// the one that fired blind.
//
// Measured 2026-09-21: dispatching quant-research/backtest_evidence arm
// `current` from the chatbox produced a recorded run whose metrics read
// `"error": "strategy is empty — pass raw .lqts source or a JSON payload"`,
// `"status": "empty_strategy"`. A failed row is worse than a refusal, because
// it looks like evidence the arm was tried.

import (
	"os"
	"path/filepath"
	"testing"
)

func writeAskFixture(t *testing.T, dispatch string) string {
	t.Helper()
	dir := t.TempDir()
	spec := "experiments:\n" +
		"- id: e1\n" +
		"  metric: {name: real_tape}\n" +
		dispatch +
		"  arms:\n" +
		"  - id: current\n"
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDispatchAskIsReadFromTheDeclaration(t *testing.T) {
	dir := writeAskFixture(t,
		"  dispatch: {loop: backtest, ask: \"Which strategy id should it run?\"}\n")
	got := experimentDispatchAsk(dir, "e1")
	if got != "Which strategy id should it run?" {
		t.Fatalf("ask not read from the declaration: %q", got)
	}
}

func TestNoAskMeansNoSubjectRequirement(t *testing.T) {
	// The common case: an arm that is self-sufficient. It must stay
	// dispatchable with no extra ceremony, or the guard turns every one-click
	// arm into a conversation.
	dir := writeAskFixture(t, "  dispatch: {loop: kol_strategy}\n")
	if got := experimentDispatchAsk(dir, "e1"); got != "" {
		t.Fatalf("an experiment with no ask reported one: %q", got)
	}
	dir2 := writeAskFixture(t, "")
	if got := experimentDispatchAsk(dir2, "e1"); got != "" {
		t.Fatalf("an experiment with no dispatch block reported an ask: %q", got)
	}
}

func TestUnknownExperimentHasNoAsk(t *testing.T) {
	dir := writeAskFixture(t, "  dispatch: {loop: backtest, ask: \"which strategy?\"}\n")
	if got := experimentDispatchAsk(dir, "not-an-experiment"); got != "" {
		t.Fatalf("an unknown experiment reported an ask: %q", got)
	}
}
