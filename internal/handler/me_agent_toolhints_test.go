package handler

import (
	"strings"
	"testing"
)

// TestToolHintSuffixGating — the intent→tool routing block is appended ONLY
// for providers flagged needsToolHints (gemma4); claude-code and any other
// provider see an unchanged (empty-suffix) system prompt. Guards the fix for
// the credentialed-sweep regressions: 'autoresearch' firing neither
// list_loops/loop_status, 'run X loop' firing no run tool, and 'show my
// experiments' firing list_apps instead of list_experiments.
func TestToolHintSuffixGating(t *testing.T) {
	var gemma, claudeCode *llmProvider
	for i := range llmProviders {
		switch llmProviders[i].id {
		case "kvrun-gemma4":
			gemma = &llmProviders[i]
		case "claude-code-sonnet":
			claudeCode = &llmProviders[i]
		}
	}
	if gemma == nil {
		t.Fatal("kvrun-gemma4 not in llmProviders")
	}
	if !gemma.needsToolHints {
		t.Fatal("kvrun-gemma4 must be flagged needsToolHints")
	}

	suffix := toolHintSuffix(*gemma)
	if suffix == "" {
		t.Fatal("toolHintSuffix empty for a needsToolHints provider")
	}
	// The three sweep failures must each be covered by an explicit tool name.
	for _, tool := range []string{
		"run_loop_now", "branch_run", // run/execute a loop
		"list_experiments", "experiment_status", // experiments
		"list_loops", "loop_status", // autoresearch loops
		"search_marketplace", // marketplace discovery
	} {
		if !strings.Contains(suffix, tool) {
			t.Errorf("hint block missing tool %q", tool)
		}
	}

	if claudeCode == nil {
		t.Fatal("claude-code-sonnet not in llmProviders")
	}
	if claudeCode.needsToolHints {
		t.Error("claude-code-sonnet must NOT be flagged needsToolHints (behavior must not change)")
	}
	if got := toolHintSuffix(*claudeCode); got != "" {
		t.Errorf("toolHintSuffix(claude-code) = %q, want empty", got)
	}
}
