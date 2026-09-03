package handler

import "testing"

// A turn asking to run a declared ARM must be recognised as platform control,
// or it stays on claude-code — whose CLI toolset cannot see the me_agent
// registry — and the model answers "I don't have a tool called
// dispatch_experiment_arm". Measured on the live service before this: the
// operator's own default provider (super_admin -> claude-code-sonnet) could
// not reach the dispatch tool at all, while every other role could.
func TestControlIntentRecognisesArmDispatch(t *testing.T) {
	yes := []string{
		"run the arm panel_median3 on mbb-consultant",
		"please run this arm and tell me the result",
		"dispatch the arm for backtest_evidence",
		"run the experiment judge_panel_parity",
		"compare the arms for me",
		"run both arms of the panel experiment",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("not routed to a tool-capable provider: %q", m)
		}
	}
	// The phrasings e2e actually produced, which the literal list missed:
	// naming the arm inline is the natural way to ask.
	phrasings := []string{
		"run the panel_single arm of the judge_panel_parity experiment on mbb-consultant",
		"dispatch the panel_median3 arm with args case=Case_002 and q=Q1",
		"list the experiments on this app and their arms",
		"show me the experiments for mbb-consultant",
		"use dispatch_experiment_arm to run panel_single",
	}
	for _, m := range phrasings {
		if !controlIntent(userMsg(m)) {
			t.Errorf("natural phrasing not routed: %q", m)
		}
	}

	// Must NOT steal ordinary shell/code turns from claude-code.
	no := []string{
		"run the tests",
		"install numpy",
		"what does this arm of the if-statement do?",
		"run black on the repo",
		// Bounded gaps matter: a code question that happens to contain both
		// words far apart must not qualify.
		"run the tests, then read the arm64 build config and tell me what it does",
	}
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("wrongly stolen from claude-code: %q", m)
		}
	}
}
