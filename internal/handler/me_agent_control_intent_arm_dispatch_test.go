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
	// Must NOT steal ordinary shell/code turns from claude-code.
	no := []string{
		"run the tests",
		"install numpy",
		"what does this arm of the if-statement do?",
		"run black on the repo",
	}
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("wrongly stolen from claude-code: %q", m)
		}
	}
}
