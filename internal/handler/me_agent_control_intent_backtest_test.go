package handler

import "testing"

// A super_admin's default provider is claude-code, whose CLI toolset cannot see
// the me_agent registry. controlIntent is what re-routes a platform-control turn
// to a tool-capable provider. A 2026-08-31 walkthrough asked it to backtest a
// strategy; nothing matched, the turn stayed on claude-code, and the model
// correctly reported it had no tool that could invoke the app's commands.
func TestControlIntentRoutesBacktestAndNamedWorkflows(t *testing.T) {
	routes := []string{
		"Backtest this strategy on symbol KXBTCD-26SEP0317-T77999.99 using the quant-research app",
		"backtest my strategy on KXBTC15M-26SEP022315-15",
		"run a backtest for the ofi_z strategy",
		"submit a backtest with this .lqts source",
		"can you back-test this strategy against the recorded tape?",
		"run quant-research's backtest workflow",
		"trigger the harvest_outbox loop",
		"fire the send_universe_refresh_fast workflow now",
	}
	for _, m := range routes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("should route to a tool-capable provider: %q", m)
		}
	}

	// The bar stays "platform work", not "the word backtest appeared". These
	// are code/shell asks a super_admin deliberately uses claude-code for; a
	// bare-substring rule would have stolen every one of them.
	stays := []string{
		"explain how the backtest worker code decides the signals label",
		"where is the backtest replay window configured?",
		"read services/lqt-backtest-worker/src/replay.rs and summarise it",
		"run the tests",
		"what does a backtest measure?",
	}
	for _, m := range stays {
		if controlIntent(userMsg(m)) {
			t.Errorf("should stay on claude-code (not platform control): %q", m)
		}
	}
}
