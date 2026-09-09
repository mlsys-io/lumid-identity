package handler

import "testing"

// Forward tests and mbb-consultant's verbs must route to the platform toolset.
//
// Backtest was given dedicated patterns after the 2026-08-31 walkthrough dead
// end; forward test never was, so the two halves of one workflow behaved
// differently — "backtest this strategy on TSLA" reached the registry and
// "forward test this strategy on TSLA" did not, dead-ending on claude-code with
// "this session doesn't have a tool bound that can invoke that app's commands".
// mbb-consultant had no cue of any kind: the app whose entire premise is
// conversational was the one this router could not hear.
func TestControlIntentRecognisesForwardTest(t *testing.T) {
	yes := []string{
		"forward test my strategy",
		"run a forward test on momentum_30m_demo",
		"start the forward test for strategy 9f10",
		"check the forward test for this strategy",
		"forward-test this strategy on TSLA",
		"forward test the strategy against symbol AAPL",
		"kick off a forward test",
		"run forward_test",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("forward test not routed to a tool-capable provider: %q", m)
		}
	}
}

func TestControlIntentRecognisesConsultantVerbs(t *testing.T) {
	yes := []string{
		"interview me",
		"interview me on case 19",
		"start the interview",
		"run the interview on Case_002",
		"continue the interview",
		"run the case eval",
		"run case_eval on the casebook",
		"score my answer",
		"grade my answer against the rubric",
		"score that answer please",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("consultant verb not routed to a tool-capable provider: %q", m)
		}
	}
}

// The whole discipline of this router is that a bare noun does NOT route: a
// super_admin asking about code must still reach claude-code. These are the
// turns the new patterns would be wrong to steal.
func TestControlIntentLeavesCodeTurnsAlone(t *testing.T) {
	no := []string{
		"explain the forward test code",
		"where is the forward test implemented?",
		"what does the interview command do?",
		"prep me for an interview",
		"open the judge.py file",
		"read the case eval docs", // "case eval" alone is a platform noun...
	}
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("ordinary code/shell turn wrongly routed away from claude-code: %q", m)
		}
	}
}
