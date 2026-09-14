package handler

import "testing"

// The three tools that had no front door.
//
// experiment_case, casebook and loop_metric_series are registered, implemented
// and — until now — reachable only by accident: experiment_case rode the broad
// "experiments? … score[sd]?" pattern, and the other two had no pattern and no
// phrase at all. A turn that misses every pattern stays on claude-code, whose
// CLI toolset cannot see this registry, so the model answers that it has no
// such tool rather than calling it.
//
// A drill-in is the question that FOLLOWS a verdict — "which cases dragged it
// down", "show me the metric over time" — so these are exactly the turns that
// arrive once an experiment starts producing numbers.
func TestControlIntentRecognisesExperimentDrillIn(t *testing.T) {
	yes := []string{
		// experiment_case
		"how did Case_019 score in that experiment",
		"show me the scores for case_001",
		"what's the result for Case_003",
		"give me the per case breakdown",
		"which cases are dragging the mean down",
		"case by case, how did it do",
		// casebook
		"what cases is this scored on",
		"show the casebook for mbb-consultant",
		"list the cases in the casebook",
		"the casebook please",
		// loop_metric_series
		"show me the metric over time",
		"what's the trend on that score",
		"give me the metric series for case_eval",
		"plot the score over time",
		// literal tool names
		"use experiment_case for Case_019",
		"call loop_metric_series on case_eval",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("not routed to a tool-capable provider: %q", m)
		}
	}
}

// The patterns are verb-or-noun bounded on purpose. General curiosity about the
// CONCEPT is a conversation, not a control action, and must still reach the
// general assistant — otherwise every mention of the word "case" gets dragged
// into the registry.
func TestControlIntentLeavesGeneralQuestionsAlone(t *testing.T) {
	no := []string{
		"what is a casebook in consulting",
		"in that case, what should I do next",
		"just in case, back it up first",
		"explain how metrics work",
		"why does the score matter",
	}
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("general question was captured by the control router: %q", m)
		}
	}
}
