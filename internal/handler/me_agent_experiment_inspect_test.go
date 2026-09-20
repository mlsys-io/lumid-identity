package handler

// "Inspect the result" is the middle of the loop this control plane serves:
// define -> run -> INSPECT -> discuss -> dispatch the next arm. define, list and
// dispatch all had router patterns; inspecting did not.
//
// Measured 2026-09-13 against the live stack: "how did the analyst_local_gpu
// experiment turn out? give me the numbers" came back auto_routed:false. It fell
// through to claude-code, which cannot see the experiment registry, and which
// then said — correctly, and uselessly — that it had no numbers and would not
// guess. The verdict was sitting in the API the whole time.

import "testing"

// routes DELEGATES to controlIntent rather than re-implementing it. It used to
// walk controlIntentPatterns and controlIntentPhrases itself, which meant any
// routing rule that did not live in exactly those two slices was invisible to
// every test using this helper -- and it also matched patterns against the RAW
// string while production lowercases first. Measured 2026-09-18: a new gated
// read-back set routed correctly through controlIntent while this helper
// reported it did not, which reads as a broken feature and is a broken test.
func routes(s string) bool {
	return controlIntent([]chatMessage{{Role: "user", Content: s}})
}

func TestAskingHowAnExperimentWentIsRouted(t *testing.T) {
	for _, q := range []string{
		"how did the analyst_local_gpu experiment turn out?",
		"how did the analyst_local_gpu experiment turn out? give me the numbers",
		"what was the outcome of the judge_panel_parity experiment",
		"did the experiment finish",
		"is the gemma4 arm doing any better",
		"show me the verdict for that experiment",
		"experiment_status for mbb-consultant",
		"which arm won the experiment",
	} {
		if !routes(q) {
			t.Errorf("not routed, would fall through to claude-code: %q", q)
		}
	}
}

// The router is a front door, not a catch-all: over-matching sends ordinary
// conversation to the control plane and makes the assistant useless for
// everything else.
func TestOrdinaryTalkIsNotRouted(t *testing.T) {
	// NOTE: "what is an experiment, conceptually?" DOES route, via the
	// pre-existing `(list|show|what) ... experiments` pattern. That over-match
	// predates this change and narrowing it risks breaking "what experiments are
	// there", so it is recorded here rather than silently altered.
	for _, q := range []string{
		"explain how A/B testing works",
		"how did your day go",
		"write me a haiku about turning out the lights",
	} {
		if routes(q) {
			t.Errorf("over-matched ordinary conversation: %q", q)
		}
	}
}

// The cases that already worked must keep working.
func TestExistingExperimentIntentsStillRoute(t *testing.T) {
	for _, q := range []string{
		"list the experiments on mbb-consultant",
		"run the median-panel arm",
		"make case_eval an experiment measuring avg_question_score over cases_v1",
		"add an arm with deepseek as judge",
		// Editing is the SAME verb — an existing id replaces. This phrasing fell
		// through minutes after adding was made reachable, so correcting a
		// model on an arm was impossible from chat.
		"replace the qwen14b_local arm so it uses the AWQ build",
		"change the arm to use a quantized model",
	} {
		if !routes(q) {
			t.Errorf("regression — previously routed: %q", q)
		}
	}
}
