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

import (
	"strings"
	"testing"
)

func routes(s string) bool {
	for _, re := range controlIntentPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	low := strings.ToLower(s)
	for _, kw := range controlIntentPhrases {
		if kw != "" && strings.Contains(low, kw) {
			return true
		}
	}
	return false
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
	} {
		if !routes(q) {
			t.Errorf("regression — previously routed: %q", q)
		}
	}
}
