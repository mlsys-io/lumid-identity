package handler

import (
	"strings"
	"testing"
)

// The whole point of the context params: a reviewer must be able to see what a
// correction is about. A body that is only the user's sentence is a verdict with
// no evidence, and dismissing it is the only honest action.
func TestFeedbackBodyCarriesContext(t *testing.T) {
	got := feedbackBody("you never sized the addressable market", feedbackContext{
		CaseID:   "Case_019_BetaOptics_PK21",
		Question: "How should the client think about entering?",
		Answer:   "I'd split profitability into revenue and cost…",
	})
	for _, want := range []string{
		"you never sized the addressable market",
		"Case_019_BetaOptics_PK21",
		"How should the client think about entering?",
		"I'd split profitability into revenue and cost",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("body missing %q:\n%s", want, got)
		}
	}
}

// A bare correction with no context must not grow an empty "---" section that
// promises evidence and delivers none.
func TestFeedbackBodyBareStaysBare(t *testing.T) {
	got := feedbackBody("wrong", feedbackContext{})
	if got != "wrong" {
		t.Fatalf("bare note should pass through unchanged, got %q", got)
	}
}

// A model-supplied card name is a guess. A guess that misses stages an edit to a
// prompt file that does not exist — discoverable only by approving it.
func TestOnlyKnownSkillCardsStage(t *testing.T) {
	if knownSkillCards["market_sizing"] != true {
		t.Fatal("market_sizing is a real card and must stage")
	}
	for _, bad := range []string{"", "communication", "../analyst_system", "sizing", "MARKET_SIZING"} {
		if knownSkillCards[bad] {
			t.Fatalf("%q must not stage a skill draft", bad)
		}
	}
}

// The answer is the bulk of a turn; the draft needs enough to judge, not all of it.
func TestFeedbackBodyClipsLongAnswer(t *testing.T) {
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	got := feedbackBody("wrong", feedbackContext{Answer: string(long)})
	if len(got) > 1500 {
		t.Fatalf("answer not clipped: body is %d bytes", len(got))
	}
	if !strings.Contains(got, "…") {
		t.Fatal("clipped answer should be marked as clipped")
	}
}

// The card name in an approved draft chooses a file path on the far side of an
// intent boundary. Parse it from the marker line, and re-check the allowlist.
func TestSkillFromDraftBody(t *testing.T) {
	good := skillCardNote("mbb-consultant", "market_sizing", "size it first")
	if got := skillFromDraftBody(good); got != "market_sizing" {
		t.Fatalf("round-trip failed: got %q", got)
	}
	for _, bad := range []string{
		"",
		"just a plain correction with no marker",
		"Proposed edit to prompts/analyst_skill_communication.md",   // off the allowlist
		"Proposed edit to prompts/analyst_skill_not_a_real_card.md", // not a card
		"Proposed edit to prompts/analyst_skill_../analyst_system.md",
	} {
		if got := skillFromDraftBody(bad); got != "" {
			t.Fatalf("%q should yield no card, got %q", bad, got)
		}
	}
}

// A memory draft must not be mistaken for a card edit just because the user's
// words happen to mention a skill.
func TestPlainCorrectionIsNotACardEdit(t *testing.T) {
	body := feedbackBody("your market_sizing was wrong", feedbackContext{CaseID: "Case_019"})
	if got := skillFromDraftBody(body); got != "" {
		t.Fatalf("plain correction parsed as card %q", got)
	}
}
