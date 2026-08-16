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

// The advertised syntax is "wrong — …". It must fire on that and stay quiet on
// everything else: a false stage puts words in the user's mouth in a queue they
// are being asked to trust.
func TestCorrectionOpenerMatches(t *testing.T) {
	for _, yes := range []string{
		"wrong — you never sized the addressable market",
		"Wrong, that skips the cost side",
		"that's not right — margin is per barrel",
		"Thats not right",
		"incorrect — the client is independent",
	} {
		if !correctionOpenerRe.MatchString(yes) {
			t.Fatalf("should stage: %q", yes)
		}
	}
	for _, no := range []string{
		"no — I'd start with the cost side",        // a candidate's answer in interviewer mode
		"I think the margin number is wrong",       // mid-sentence, describing not judging
		"what would be wrong with that approach?",  // a question
		"the case says the wrong price was quoted", // narration
		"next question",
		"",
	} {
		if correctionOpenerRe.MatchString(no) {
			t.Fatalf("should NOT stage: %q", no)
		}
	}
}

// Without a draft_id there is nothing to tell the model, and an empty note must
// not append stray instructions to every system prompt.
func TestStagedNoteEmptyWithoutDraft(t *testing.T) {
	if stagedCorrectionNote(map[string]any{}) != "" {
		t.Fatal("no draft id should produce no note")
	}
	if !strings.Contains(stagedCorrectionNote(map[string]any{"draft_id": "fb-9"}), "fb-9") {
		t.Fatal("note should name the draft")
	}
}

// The id gate runs before the store lookup, so anything it rejects is
// unreachable — a DB draft id failing here returned 400 for a row the queue was
// displaying at that moment.
func TestDraftIDGateAcceptsBothStores(t *testing.T) {
	m := draftIDMatcher{}
	for _, ok := range []string{
		"0123456789abcdef",            // filesystem: 16 hex
		"fb-c8c46a69d585e9fe36c25f97", // DB: correction
		"sk-c8c46a69d585e9fe36c25f97", // DB: skill card edit
	} {
		if !m.MatchString(ok) {
			t.Fatalf("should be accepted: %q", ok)
		}
	}
	for _, bad := range []string{
		"", "0123456789abcde", "0123456789abcdefg", "0123456789ABCDEF",
		"fb-", "fb-xyz", "fb-../../etc/passwd", "xx-c8c46a69d585e9fe",
		"fb-c8c46a6", // too short after the prefix
		"fb-" + "a123456789012345678901234567890123456789extra",
	} {
		if m.MatchString(bad) {
			t.Fatalf("should be rejected: %q", bad)
		}
	}
}

// The vocabulary map fires only on the words a user actually uses to name a
// failure, and fails closed. A wrong card sends the reviewer to edit a prompt
// that had nothing to do with the mistake.
func TestCardFromCorrection(t *testing.T) {
	cases := map[string]string{
		"wrong — you never sized the addressable market before splitting costs": "market_sizing",
		"that's not right, the issue tree is not MECE":                          "issue_tree",
		"wrong — you skipped NPV entirely":                                      "npv",
		"incorrect — no downside case at all":                                   "risk_mece",
		"wrong — you didn't state a hypothesis first":                           "hypothesis_first",
		// no vocabulary match → the model may still name one
		"wrong — that whole answer is off":                "",
		"wrong — the client is independent, not PE-owned": "",
		// two cards named at once is one correction about two things
		"wrong — no market sizing and the issue tree is not MECE": "",
	}
	for note, want := range cases {
		if got := cardFromCorrection(note); got != want {
			t.Errorf("%q → %q, want %q", note, got, want)
		}
	}
}

// Anything the vocabulary produces must survive the allowlist that guards the
// file path — the two lists cannot be allowed to drift apart.
func TestVocabularyCardsAreAllAllowlisted(t *testing.T) {
	for _, v := range cardVocabulary {
		if !knownSkillCards[v.card] {
			t.Fatalf("%q is in the vocabulary but not the allowlist — it would stage a draft that can never apply", v.card)
		}
	}
}
