package handler

import (
	"strings"
	"testing"
)

// A mode selects an EXPERIENCE; it must never select a privilege. The client
// picks the mode, so anything it can name has to map to a role we chose.
func TestRoleForMode(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{modeCoach, caseRoleInterviewer},
		{modeTrainAI, caseRoleInterviewee},
		{modeFree, caseRoleInterviewee},
		{"", caseRoleInterviewee},
		{"judge", caseRoleInterviewee},       // naming the role does not grant it
		{"interviewer", caseRoleInterviewee}, // nor does naming that one
		{"COACH", caseRoleInterviewee},       // no case-folding: normalising widens
		{"coach ", caseRoleInterviewee},
		{"admin", caseRoleInterviewee},
	} {
		if got := roleForMode(tc.mode); got != tc.want {
			t.Errorf("roleForMode(%q) = %q, want %q", tc.mode, got, tc.want)
		}
	}
	// The judge role must be unreachable from ANY mode: the answer key is only
	// ever assembled server-side for scoring, never for a conversational turn.
	for _, m := range []string{modeCoach, modeTrainAI, modeFree, "judge", "", "x"} {
		if roleForMode(m) == caseRoleJudge {
			t.Errorf("mode %q reached the judge role", m)
		}
	}
}

func TestChatMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  map[string]any
		want string
	}{
		{"nil context", nil, modeTrainAI},
		{"absent", map[string]any{"app": "x"}, modeTrainAI},
		{"coach", map[string]any{"mode": modeCoach}, modeCoach},
		{"free", map[string]any{"mode": modeFree}, modeFree},
		{"unknown collapses to default", map[string]any{"mode": "wat"}, modeTrainAI},
		{"non-string collapses", map[string]any{"mode": 3}, modeTrainAI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chatMode(tc.ctx); got != tc.want {
				t.Errorf("chatMode(%v) = %q, want %q", tc.ctx, got, tc.want)
			}
		})
	}
}

// The interviewer must hold ONE question. Handing over the set is what let a
// live coach turn reveal Q2, Q3 and Q4 in its opening message.
func TestCaseContextAtQuestionNarrowsToOne(t *testing.T) {
	dir := writeCaseFile(t)
	for _, tc := range []struct {
		name         string
		idx          int
		want, absent string
	}{
		{"first question", 0, "Q1", "Q4"},
		{"later question", 3, "Q4", "Q1"},
		{"negative clamps to first", -5, "Q1", "Q4"},
		{"past the end clamps to last", 99, "Q4", "Q1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := caseContextAtQuestion(dir, "Case_001_PremierOil_PK21", tc.idx)
			if !ok {
				t.Fatal("expected the case to resolve")
			}
			if !strings.Contains(got, `"`+tc.want+`"`) {
				t.Errorf("expected %s to be present: %s", tc.want, got)
			}
			if strings.Contains(got, `"`+tc.absent+`"`) {
				t.Errorf("%s leaked while on %s: %s", tc.absent, tc.want, got)
			}
			if strings.Contains(got, "ground_truth") {
				t.Errorf("answer key leaked: %s", got)
			}
		})
	}
}

// answeredQuestions must never RUN AHEAD of the transcript: over-counting
// advances a candidate past a question they have not answered.
func TestAnsweredQuestionsUnderCounts(t *testing.T) {
	mk := func(roles ...string) []chatMessage {
		out := make([]chatMessage, 0, len(roles))
		for _, r := range roles {
			out = append(out, chatMessage{Role: r})
		}
		return out
	}
	for _, tc := range []struct {
		name string
		msgs []chatMessage
		want int
	}{
		{"opening user turn only", mk("user"), -1},
		{"after the opening answer", mk("user", "assistant"), 0},
		{"one question answered", mk("user", "assistant", "user", "assistant"), 1},
		{"clarifying exchange lags rather than skips",
			mk("user", "assistant", "user", "assistant", "user", "assistant"), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := answeredQuestions(tc.msgs); got != tc.want {
				t.Errorf("answeredQuestions = %d, want %d", got, tc.want)
			}
		})
	}
}
