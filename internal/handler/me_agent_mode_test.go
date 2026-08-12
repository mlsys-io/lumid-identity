package handler

import "testing"

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
