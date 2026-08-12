package handler

import (
	"strings"
	"testing"
)

// The judge's reply is model text; anything unparsed must be refused rather
// than passed through, since that text was generated with the answer key in
// context.
func TestParseJudgeJSON(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     bool
	}{
		{"plain object", `{"covered":5,"total":12}`, true},
		{"fenced", "```json\n{\"covered\":5,\"total\":12}\n```", true},
		{"prose around it", `Here you go: {"covered":5,"total":12} — hope that helps`, true},
		{"no score field", `{"axes":{"framework":0.4}}`, false},
		{"not json", `The answer covered five keypoints.`, false},
		{"empty", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseJudgeJSON(tc.in)
			if (got != nil) != tc.want {
				t.Errorf("parseJudgeJSON(%q) parsed=%v, want %v", tc.in, got != nil, tc.want)
			}
		})
	}
}

// judgePromptFor must never return empty — an empty system prompt would let the
// model decide for itself what scoring means.
func TestJudgePromptForAlwaysReturnsARubric(t *testing.T) {
	got := judgePromptFor(t.TempDir()) // no prompts/ dir at all
	if strings.TrimSpace(got) == "" {
		t.Fatal("expected a fallback rubric")
	}
	if !strings.Contains(strings.ToLower(got), "keypoint") {
		t.Errorf("fallback should still describe keypoint scoring, got %q", got)
	}
}
