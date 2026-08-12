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

// A model told to return an integer returned the LIST it counted. Accept both,
// refuse anything else — a coverage figure from a shape we did not understand is
// the invented number this tool replaces.
func TestJudgeCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   any
		want int
		ok   bool
	}{
		{"integer", float64(5), 5, true},
		{"zero", float64(0), 0, true},
		{"list is counted", []any{"a", "b", "c"}, 3, true},
		{"empty list", []any{}, 0, true},
		{"numeric string", "7", 7, true},
		{"negative refused", float64(-1), 0, false},
		{"prose refused", "about five", 0, false},
		{"object refused", map[string]any{"n": 5}, 0, false},
		{"nil refused", nil, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := judgeCount(tc.in)
			if got != tc.want || ok != tc.ok {
				t.Errorf("judgeCount(%v) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// The first retry checked only `covered`, so a reply with a good covered and a
// missing total never retried and always failed — turning a flaky judge into a
// consistently broken one.
func TestJudgeTotals(t *testing.T) {
	for _, tc := range []struct {
		name             string
		in               map[string]any
		wantCov, wantTot int
		ok               bool
	}{
		{"both present", map[string]any{"covered": 5.0, "total": 12.0}, 5, 12, true},
		{"total derived from missed list",
			map[string]any{"covered": 2.0, "missed": []any{"a", "b", "c"}}, 2, 5, true},
		{"covered as a list, total present",
			map[string]any{"covered": []any{"x", "y"}, "total": 10.0}, 2, 10, true},
		{"total smaller than covered is rejected, falls back to missed",
			map[string]any{"covered": 9.0, "total": 3.0, "missed": []any{"a"}}, 9, 10, true},
		{"no total and no missed", map[string]any{"covered": 4.0}, 0, 0, false},
		{"no covered at all", map[string]any{"total": 12.0}, 0, 0, false},
		{"zero total and empty missed", map[string]any{"covered": 0.0, "missed": []any{}}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, tot, ok := judgeTotals(tc.in)
			if ok != tc.ok || (ok && (c != tc.wantCov || tot != tc.wantTot)) {
				t.Errorf("judgeTotals(%v) = (%d, %d, %v), want (%d, %d, %v)",
					tc.in, c, tot, ok, tc.wantCov, tc.wantTot, tc.ok)
			}
		})
	}
}
