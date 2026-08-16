package handler

// The three case modes are FIXED workflows chosen by a click, but they reached
// the model as an ordinary sentence — so the first turn was spent working out
// which of 102 tools to call and which role it was playing. Measured 32s and
// 53s of thinking on first turns. Declaring the mode collapses that decision
// and, more importantly, makes the ROLE unambiguous: the app's default posture
// is the analyst, so interviewer mode was the one most likely to be got wrong.

import (
	"strings"
	"testing"
)

func TestRenderViewingContext_ModeInterview(t *testing.T) {
	out := renderViewingContext(map[string]any{
		"app": "mbb-consultant", "mode": "interview", "case_id": "Case_001_PremierOil_PK21",
	})
	if !strings.Contains(out, "MODE: interviewer") {
		t.Fatalf("no interviewer directive:\n%s", out)
	}
	if !strings.Contains(out, "case_open(app=mbb-consultant, case_id=Case_001_PremierOil_PK21, role=interviewer)") {
		t.Fatalf("first action not named:\n%s", out)
	}
	if !strings.Contains(out, "do not answer the questions yourself") {
		t.Fatal("role inversion not stated — this is the one it gets wrong")
	}
}

func TestRenderViewingContext_ModeBenchmarkIsTheOppositeRole(t *testing.T) {
	out := renderViewingContext(map[string]any{
		"app": "mbb-consultant", "mode": "benchmark", "case_id": "Case_019_BetaOptics_PK21",
	})
	if !strings.Contains(out, "MODE: interviewee") {
		t.Fatalf("no interviewee directive:\n%s", out)
	}
	if strings.Contains(out, "role=interviewer") {
		t.Fatal("benchmark mode must not open the case as the interviewer")
	}
}

func TestRenderViewingContext_ModePracticeCarriesTheCaveat(t *testing.T) {
	out := renderViewingContext(map[string]any{"app": "mbb-consultant", "mode": "practice"})
	if !strings.Contains(out, "ungrounded") || !strings.Contains(out, "caveat") {
		t.Fatalf("open-question caveat not required:\n%s", out)
	}
	if strings.Contains(out, "case_open(") {
		t.Fatal("practice mode has no case to open")
	}
}

func TestRenderViewingContext_UnknownModeFailsClosed(t *testing.T) {
	// A typo or a stale client must degrade to the previous behaviour — reading
	// the sentence — not to a wrong role.
	for _, m := range []string{"", "Interview", "interviewer", "nonsense"} {
		out := renderViewingContext(map[string]any{"app": "mbb-consultant", "mode": m})
		if strings.Contains(out, "MODE:") {
			t.Fatalf("mode %q produced a directive:\n%s", m, out)
		}
	}
}

func TestRenderViewingContext_NoCaseIdStillDeclaresTheRole(t *testing.T) {
	// The role matters even when we cannot name the case.
	out := renderViewingContext(map[string]any{"app": "mbb-consultant", "mode": "interview"})
	if !strings.Contains(out, "MODE: interviewer") {
		t.Fatal("role must be declared without a case id")
	}
	if strings.Contains(out, "case_open(") {
		t.Fatal("must not emit a case_open call with no case id")
	}
}
