package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Role-scoped case visibility.
//
// One dataset file, three seats. The interviewee is being TESTED, so it gets the
// client brief and nothing else. The interviewer RUNS the case for a human, so it
// needs its own script, the questions, and the facts it releases on request — but
// never the answer key, because an interviewer that holds the key leaks it through
// its reactions long before it would ever quote it. Only the judge, scoring a
// finished transcript, sees the key.
//
// These assertions exist because the previous leak shipped with nothing pinning
// them: the projection was widened and no test noticed.

// writeCaseFile lays down a case file shaped like the real dataset
// (mbb-casebook-cases/data/Case_001_PremierOil_PK21_v5.json): every structure_N
// present, the interviewer script carrying all four questions, and the answer key
// in structure_4.
func writeCaseFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
	  "case_id": "Case_001_PremierOil_PK21",
	  "version": "v5",
	  "industry": "Energy / Oil & Gas",
	  "difficulty": "Easy",
	  "case_type": "interviewer_driven",
	  "topic": "Profitability improvement",
	  "opening_prompt": "Pls be a good interviewee. Q1. What factors would you consider? Q4. Calculate the savings.",
	  "structure_1_client_basic_context": {"company": "Premier Oil", "situation": "price collapse", "ask": "restore profitability"},
	  "structure_2_information_upon_request": {"item_1": {"info": "assets only in the North Sea"}},
	  "structure_3_case_questions": {"Q1": {"question_text": "What factors would you consider?"}, "Q4": {"question_text": "Calculate the annual savings."}},
	  "structure_4_ground_truth": {"Q4_ground_truth": {"correct_final_answer": "26000000", "keypoints": ["reduce lifting cost per barrel"]}},
	  "scoring_summary": {"Q1": {"total_keypoints": 12}}
	}`
	if err := os.WriteFile(filepath.Join(seed, "Case_001_PremierOil_PK21_v5.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The strings that identify each layer of the file, so a test can say exactly
// which layer it expects to see and which it expects to be absent.
const (
	seeBriefCompany   = "Premier Oil"
	seeBriefSituation = "price collapse"
	seeScript         = "good interviewee"          // opening_prompt
	seeQuestionLate   = "Calculate the annual"      // structure_3, a LATER question
	seeOnRequest      = "only in the North Sea"     // structure_2, must be asked for
	seeAnswerKey      = "26000000"                  // structure_4, the correct figure
	seeAnswerKeypoint = "reduce lifting cost"       // structure_4, a scoring keypoint
	seeKeyName        = "structure_4_ground_truth"  // the key's own field name
	seeUnlisted       = "Profitability improvement" // `topic`: allowlisted for nobody
)

func mustCase(t *testing.T, dir, role string) string {
	t.Helper()
	got, ok := caseContextForRole(dir, "Case_001_PremierOil_PK21", role)
	if !ok {
		t.Fatalf("role %q: expected the case to resolve", role)
	}
	return got
}

func mustContain(t *testing.T, role, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("role %q: missing %q — it needs this to do its job", role, w)
		}
	}
}

func mustNotContain(t *testing.T, role, got string, leaks ...string) {
	t.Helper()
	for _, l := range leaks {
		if strings.Contains(got, l) {
			t.Errorf("role %q: LEAKED %q", role, l)
		}
	}
}

// The interviewee sees the client brief and stops there.
func TestCaseContextForRoleIntervieweeSeesOnlyTheBrief(t *testing.T) {
	dir := writeCaseFile(t)
	got := mustCase(t, dir, caseRoleInterviewee)

	mustContain(t, caseRoleInterviewee, got, seeBriefCompany, seeBriefSituation, "Energy / Oil & Gas")
	mustNotContain(t, caseRoleInterviewee, got,
		seeScript, seeQuestionLate, seeOnRequest,
		seeAnswerKey, seeAnswerKeypoint, "ground_truth", seeUnlisted,
	)
}

// caseContext() is the interviewee view, byte for byte. Existing callers cannot
// drift into a wider projection just because a wider one now exists.
func TestCaseContextWrapperMatchesIntervieweeRole(t *testing.T) {
	dir := writeCaseFile(t)
	legacy, okLegacy := caseContext(dir, "Case_001_PremierOil_PK21")
	scoped, okScoped := caseContextForRole(dir, "Case_001_PremierOil_PK21", caseRoleInterviewee)
	if okLegacy != okScoped || legacy != scoped {
		t.Fatalf("caseContext drifted from role %q:\n legacy(%v) %q\n scoped(%v) %q",
			caseRoleInterviewee, okLegacy, legacy, okScoped, scoped)
	}
}

// The interviewer gets the questions and the on-request facts — no answer key,
// and NOT the opening script.
//
// The script was in this set until a live coach-mode turn pasted it verbatim and
// revealed Q2, Q3 and Q4 in the opening message. It contains every question, and
// a model that holds the whole list does not honour "ask them one at a time".
// Removing it is what makes caseContextAtQuestion's narrowing meaningful — the
// model cannot reveal what it was never given.
func TestCaseContextForRoleInterviewerSeesQuestionsButNotTheScriptOrTheKey(t *testing.T) {
	dir := writeCaseFile(t)
	got := mustCase(t, dir, caseRoleInterviewer)

	mustContain(t, caseRoleInterviewer, got,
		seeBriefCompany, seeQuestionLate, "What factors would you consider", seeOnRequest,
	)
	mustNotContain(t, caseRoleInterviewer, got, seeScript)
	mustNotContain(t, caseRoleInterviewer, got,
		seeAnswerKey, seeAnswerKeypoint, "ground_truth", seeKeyName, seeUnlisted,
	)
}

// The judge scores, so it holds the key — on top of everything the interviewer saw.
func TestCaseContextForRoleJudgeSeesTheAnswerKey(t *testing.T) {
	dir := writeCaseFile(t)
	got := mustCase(t, dir, caseRoleJudge)

	mustContain(t, caseRoleJudge, got,
		seeAnswerKey, seeAnswerKeypoint, seeKeyName,
		seeBriefCompany, seeQuestionLate, seeOnRequest,
	)
	// The judge scores a finished transcript; it has no use for the interviewer's
	// script either, and every field withheld is one that cannot leak.
	mustNotContain(t, caseRoleJudge, got, seeScript)
	mustNotContain(t, caseRoleJudge, got, seeUnlisted)
}

// Fail closed. A typo, a zero-value field, a stray query parameter — anything that
// is not one of the three spellings collapses to the NARROWEST view. The failure
// mode of a role string is silence, never disclosure.
func TestCaseContextForRoleUnknownAndEmptyFailClosed(t *testing.T) {
	dir := writeCaseFile(t)
	want := mustCase(t, dir, caseRoleInterviewee)

	for _, role := range []string{"", "Interviewer", "INTERVIEWER", "judge ", "admin", "grader", "  "} {
		got, ok := caseContextForRole(dir, "Case_001_PremierOil_PK21", role)
		if !ok {
			t.Errorf("role %q: expected the interviewee fallback to resolve", role)
			continue
		}
		if got != want {
			t.Errorf("role %q: did NOT fall back to the interviewee projection:\n got %q", role, got)
		}
		mustNotContain(t, role, got, seeScript, seeQuestionLate, seeOnRequest, seeAnswerKey, "ground_truth")
	}
}

// No client brief → nothing, for EVERY role. Without this, a file we could not
// otherwise parse would still hand the judge its answer key: the widening roles
// are additive, so they must be anchored on a projection that actually resolved.
func TestCaseContextForRoleRefusesUnknownShapeForEveryRole(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	// Deliberately carries fields the interviewer and judge WOULD be allowed —
	// only the interviewee anchor is missing.
	body := `{
	  "notes": "x",
	  "opening_prompt": "Pls be a good interviewee.",
	  "structure_3_case_questions": {"Q1": {"question_text": "What factors?"}},
	  "structure_4_ground_truth": {"Q4_ground_truth": {"correct_final_answer": "26000000"}}
	}`
	if err := os.WriteFile(filepath.Join(seed, "Case_X.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{caseRoleInterviewee, caseRoleInterviewer, caseRoleJudge, "", "bogus"} {
		if got, ok := caseContextForRole(dir, "Case_X", role); ok || got != "" {
			t.Errorf("role %q: expected refusal, got ok=%v %q", role, ok, got)
		}
	}
}

// 2 of the 50 shipped cases name "structure_4_ground_truth" inside a structure_3
// prose _note. That tripped the substring guard and made the interviewer refuse
// those cases outright — the guard working correctly on text that was never the
// key, which cost two real cases.
//
// The fix strips "_"-prefixed annotation keys before the guard runs: they are
// authoring commentary, not case content. So the case now SERVES, and the key is
// still absent — which is the property that actually matters. The guard itself
// is untouched; if the key ever appears in real content, it still refuses.
func TestCaseContextForRoleInterviewerStripsNoteKeysRatherThanRefusing(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
	  "case_id": "Case_007",
	  "structure_1_client_basic_context": {"company": "Fast Casual Food"},
	  "structure_3_case_questions": {"_note": "ground truth is isolated in structure_4_ground_truth", "Q1": {"question_text": "What factors?"}}
	}`
	if err := os.WriteFile(filepath.Join(seed, "Case_007.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := caseContextForRole(dir, "Case_007", caseRoleInterviewer)
	if !ok {
		t.Fatal("interviewer: expected the case to resolve once the _note is stripped")
	}
	if strings.Contains(got, "ground_truth") || strings.Contains(got, "ground truth") {
		t.Errorf("interviewer: the _note survived the projection: %q", got)
	}
	if !strings.Contains(got, "What factors?") {
		t.Errorf("interviewer: expected the real question to survive, got %q", got)
	}
	// The same file is fine for the roles that never project structure_3...
	if _, ok := caseContextForRole(dir, "Case_007", caseRoleInterviewee); !ok {
		t.Error("interviewee: expected the client brief to still resolve")
	}
	// ...and for the judge, which is exempt from the substring check by design.
	if _, ok := caseContextForRole(dir, "Case_007", caseRoleJudge); !ok {
		t.Error("judge: expected the case to resolve")
	}
}
