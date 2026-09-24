package handler

// The one invariant worth a test here: an analyst that has seen the answer key
// is not being tested, and every score for that session becomes meaningless.
// The dataset states this itself ("STRICTLY CONFIDENTIAL … must NEVER be shared
// with or leaked to Analyst LLM"). It fails silently — a leaked key produces
// better answers, not an error — so it needs pinning.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaseContextNeverLeaksGroundTruth(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"case_id":"019","structure_1_client_basic_context":{"client":"BetaOptics"},` +
		`"structure_3_case_questions":{"Q1":{"question_text":"why"}},` +
		`"structure_4_ground_truth":{"Q1_ground_truth":{"keypoints":["SECRET-KEYPOINT"]}}}`
	if err := os.WriteFile(filepath.Join(seed, "Case_019_Beta_v1.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, ok := caseContext(dir, "Case_019")
	if !ok {
		t.Fatal("case not found")
	}
	if strings.Contains(got, "SECRET-KEYPOINT") || strings.Contains(got, "structure_4_ground_truth") {
		t.Fatalf("ground truth leaked to the analyst path:\n%s", got)
	}
	if !strings.Contains(got, "BetaOptics") {
		t.Fatal("client context missing — the analyst needs the case setup")
	}
}

func TestCaseContextRejectsTraversal(t *testing.T) {
	for _, id := range []string{"../etc", "a/b", ""} {
		if _, ok := caseContext(t.TempDir(), id); ok {
			t.Fatalf("accepted unsafe case id %q", id)
		}
	}
}

// Open mode must carry the caveat, casebook mode must not — that distinction is
// the difference between an indicative number and a benchmark result.
func TestSkillCardsAlwaysIncludeCommunication(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"communication", "issue_tree", "npv"} {
		_ = os.WriteFile(filepath.Join(dir, "analyst_skill_"+n+".md"), []byte("card "+n), 0o644)
	}
	got := strings.Join(skillCardsFor(dir, "what is the NPV of this investment?"), "\n")
	if !strings.Contains(got, "card npv") {
		t.Fatal("NPV question did not select the npv card")
	}
	if !strings.Contains(got, "card communication") {
		t.Fatal("communication card must always apply — it enforces top-line-first")
	}
}

// tool_choice narrows what the model may pick; it must never grant a tool the
// caller does not already have. That would be a privilege escalation dressed up
// as a convenience.
func TestToolAvailableGuardsForcedChoice(t *testing.T) {
	tools := []map[string]any{
		{"name": "app_answer"},
		{"name": "casebook"},
	}
	if !toolAvailable(tools, "app_answer") {
		t.Fatal("a tool the caller HAS must be forceable")
	}
	for _, bad := range []string{"admin_set_user_role", "", "App_Answer"} {
		if toolAvailable(tools, bad) {
			t.Fatalf("forced a tool the caller does not have: %q", bad)
		}
	}
}

// The regression this guards (shipped v0.5.17, reverted 20 min later):
// "Ask the app" is a sticky toggle, ON by default, so it sends
// tool_choice=app_answer on EVERY docked turn. Executing that server-side
// hijacked every message into a one-shot answer with no case context and no
// conversation history, breaking multi-turn continuity and reload persistence.
//
// Only a tool sent by an explicit, per-turn user action (the "Correct this"
// button) may be executed without a model turn. If app_answer ever reappears
// here, that regression comes back.
func TestForcedToolPathExcludesAppAnswer(t *testing.T) {
	src, err := os.ReadFile("me_agent_app_answer.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	i := strings.Index(body, "func runForcedAppTool")
	if i < 0 {
		t.Fatal("runForcedAppTool not found")
	}
	fn := body[i:]
	if strings.Contains(fn, `case "app_answer":`) {
		t.Fatal("app_answer is back on the forced path — this hijacks every docked turn (see v0.5.17)")
	}
	if !strings.Contains(fn, `case "app_feedback":`) {
		t.Fatal("app_feedback should be forceable — it is only ever sent by an explicit button")
	}
}

// Bug: the Data Warehouse / Compute Fleet / Apps-list docked chats have no
// app in context, but "Ask the app" is a sticky toggle ON by default, so it
// forced tool_choice=app_answer on every turn. runForcedAppTool used to check
// body.Context["app"] BEFORE dispatching on `tool`, so it returned the
// "no app in context" error for app_answer too — even though app_answer is
// deliberately excluded from the switch below and is supposed to fall
// through untouched to a normal model turn. Every general data-mesh question
// asked from those surfaces rendered a dead `app_answer` error tool card
// instead of an answer.
func TestForcedAppAnswerWithNoAppFallsThroughToModel(t *testing.T) {
	body := meAgentChatBody{
		Messages: []chatMessage{{Role: "user", Content: "what is the difference between FinData, LumidData, and LQT Data?"}},
		Context:  map[string]any{"page": "data"}, // no "app" key — Data Warehouse surface
	}
	res, handled := runForcedAppTool(nil, "u1", "member", "app_answer", body)
	if handled {
		t.Fatalf("app_answer must fall through to a normal model turn when unhandled, got handled=true res=%v", res)
	}
	if res != nil {
		t.Fatalf("expected nil result on fallthrough, got %v", res)
	}
}

// Same surfaces also have no REAL app for app_feedback to ground on — that
// path legitimately needs one and should still degrade to the explicit
// error card (a correction with nothing to correct against), not silently
// drop the user's note.
func TestForcedAppFeedbackWithNoAppStillErrors(t *testing.T) {
	body := meAgentChatBody{
		Messages: []chatMessage{{Role: "user", Content: "Record a correction against this app: it's wrong"}},
		Context:  map[string]any{"page": "data"},
	}
	res, handled := runForcedAppTool(nil, "u1", "member", "app_feedback", body)
	if !handled {
		t.Fatal("app_feedback with no app should still be handled (with an error), not silently fall through")
	}
	if errMsg, _ := res["error"].(string); errMsg == "" {
		t.Fatalf("expected an error result for app_feedback with no app, got %v", res)
	}
}
