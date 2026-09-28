package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLooksLikeAnswer(t *testing.T) {
	answers := []string{
		"I'd structure it in four parts: market attractiveness, customer needs, competition, and our own capabilities and economics.",
		"What matters most is total cost of ownership: fuel and maintenance savings against the purchase premium, then range and uptime for the routes these fleets run.",
	}
	for _, a := range answers {
		if !looksLikeAnswer(a) {
			t.Errorf("answer not scored: %q", a)
		}
	}
	notAnswers := []string{
		"What is the current market share of e-trucks in the US?",
		"Can you tell me how many trucks they sell a year and at what margin?",
		"scorecard",
		"next question please, I think I covered that one well enough already",
		"wrong — the issue tree should split cost before volume and you skipped it entirely",
		"ok",
		"Interview me on case Case_001_DieselTruck_PK20_v5. You're the interviewer and I'm the candidate.",
	}
	for _, a := range notAnswers {
		if looksLikeAnswer(a) {
			t.Errorf("non-answer would be scored: %q", a)
		}
	}
}

func TestCandidateTurnPairsAnswerWithLastQuestion(t *testing.T) {
	msgs := []chatMessage{
		{Role: "user", Content: "Interview me on case X"},
		{Role: "assistant", Content: "Q1: How would you evaluate if they should produce and sell e-trucks?"},
		{Role: "user", Content: "Market, customers, competition, capabilities."},
	}
	a, q := candidateTurn(msgs)
	if a != "Market, customers, competition, capabilities." || !strings.Contains(q, "Q1") {
		t.Fatalf("answer=%q question=%q", a, q)
	}
	if _, q := candidateTurn(msgs[:1]); q != "" {
		t.Fatalf("first message has no question, got %q", q)
	}
}

func TestAutoJudgeOnlyInCoachModeWithACase(t *testing.T) {
	long := strings.Repeat("A structured answer about market, customers and economics. ", 3)
	msgs := []chatMessage{{Role: "assistant", Content: "Q1?"}, {Role: "user", Content: long}}
	for _, ctx := range []map[string]any{
		nil,
		{"app": "mbb-consultant", "mode": "train_ai", "case_id": "C1"}, // the AI answers: nothing of the user's to score
		{"app": "mbb-consultant", "mode": "coach"},                     // no case → no ground truth
		{"mode": "coach", "case_id": "C1"},                             // no app
	} {
		if _, ok := autoJudgeCandidate(nil, "u", "user", meAgentChatBody{Context: ctx, Messages: msgs}); ok {
			t.Errorf("scored with context %v", ctx)
		}
	}
}

func TestChatModeAcceptsCaseBrowserNames(t *testing.T) {
	for in, want := range map[string]string{
		"interview": modeCoach, "benchmark": modeTrainAI, "practice": modeFree,
		"coach": modeCoach, "": modeTrainAI, "bogus": modeTrainAI,
	} {
		if got := chatMode(map[string]any{"mode": in}); got != want {
			t.Errorf("chatMode(%q) = %q, want %q", in, got, want)
		}
	}
	if roleForMode(chatMode(map[string]any{"mode": "interview"})) != caseRoleInterviewer {
		t.Error("the Work tab's interview mode must get the interviewer seat")
	}
}

func TestCoachModeGetsTheInterviewerDirective(t *testing.T) {
	out := renderViewingContext(map[string]any{"page": "app", "app": "mbb-consultant", "mode": "coach", "case_id": "Case_001_X"})
	if !strings.Contains(out, "MODE: interviewer") || !strings.Contains(out, "role=interviewer") {
		t.Fatalf("coach mode rendered no interviewer directive:\n%s", out)
	}
	if strings.Contains(renderViewingContext(map[string]any{"page": "app", "app": "mbb-consultant", "mode": "train_ai"}), "MODE:") {
		t.Fatal("the default mode must not inject a case directive into every app chat")
	}
}

func TestChatCycleRecordsTheLoopMetric(t *testing.T) {
	m := chatCycleMetrics([]toolCallResult{{Name: "app_judge", OK: true,
		Result: map[string]any{"score": 0.5, "case_id": "C1", "subject": "human", "panel_n": 2}}})
	if m["avg_question_score"] != 0.5 || m["score"] != 0.5 {
		t.Fatalf("metrics = %v", m)
	}
}

func TestAutoJudgeNoteReportsRealNumbers(t *testing.T) {
	n := autoJudgeNote(map[string]any{"covered": 4, "total": 13, "panel_n": 2})
	if !strings.Contains(n, "4 of 13") || !strings.Contains(n, "judges 2") || !strings.Contains(n, "Do NOT call app_judge") {
		t.Fatalf("note = %q", n)
	}
	if autoJudgeNote(map[string]any{"error": "x"}) != "" {
		t.Fatal("an errored judge must not claim a score")
	}
}

// A model-issued app_judge after the server already judged the answer returns
// that verdict instead of running the panel again (observed: it re-judged).
func TestAppJudgeReusesTheTurnsAutoJudge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/", nil)
	c.Set(ctxAutoJudgeKey, map[string]any{"covered": 5, "total": 13, "score": 5.0 / 13, "subject": "human"})
	res, ok := dispatchTool(c, "u", "user", "app_judge", map[string]any{"app": "mbb-consultant", "answer": "x"})
	if !ok || res["already_scored"] != true || res["covered"] != 5 || res["subject"] != "human" {
		t.Fatalf("res=%v ok=%v", res, ok)
	}
}
