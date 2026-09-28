package handler

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// autoJudgeCandidate scores the candidate's answer BEFORE the model turn, in
// the mode where the AI interviews the user.
//
// The gap it closes: the Work tab's "AI interviews you" promises every answer
// is scored against the case's ground truth, and the only thing that ever
// scored one was the model choosing to call app_judge. Observed 2026-09-28 on
// the reader account: the interviewer acknowledged a full Q1 answer, moved on
// to Q2, and called nothing but case_open — TURNS SCORED stayed 0 and the
// interview loop's run read "Not scored". Same lesson as autoStageCorrection:
// a promise the page makes is kept server-side, and the reply stays the
// model's. tool_choice is no substitute — the lumid-llm gateway drops it.
//
// What is scored: the user's latest message, against the question the
// interviewer last put (the previous assistant turn — judgeKeypointsFor
// matches it to the case's question by word overlap). What is NOT: commands
// (scorecard, next question, a "wrong — …" correction), a fact request, and
// anything too short to be an answer. A missed score is recoverable (the model
// can still call app_judge); a request for facts scored as a 0/13 answer is
// not, because it lands in the user's scorecard.
func autoJudgeCandidate(c context.Context, userID, role string, body meAgentChatBody) (map[string]any, bool) {
	if body.Context == nil || chatMode(body.Context) != modeCoach {
		return nil, false
	}
	app, _ := body.Context["app"].(string)
	caseID, _ := body.Context["case_id"].(string)
	if app == "" || caseID == "" {
		return nil, false
	}
	answer, question := candidateTurn(body.Messages)
	if !looksLikeAnswer(answer) || strings.TrimSpace(question) == "" {
		return nil, false
	}
	res, ok := toolAppJudge(c, userID, role, app, caseID, clip(question, 4000), answer, modeCoach, "human")
	if !ok || res == nil {
		return res, false
	}
	return res, true
}

// candidateTurn returns the latest user message and the assistant message
// before it — the answer and the question it answers. Empty question when the
// user spoke first (nothing has been asked yet).
func candidateTurn(msgs []chatMessage) (answer, question string) {
	i := len(msgs) - 1
	for ; i >= 0; i-- {
		if msgs[i].Role == "user" {
			answer = strings.TrimSpace(msgs[i].Content)
			break
		}
	}
	for j := i - 1; j >= 0; j-- {
		if msgs[j].Role == "assistant" {
			return answer, msgs[j].Content
		}
	}
	return answer, ""
}

// Commands the Work tab advertises, and the correction opener. Anchored: these
// are how a turn OPENS.
var candidateCommandRe = regexp.MustCompile(`(?i)^\s*(scorecard|next( question)?|skip|hint|repeat|wrong|incorrect|that'?s not right|that is not right|interview me)\b`)

// A request for facts: a short message that asks rather than asserts.
var factRequestRe = regexp.MustCompile(`(?i)^\s*(can|could|may|what|what's|how|do|does|did|is|are|was|were|which|who|when|where|why|any|please)\b`)

// looksLikeAnswer is deliberately conservative — see autoJudgeCandidate.
func looksLikeAnswer(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 60 || candidateCommandRe.MatchString(s) {
		return false
	}
	// "What is their current market share?" is a request, not an answer.
	// Both halves need the question mark: "What matters most is TCO…" opens
	// with a question word and is an answer.
	if len(s) < 300 && (strings.HasSuffix(s, "?") || (factRequestRe.MatchString(s) && strings.Contains(s, "?"))) {
		return false
	}
	return true
}

// autoJudgeNote tells the model the answer is already scored, so it reports
// the real numbers instead of inventing a score or calling the judge twice.
func autoJudgeNote(res map[string]any) string {
	if res == nil {
		return ""
	}
	if e, _ := res["error"].(string); e != "" {
		return ""
	}
	parts := []string{}
	if cov, ok := res["covered"]; ok {
		parts = append(parts, fmt.Sprintf("keypoints covered %v of %v", cov, res["total"]))
	}
	if n, ok := res["panel_n"]; ok {
		parts = append(parts, fmt.Sprintf("judges %v", n))
	}
	if ax, ok := res["axes"]; ok && ax != nil {
		parts = append(parts, fmt.Sprintf("axes %v", ax))
	}
	return "\n\nALREADY DONE THIS TURN: the candidate's answer above was scored by the judge panel against the case's ground truth (" +
		strings.Join(parts, "; ") + "). Do NOT call app_judge again for this answer and do NOT estimate a score yourself. " +
		"Open your reply by reporting this score in one or two lines — keypoints covered, the per-axis scores, and the number of judges — " +
		"then continue the interview as usual. Do not reveal the missed keypoints' wording to the candidate."
}
