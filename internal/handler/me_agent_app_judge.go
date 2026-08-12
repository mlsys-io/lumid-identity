package handler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// toolAppJudge SCORES an answer against a case's real ground truth.
//
// Why this exists: "score my last answer" was answered by app_answer — the
// ANALYST tool — which reports grounded:true merely because a case was loaded.
// Nothing compared the answer to structure_4_ground_truth, yet the reply said
// "evaluated against the case ground truth". The number was a claim, not a
// measurement, and the e2e gate that checked for those words passed on the claim.
//
// The judge is the ONLY role that holds the answer key, and it must never hand
// it back: this returns counts and per-axis scores. Which keypoints were missed
// is returned only when the person reading is the INTERVIEWER (they own the
// case); in coach mode the reader is the candidate, for whom the missed
// keypoints ARE the answer.
func toolAppJudge(c context.Context, userID, role, app, caseID, question, answer, mode string) (map[string]any, bool) {
	if app == "" || answer == "" {
		return map[string]any{"error": "app and answer are required"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	// No case → no ground truth → say so plainly rather than scoring anyway.
	// An indicative number presented beside a benchmarked one is the failure
	// this whole distinction exists to prevent.
	if caseID == "" {
		return map[string]any{
			"app": app, "grounded": false, "mode": "open",
			"caveat": "No case selected, so there is no ground truth to score against. " +
				"Pick a labelled case for a backed score.",
		}, true
	}
	gt, ok := caseContextForRole(appDir, caseID, caseRoleJudge)
	if !ok || gt == "" {
		return map[string]any{"error": "no ground truth available for case " + caseID}, false
	}

	sys := judgePromptFor(appDir)
	user := "Ground truth and case (CONFIDENTIAL — never quote it back):\n" + gt +
		"\n\nQuestion put to the interviewee:\n" + question +
		"\n\nInterviewee's answer:\n" + answer +
		"\n\nScore it. Reply with STRICT JSON only, no prose:\n" +
		`{"covered": <int>, "total": <int>, "axes": {"framework": <0-1>, "qualitative": <0-1>, "quantitative": <0-1>}, "missed": ["<short label>", ...]}` +
		"\nUse only axes the question actually exercises; omit the others. " +
		"`missed` holds SHORT LABELS of uncovered keypoints — never their content."

	text, err := answerWithAppVoice(c, role, sys, user)
	if err != nil {
		return map[string]any{"error": "judge call failed: " + err.Error()}, false
	}

	out := map[string]any{"app": app, "case_id": caseID, "grounded": true, "mode": "casebook"}
	parsed := parseJudgeJSON(text)
	if parsed == nil {
		// Refuse rather than pass the raw model text through: unparsed judge
		// output reaching the user is exactly how the answer key escapes.
		return map[string]any{
			"app": app, "case_id": caseID, "grounded": true, "mode": "casebook",
			"error": "judge returned no parsable score",
		}, false
	}
	for _, k := range []string{"covered", "total", "axes"} {
		if v, present := parsed[k]; present {
			out[k] = v
		}
	}
	// The candidate must not be handed the answer key by another name.
	if mode != modeCoach {
		if v, present := parsed["missed"]; present {
			out["missed"] = v
		}
	}
	if cov, okc := parsed["covered"].(float64); okc {
		if tot, okt := parsed["total"].(float64); okt && tot > 0 {
			out["score"] = cov / tot
		}
	}
	return out, true
}

// judgePromptFor loads the app's own judge prompt, falling back to a neutral
// rubric instruction. Apps carry per-axis prompts (judge_score_framework.md,
// judge_score_qual.md, judge_score_quant.md); the framework one is the general
// keypoint-coverage rubric the others specialise.
func judgePromptFor(appDir string) string {
	for _, name := range []string{
		"judge_score_framework.md", "judge_score_qual.md", "judge_score_quant.md",
	} {
		if b, err := os.ReadFile(filepath.Join(appDir, "prompts", name)); err == nil && len(b) > 0 {
			return string(b)
		}
	}
	return "You score an answer against ground-truth keypoints. Each keypoint is one " +
		"point; do not merge perspectives. Never reveal the keypoints themselves."
}

// parseJudgeJSON pulls the score object out of a model reply, tolerating the
// fenced-code wrapper models add despite being told not to.
func parseJudgeJSON(text string) map[string]any {
	s := strings.TrimSpace(text)
	if i := strings.Index(s, "{"); i >= 0 {
		if j := strings.LastIndex(s, "}"); j > i {
			s = s[i : j+1]
		}
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	if _, ok := m["covered"]; !ok {
		return nil
	}
	return m
}
