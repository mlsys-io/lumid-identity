package handler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
		`{"covered": <integer count>, "total": <integer count>, "axes": {"framework": <0-1>, "qualitative": <0-1>, "quantitative": <0-1>}, "missed": ["<short label>", ...]}` +
		"\n`covered` and `total` MUST be integers — counts of keypoints, not lists. " +
		"Use only axes the question actually exercises; omit the others. " +
		"`missed` holds SHORT LABELS of uncovered keypoints — never their content."

	// One retry, with the format restated bluntly. Measured: the same model
	// returned clean counts on one call and unparsable prose on the next, so a
	// single attempt made scoring randomly unavailable. Bounded at two — a judge
	// that cannot produce a number twice should refuse, not be argued with.
	var parsed map[string]any
	var text string
	var err error
	for attempt := 0; attempt < 2 && parsed == nil; attempt++ {
		u := user
		if attempt > 0 {
			u = user + "\n\nYour previous reply could not be parsed. Output the JSON " +
				"object ONLY — no prose, no code fence, no explanation. `covered` and " +
				"`total` must be plain integers."
		}
		text, err = answerWithAppVoice(c, role, sys, u)
		if err != nil {
			return map[string]any{"error": "judge call failed: " + err.Error()}, false
		}
		parsed = parseJudgeJSON(text)
		if parsed != nil {
			if _, ok := judgeCount(parsed["covered"]); !ok {
				parsed = nil // parsed, but not into a count — retry once
			}
		}
	}

	out := map[string]any{"app": app, "case_id": caseID, "grounded": true, "mode": "casebook"}
	if parsed == nil {
		// Refuse rather than pass the raw model text through: unparsed judge
		// output reaching the user is exactly how the answer key escapes.
		return map[string]any{
			"app": app, "case_id": caseID, "grounded": true, "mode": "casebook",
			"error": "judge returned no parsable score",
		}, false
	}
	// Coerce before use. Told to return an integer count, the model returned
	// `covered` as a LIST of the keypoints it matched — accepted by the parser
	// (the key was present) and then unusable, so the turn reported a score of
	// nothing. Count a list, take a number, refuse anything else.
	covered, okCov := judgeCount(parsed["covered"])
	total, okTot := judgeCount(parsed["total"])
	if !okCov || !okTot || total <= 0 {
		return map[string]any{
			"app": app, "case_id": caseID, "grounded": true, "mode": "casebook",
			"error": "judge returned no usable covered/total count",
		}, false
	}
	out["covered"] = covered
	out["total"] = total
	out["score"] = float64(covered) / float64(total)
	if v, present := parsed["axes"]; present {
		out["axes"] = v
	}
	// The candidate must not be handed the answer key by another name.
	if mode != modeCoach {
		if v, present := parsed["missed"]; present {
			out["missed"] = v
		}
	}
	return out, true
}

// judgeCount accepts the two shapes a model actually produces for a count: the
// integer it was asked for, and the LIST of items it counted. Anything else is
// refused rather than guessed — a coverage figure derived from a shape we did
// not understand is exactly the invented number this tool exists to replace.
func judgeCount(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		if x < 0 {
			return 0, false
		}
		return int(x), true
	case []any:
		return len(x), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil || n < 0 {
			return 0, false
		}
		return n, true
	}
	return 0, false
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
