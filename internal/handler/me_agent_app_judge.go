package handler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
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

	// Count the keypoints OURSELVES. Asking the model for `total` made the
	// benchmark move: six runs on one question returned totals of 1, 3 and 13
	// for a rubric whose size is fixed. The total is a property of the rubric,
	// not a judgement — the model is asked only WHICH are covered.
	keypoints, scope := judgeKeypointsFor(gt, question)
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
		// Pinned to a stronger scorer than the chat default. resolveProvider
		// still re-checks the caller's role, so an over-tier pin degrades to the
		// role default rather than escalating.
		text, err = answerWithAppVoiceModel(c, role, judgeModelID, sys, u)
		if err != nil {
			return map[string]any{"error": "judge call failed: " + err.Error()}, false
		}
		parsed = parseJudgeJSON(text)
		if parsed != nil {
			if _, _, ok := judgeTotals(parsed); !ok {
				parsed = nil // parsed, but not into usable counts — retry once
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
	covered, total, okCounts := judgeTotals(parsed)
	// Our count wins when we have one: it is derived from the rubric, so it is
	// the same on every run, which is what makes two scores comparable at all.
	if len(keypoints) > 0 {
		total = len(keypoints)
		out["total_scope"] = scope
		okCounts = okCov(parsed)
		if covered > total {
			covered = total
		}
	}
	if !okCounts {
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

// judgeTotals extracts covered AND total, deriving total when the model omits
// it but listed what was missed.
//
// The first retry checked only `covered`, so a reply with a good covered and a
// missing total never retried and always failed — the fix made scoring fail
// consistently where it had merely been flaky. Both are checked now, and
// covered + len(missed) is a sound total when the model enumerated the misses.
func judgeTotals(parsed map[string]any) (int, int, bool) {
	covered, okCov := judgeCount(parsed["covered"])
	if !okCov {
		return 0, 0, false
	}
	if total, okTot := judgeCount(parsed["total"]); okTot && total > 0 && total >= covered {
		return covered, total, true
	}
	if missed, okMiss := judgeCount(parsed["missed"]); okMiss && covered+missed > 0 {
		return covered, covered + missed, true
	}
	return 0, 0, false
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

// judgeModelID — the scorer. Kept separate from the chat model on purpose: the
// user picks a model for CONVERSATION, and letting that choice decide how
// answers are scored makes a benchmark that moves with a dropdown.
const judgeModelID = "lumid-qwen3-35b"

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

// okCov reports whether the model gave a usable covered count, independent of
// whatever it said about the total.
func okCov(parsed map[string]any) bool {
	_, ok := judgeCount(parsed["covered"])
	return ok
}

// judgeKeypoints pulls the rubric's keypoint list out of the ground truth.
//
// Shapes vary by question type — pillars each holding keypoints[], or a flat
// keypoints[] — so this walks the structure rather than assuming one. Returns
// empty when it cannot find them, and the caller falls back to the model's own
// count rather than pretending to a precision it does not have.
func judgeKeypoints(gt string) []string {
	var doc map[string]any
	if json.Unmarshal([]byte(gt), &doc) != nil {
		return nil
	}
	key, _ := doc["structure_4_ground_truth"].(map[string]any)
	if key == nil {
		return nil
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if kps, ok := x["keypoints"].([]any); ok {
				for _, k := range kps {
					if s, ok := k.(string); ok && strings.TrimSpace(s) != "" {
						out = append(out, s)
					}
				}
			}
			// Sorted: map iteration order is random in Go, so an unsorted walk
			// returned the same keypoints in a different order every call. The
			// count was right and the list was not reproducible — which matters
			// the moment anything quotes "the first missed keypoint".
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k])
			}
		case []any:
			for _, nested := range x {
				walk(nested)
			}
		}
	}
	walk(key)
	return out
}

// judgeKeypointBlock renders the keypoints as an explicit numbered list.
//
// NOT currently injected into the prompt. Adding it took the judge from 4/4
// parsable to 0/4: the numbered list tipped the model into answering in prose
// about each keypoint instead of emitting JSON. Kept because the total it
// implies is still used — judgeKeypoints supplies the denominator — and because
// the next attempt at a filled {gt_text} template should start here rather than
// rediscover the shape.
func judgeKeypointBlock(kps []string) string {
	if len(kps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\nScore against EXACTLY these " + strconv.Itoa(len(kps)) +
		" keypoints, each worth one point:\n")
	for i, k := range kps {
		b.WriteString(strconv.Itoa(i+1) + ". " + k + "\n")
	}
	b.WriteString("`total` is " + strconv.Itoa(len(kps)) + ". Do not invent keypoints.\n")
	return b.String()
}

// judgeKeypointsFor narrows the rubric to the QUESTION being scored.
//
// The ground truth is keyed per question (Q1_ground_truth, Q2_ground_truth, …),
// each declaring its own total_keypoints — 13, 19, 8 for one real case. Scoring
// an answer to Q1 against all 40 makes a good answer look terrible, and makes
// two answers to different questions incomparable, which is the opposite of what
// a denominator is for.
//
// The question is matched by word overlap against structure_3's question_text.
// A weak match falls back to the whole case AND says so in total_scope, because
// a number whose denominator is a guess should be labelled as one.
func judgeKeypointsFor(gt, question string) ([]string, string) {
	var doc map[string]any
	if json.Unmarshal([]byte(gt), &doc) != nil {
		return judgeKeypoints(gt), "case"
	}
	qid := matchQuestionID(doc, question)
	if qid == "" {
		return judgeKeypoints(gt), "case"
	}
	key, _ := doc["structure_4_ground_truth"].(map[string]any)
	if key == nil {
		return judgeKeypoints(gt), "case"
	}
	sub, _ := key[qid+"_ground_truth"].(map[string]any)
	if sub == nil {
		return judgeKeypoints(gt), "case"
	}
	wrapped, err := json.Marshal(map[string]any{"structure_4_ground_truth": sub})
	if err != nil {
		return judgeKeypoints(gt), "case"
	}
	kps := judgeKeypoints(string(wrapped))
	if len(kps) == 0 {
		return judgeKeypoints(gt), "case"
	}
	return kps, qid
}

// matchQuestionID picks the question whose text best overlaps `question`.
// Returns "" when nothing matches convincingly — a wrong denominator is worse
// than an honest whole-case one.
func matchQuestionID(doc map[string]any, question string) string {
	qs, _ := doc["structure_3_case_questions"].(map[string]any)
	if qs == nil || strings.TrimSpace(question) == "" {
		return ""
	}
	want := wordSet(question)
	if len(want) == 0 {
		return ""
	}
	best, bestScore := "", 0.0
	for id, raw := range qs {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		text, _ := m["question_text"].(string)
		if text == "" {
			continue
		}
		have := wordSet(text)
		hits := 0
		for w := range have {
			if want[w] {
				hits++
			}
		}
		if len(have) == 0 {
			continue
		}
		s := float64(hits) / float64(len(have))
		if s > bestScore {
			best, bestScore = id, s
		}
	}
	if bestScore < 0.4 { // weak overlap — do not guess a denominator
		return ""
	}
	return best
}

func wordSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(w) > 3 { // skip the/what/would/… which every question shares
			out[w] = true
		}
	}
	return out
}
