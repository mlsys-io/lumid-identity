package handler

// app_answer — let an installed app answer in its own voice.
//
// The gap this closes: an app declares tools[] in its spec, but nothing in the
// chat surface can invoke them. app_run returns a PROCEDURE rather than running
// one, and the app's commands/*.py only execute under the scheduler. So a
// free-form question was answered by deep_research with the app never
// participating — its analyst prompt, its skill cards and its
// grounded/ungrounded distinction all sat unused, and an "open mode" score that
// the app defines could never actually be produced.
//
// This reads the app's OWN prompts and asks the model with them, so the voice
// and the rubric come from the app rather than from the generic assistant.
//
// Ground truth is reported, never fed in: `grounded` says whether a labelled
// case backs the answer. The keypoints themselves are deliberately NOT loaded
// here — an analyst that has seen the answer key is not being tested, which is
// the dataset's own instruction and the whole basis of the benchmark.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const openModeCaveat = "indicative only — no ground truth for this question"

// skillCardsFor picks the app skill-card prompts that fit a question. Mirrors
// the app's own router; falls back to whatever cards exist so an app with a
// different naming scheme still gets its voice applied.
func skillCardsFor(promptsDir, question string) []string {
	q := strings.ToLower(question)
	want := []string{"communication"}
	switch {
	case strings.Contains(q, "npv"), strings.Contains(q, "payback"), strings.Contains(q, "irr"):
		want = append(want, "npv", "profitability")
	case strings.Contains(q, "how many"), strings.Contains(q, "market size"), strings.Contains(q, "estimate"):
		want = append(want, "market_sizing")
	case strings.Contains(q, "option"), strings.Contains(q, "which of"):
		want = append(want, "options")
	case strings.Contains(q, "risk"), strings.Contains(q, "factors"):
		want = append(want, "risk_mece", "stakeholder_eval")
	default:
		want = append(want, "issue_tree", "hypothesis_first")
	}
	var out []string
	for _, w := range want {
		p := filepath.Join(promptsDir, "analyst_skill_"+w+".md")
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			out = append(out, string(b))
		}
	}
	return out
}

// caseContext returns analyst-SAFE context for a labelled case: the client
// setup and the question text, never structure_4_ground_truth.
func caseContext(appDir, caseID string) (string, bool) {
	if caseID == "" || strings.ContainsAny(caseID, "/\\") || strings.Contains(caseID, "..") {
		return "", false
	}
	seed := filepath.Join(appDir, "data", "seed")
	matches, _ := filepath.Glob(filepath.Join(seed, caseID+"*.json"))
	if len(matches) == 0 {
		// A mounted dataset keeps its own top-level dir in some layouts.
		matches, _ = filepath.Glob(filepath.Join(seed, "*", caseID+"*.json"))
	}
	if len(matches) == 0 {
		return "", false
	}
	sort.Strings(matches)
	b, err := os.ReadFile(matches[0])
	if err != nil {
		return "", false
	}
	body := string(b)
	// Hard stop: never let the answer key reach the analyst, whatever the file
	// shape. Truncating at the ground-truth key is cheaper and far more robust
	// than trying to re-serialise every dataset variant correctly.
	if i := strings.Index(body, "structure_4_ground_truth"); i > 0 {
		body = body[:i]
	}
	const maxCase = 24 << 10
	if len(body) > maxCase {
		body = body[:maxCase]
	}
	return body, true
}

// toolAppAnswer answers as the app's analyst.
func toolAppAnswer(c context.Context, userID, role, app, question, caseID string) (map[string]any, bool) {
	if app == "" || question == "" {
		return map[string]any{"error": "app and question are required"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	promptsDir := filepath.Join(appDir, "prompts")
	sys, err := os.ReadFile(filepath.Join(promptsDir, "analyst_system.md"))
	if err != nil {
		return map[string]any{"error": "app declares no analyst prompt (prompts/analyst_system.md)"}, false
	}

	parts := []string{string(sys)}
	parts = append(parts, skillCardsFor(promptsDir, question)...)
	system := strings.Join(parts, "\n\n---\n\n")

	user := question
	grounded := false
	if caseID != "" {
		if ctxText, ok := caseContext(appDir, caseID); ok {
			user = "Case context (ground truth withheld):\n" + ctxText + "\n\nQuestion:\n" + question
			grounded = true
		}
	}

	text, err := answerWithAppVoice(c, role, system, user)
	if err != nil {
		return map[string]any{"error": "analyst call failed: " + err.Error()}, false
	}

	out := map[string]any{
		"app": app, "answer": text,
		"grounded": grounded,
		"mode":     map[bool]string{true: "casebook", false: "open"}[grounded],
	}
	if !grounded {
		// The caller must be able to state this; an open-mode score presented as
		// a benchmark number is the failure this whole distinction exists for.
		out["caveat"] = openModeCaveat
	}
	if caseID != "" {
		out["case_id"] = caseID
	}
	return out, true
}

// answerWithAppVoice runs one non-streaming completion with the app's own
// system prompt. Mirrors the provider/key/callLLM path the chat endpoint uses
// (me_agent.go) rather than opening a second way to reach a model.
func answerWithAppVoice(ctx context.Context, role, system, user string) (string, error) {
	provider := resolveProvider("", role)
	apiKey, err := provider.keyFn()
	if err != nil {
		return "", err
	}
	resp, err := callLLM(ctx, provider, apiKey, map[string]any{
		"model":      provider.upstreamModel,
		"max_tokens": 2000,
		"system":     system,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	})
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if content, ok := resp["content"].([]any); ok {
		for _, blk := range content {
			m, ok := blk.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := m["type"].(string); t == "text" {
				if s, _ := m["text"].(string); s != "" {
					sb.WriteString(s)
				}
			}
		}
	}
	return strings.TrimSpace(sb.String()), nil
}
