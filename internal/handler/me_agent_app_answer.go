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
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lumid_identity/models"
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
	// PROJECT, don't truncate. Cutting at structure_4 kept the answer key out but
	// still handed the analyst the interviewer's script (opening_prompt), every
	// question Q1..Q4, and structure_2 — the facts it is supposed to have to ASK
	// for. So the interview was never blind: the interviewee could see the whole
	// case ahead, and (observed live) echoed the interviewer's prompt verbatim
	// into the chat, revealing all four questions and inverting the roles.
	//
	// An allowlist is the only safe shape here. A new dataset field is invisible
	// by default rather than leaked by default, which is the correct direction
	// for a file that also carries the answer key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return "", false
	}
	allowed := []string{
		"case_id", "industry", "difficulty", "case_type",
		"structure_1_client_basic_context", // company, situation, the ask
	}
	out := map[string]json.RawMessage{}
	for _, k := range allowed {
		if v, ok := raw[k]; ok {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return "", false
	}
	// Encoder with escaping off: json.Marshal HTML-escapes &, <, >, so an
	// industry like "Energy / Oil & Gas" would reach the model as
	// "Oil \u0026 Gas". Harmless to a parser, noise to a language model.
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		return "", false
	}
	body := strings.TrimSpace(buf.String())
	// Belt and braces: if a dataset ever nests the key inside an allowed field,
	// refuse rather than serve it.
	if strings.Contains(body, "ground_truth") {
		return "", false
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

// toolAppFeedback records a correction against an app and STAGES it for review.
//
// give_feedback cannot serve this: it requires app+loop+ts because it is
// feedback on a scheduled cycle run, and an interactive answer has no run to
// point at. So a user correcting an answer in chat had nowhere to send it.
//
// Staged, never auto-applied: a claim that an answer was wrong is a claim about
// quality, and an unreviewed one does not just sit there — it biases what the
// app retrieves next. The human confirms before it compounds.
func toolAppFeedback(userID, app, note string, rating int) (map[string]any, bool) {
	if app == "" || strings.TrimSpace(note) == "" {
		return map[string]any{"error": "app and note are required"}, false
	}
	if resolveAppDir(userID, app) == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	agent := "mbb-ai-analyst"
	if xp, err := os.ReadFile(filepath.Join(resolveAppDir(userID, app), "xpcloud.yaml")); err == nil {
		if a := firstMemoryAgent(xp); a != "" {
			agent = a
		}
	}
	d := &models.MeDraft{
		ID:      "fb-" + contentSHA([]byte(app + note + time.Now().UTC().String()))[:24],
		UserSub: userID, App: app, Agent: agent,
		Subject: "Correction", Body: strings.TrimSpace(note),
		State: "pending",
	}
	if rating != 0 {
		d.Confidence = float64(rating)
	}
	if err := draftStoreStage(d); err != nil {
		return map[string]any{"error": "could not stage: " + err.Error()}, false
	}
	return map[string]any{
		"ok": true, "app": app, "draft_id": d.ID, "agent": agent,
		"state": "pending",
		"next":  "waiting in this app's Review queue; approve it and it shapes later answers",
	}, true
}

// firstMemoryAgent reads memory_agent / memory_agents[0] from a spec so a
// correction is attributed to the app's own agent rather than a hardcoded one.
func firstMemoryAgent(spec []byte) string {
	var doc struct {
		MemoryAgent  string   `yaml:"memory_agent"`
		MemoryAgents []string `yaml:"memory_agents"`
	}
	if yaml.Unmarshal(spec, &doc) != nil {
		return ""
	}
	if doc.MemoryAgent != "" {
		return doc.MemoryAgent
	}
	if len(doc.MemoryAgents) > 0 {
		return doc.MemoryAgents[0]
	}
	return ""
}

// runForcedAppTool executes a client-forced app tool without a model turn.
//
// Only the app tools are eligible, and only their own arguments are synthesised
// — from the viewing context the client already sent and the user's last
// message. It cannot reach anything else, so "force a tool" can never become
// "call an arbitrary handler with attacker-chosen args".
func runForcedAppTool(c *gin.Context, userID, role, tool string, body meAgentChatBody) (map[string]any, bool) {
	app := ""
	if body.Context != nil {
		app, _ = body.Context["app"].(string)
	}
	if app == "" {
		return nil, false // nothing to ground on; fall through to the model
	}
	last := ""
	for i := len(body.Messages) - 1; i >= 0; i-- {
		if body.Messages[i].Role == "user" {
			last = strings.TrimSpace(body.Messages[i].Content)
			break
		}
	}
	if last == "" {
		return nil, false
	}
	switch tool {
	// app_answer is deliberately NOT here. "Ask the app" is a sticky toggle that
	// is ON by default, so forcing it server-side hijacked EVERY docked turn into
	// a one-shot answer with no case context and no conversation history —
	// breaking multi-turn continuity and reload persistence (shipped as v0.5.17,
	// reverted 20 minutes later). Only a tool sent by an explicit, per-turn user
	// action belongs on this path.
	case "app_feedback":
		// The composer prefixes the correction; the note is what follows.
		note := last
		if i := strings.Index(note, ":"); i > 0 && i < 60 {
			note = strings.TrimSpace(note[i+1:])
		}
		res, _ := toolAppFeedback(userID, app, note, -1)
		return res, true
	}
	return nil, false // any other tool stays the model's business
}
