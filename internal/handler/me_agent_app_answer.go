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
	"strconv"
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

// Case roles. The same dataset file serves three different seats at the table,
// and they do NOT get the same view of it.
const (
	caseRoleInterviewee = "interviewee" // the AI is being tested — client brief only
	caseRoleInterviewer = "interviewer" // the AI runs the case for a HUMAN candidate
	caseRoleJudge       = "judge"       // the AI scores a finished transcript
)

// caseFieldsInterviewee is the analyst-safe projection: who the client is, what
// the situation is, what the ask is — and nothing that would let the candidate
// see the questions or the answers ahead of time. It is also the ANCHOR for
// every other role: if a file cannot produce this much, no role gets anything.
var caseFieldsInterviewee = []string{
	"case_id", "industry", "difficulty", "case_type",
	"structure_1_client_basic_context", // company, situation, the ask
}

// caseFieldsInterviewerExtra is what running the case requires and being tested
// on it forbids: the interviewer's own script, the questions to put, and the
// facts to release only when the candidate's answer touches them.
// NOTE: opening_prompt is deliberately ABSENT. It is the interviewer's full
// script and contains every question, and a model handed it pastes it verbatim
// — measured live: coach mode revealed Q2, Q3 and Q4 in its opening turn, which
// is the same leak that made the analyst echo the script back at the user. The
// instruction "never reveal a later question" does not survive contact with a
// model that has the whole list in front of it. Structure beats prompt: see
// caseContextAtQuestion, which projects ONE question.
var caseFieldsInterviewerExtra = []string{
	"structure_3_case_questions",
	"structure_2_information_upon_request",
}

// caseFieldsJudgeExtra is the answer key. Only a role that scores a FINISHED
// transcript may hold it — an interviewer that can see the key leaks it through
// its own reactions long before it ever quotes it.
var caseFieldsJudgeExtra = []string{
	"structure_4_ground_truth",
}

// caseContext returns analyst-SAFE context for a labelled case: the client
// setup only, never the questions and never structure_4_ground_truth. Thin
// wrapper so existing callers keep the interviewee view and cannot silently
// acquire a wider one.
func caseContext(appDir, caseID string) (string, bool) {
	return caseContextForRole(appDir, caseID, caseRoleInterviewee)
}

// caseContextForRole projects a labelled case for one seat at the table.
//
// A single global rule cannot serve all three: the interviewee must not see the
// questions, the interviewer must, and only the judge may see the answer key.
// So the allowlist is per role and it is additive — interviewer = interviewee +
// script/questions/on-request facts, judge = interviewer + ground truth.
//
// It FAILS CLOSED. An unknown or empty role is treated as "interviewee", which
// is the narrowest view, so a typo, a zero-value struct field or a stray query
// parameter degrades to the safe projection rather than widening it. Widening
// has to be spelled correctly and on purpose.
// Per-role size ceilings. The interviewee sees a brief (0.5-1.2 KB measured);
// the interviewer adds the script, questions and release rules; the judge adds
// the rubric, which is the bulk of the file.
const (
	maxCaseInterviewee = 24 << 10
	maxCaseInterviewer = 64 << 10
	maxCaseJudge       = 192 << 10
)

func caseContextForRole(appDir, caseID, role string) (string, bool) {
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
	path, ok := resolveUniqueCase(caseID, matches)
	if !ok {
		return "", false
	}
	b, err := os.ReadFile(path)
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
	out := map[string]json.RawMessage{}
	for _, k := range caseFieldsInterviewee {
		if v, ok := raw[k]; ok {
			out[k] = stripNoteKeys(v)
		}
	}
	// The interviewee projection is the anchor for EVERY role. A file that
	// cannot even produce a client brief is an unrecognised shape, and handing
	// a judge the answer key out of a file we could not otherwise parse is
	// exactly the partial dump this refusal exists to prevent.
	if len(out) == 0 {
		return "", false
	}
	wider := []string(nil)
	switch role {
	case caseRoleInterviewer:
		wider = caseFieldsInterviewerExtra
	case caseRoleJudge:
		wider = append(append([]string{}, caseFieldsInterviewerExtra...), caseFieldsJudgeExtra...)
	default:
		role = caseRoleInterviewee // fail closed: unknown/empty → narrowest view
	}
	for _, k := range wider {
		if v, ok := raw[k]; ok {
			out[k] = stripNoteKeys(v)
		}
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
	// refuse rather than serve it. The judge is the one role for which the key
	// is the point, so it is exempt — every other role is not.
	if role != caseRoleJudge && strings.Contains(body, "ground_truth") {
		return "", false
	}
	// Cap PER ROLE, and REFUSE rather than truncate.
	//
	// A flat 24 KB cut was silently wrong for the wider roles: measured across
	// the 50 shipped cases the judge projection runs 19-41 KB and the
	// interviewer 12-22 KB (json.RawMessage carries the source file's
	// indentation verbatim). Truncating mid-document yields invalid JSON AND a
	// partial answer key — a judge would score against half a rubric with
	// nothing to indicate anything was missing. An error is recoverable; a
	// quietly halved rubric is not.
	limit := maxCaseInterviewee
	switch role {
	case caseRoleInterviewer:
		limit = maxCaseInterviewer
	case caseRoleJudge:
		limit = maxCaseJudge
	}
	if len(body) > limit {
		return "", false
	}
	return body, true
}

// stripNoteKeys drops "_"-prefixed annotation keys from a projected object.
//
// They are authoring commentary for whoever edits the dataset, not case
// content — and two of the 50 shipped cases name the answer key's FIELD inside
// one ("... structure_4_ground_truth"). That tripped the substring guard and
// made the interviewer refuse those cases outright: the guard working correctly
// on text that was never the key. Dropping the commentary is the fix; relaxing
// the guard would not have been.
//
// Re-encoding compactly also sheds the source indentation, which is most of
// what pushed these projections toward the cap.
func stripNoteKeys(v json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(v, &obj) != nil {
		return v // string / array / number — nothing to strip
	}
	for k := range obj {
		if strings.HasPrefix(k, "_") {
			delete(obj, k)
			continue
		}
		obj[k] = stripNoteKeys(obj[k])
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(obj) != nil {
		return v
	}
	return json.RawMessage(bytes.TrimSpace(buf.Bytes()))
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
	return answerWithAppVoiceModel(ctx, role, "", system, user)
}

// answerWithAppVoiceModel is answerWithAppVoice with an explicit provider.
//
// Scoring is precision work, and the default chat provider is not up to it:
// measured across six runs on the same question and answer, the judge returned
// totals of 1, 3 and 13 for a rubric with a fixed number of keypoints, and
// failed to produce a parsable count half the time. A coverage figure computed
// from a total the scorer invented is the same unearned number this tool was
// built to replace — just with more steps.
func answerWithAppVoiceModel(ctx context.Context, role, modelID, system, user string) (string, error) {
	provider := resolveProvider(modelID, role)
	// This path speaks HTTP ONLY. Some providers are subprocess transports —
	// claude-code-* runs the CLI in the sandbox and carries endpoint: "" — and
	// super_admin's DEFAULT is claude-code-sonnet. So every app_answer by a
	// super_admin (which is the operator + demo account) POSTed to "" and came
	// back "unsupported protocol scheme". The chat itself was fine, because its
	// own path knows how to run the subprocess; only this helper does not.
	//
	// It failed loudly but degraded quietly: the agent, seeing the tool error,
	// just answered from its own knowledge — so the reply still looked like a
	// consulting answer while carrying none of the app's analyst prompt, none of
	// its skill cards, and no score at all.
	if provider.endpoint == "" {
		provider = httpProviderFor(role)
	}
	apiKey, err := provider.keyFn()
	if err != nil {
		return "", err
	}
	resp, err := callLLM(ctx, provider, apiKey, map[string]any{
		"model": provider.upstreamModel,
		// 2000 truncated the JUDGE. The pinned scorer is a reasoning model: it
		// emits a thinking preamble before its answer, and a long one consumed
		// the whole budget before the JSON appeared — which surfaced as
		// "judge returned no parsable score" on some runs and not others, with
		// no other difference between them.
		"max_tokens": 6000,
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
		// Falling through here produced an EMPTY turn: the caller asked for a
		// specific tool, the tool could not be grounded, and the model — handed a
		// forced choice it could not satisfy — returned nothing at all. The user
		// saw a button that did nothing. Say what went wrong instead.
		return map[string]any{
			"error": "no app in context — a correction has to say which app it is about",
		}, true
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

// caseContextAtQuestion is the interviewer's view for ONE question.
//
// caseContextForRole(interviewer) hands over every question at once, which a
// model reliably dumps into its first turn. A candidate who can see Q4 while
// answering Q1 is not being interviewed. So the question set is filtered to the
// one being asked: the model cannot reveal what it was never given.
//
// qIdx is 0-based over the case's questions in key order (Q1, Q2, …), clamped —
// past the end returns the last question rather than nothing, so an over-long
// conversation degrades to "still on the final question" instead of losing the
// case.
func caseContextAtQuestion(appDir, caseID string, qIdx int) (string, bool) {
	full, ok := caseContextForRole(appDir, caseID, caseRoleInterviewer)
	if !ok {
		return "", false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(full), &doc) != nil {
		return "", false
	}
	qraw, present := doc["structure_3_case_questions"]
	if !present {
		return full, true // no question set to narrow — nothing to leak
	}
	var qs map[string]json.RawMessage
	if json.Unmarshal(qraw, &qs) != nil {
		return "", false
	}
	keys := make([]string, 0, len(qs))
	for k := range qs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return full, true
	}
	if qIdx < 0 {
		qIdx = 0
	}
	if qIdx >= len(keys) {
		qIdx = len(keys) - 1
	}
	only := map[string]json.RawMessage{keys[qIdx]: qs[keys[qIdx]]}
	enc, err := json.Marshal(only)
	if err != nil {
		return "", false
	}
	doc["structure_3_case_questions"] = enc
	// Tell the interviewer where it is, so it does not invent a "next" question
	// it cannot see.
	doc["_question_position"] = json.RawMessage(
		[]byte(`"` + keys[qIdx] + ` of ` + strconv.Itoa(len(keys)) + `"`))
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if e.Encode(doc) != nil {
		return "", false
	}
	body := strings.TrimSpace(buf.String())
	if strings.Contains(body, "ground_truth") {
		return "", false
	}
	return body, true
}

// httpProviderFor returns the caller's highest-preference provider that has an
// actual HTTP endpoint, for the paths that cannot run a subprocess transport.
//
// Falls back to the pinned scorer, which is HTTP by construction — better a
// known-good backend than an error, since the alternative is the agent silently
// improvising an answer that carries none of the app's voice or scoring.
func httpProviderFor(role string) llmProvider {
	for _, p := range llmProviders {
		if p.endpoint != "" && providerAllowed(role, p) {
			return p
		}
	}
	for _, p := range llmProviders {
		if p.id == judgeModelID {
			return p
		}
	}
	return defaultProvider()
}

// resolveUniqueCase turns a glob result into ONE case file, or refuses.
//
// `case_id` in the corpus is only the NUMBER, so Case_001 exists three times —
// Case_001_DieselTruck_PK20, Case_001_LasioVirus_PK23, Case_001_PremierOil_PK21.
// Globbing caseID+"*.json" and taking matches[0] after a lexical sort therefore
// resolved a bare "Case_001" to DieselTruck, whichever case the caller meant.
//
// Observed live and it is worse than a wrong lookup: an interview opened on
// Premier Oil with the full id, then a follow-up passed the bare "Case_001" and
// silently landed on the diesel-truck case. The model noticed the mismatch
// mid-interview, announced it had "mislabeled the case", and restarted on the
// wrong one — so the candidate was scored against a case they were never given.
//
// commands/_case.py has always raised on an ambiguous prefix rather than pick.
// This mirrors that: an EXACT stem (with or without the _vN suffix) always wins,
// a prefix is honoured only when it names exactly one case, and anything
// ambiguous fails closed. Silently guessing is the one behaviour not on offer.
func resolveUniqueCase(caseID string, matches []string) (string, bool) {
	sort.Strings(matches)
	distinct := map[string]string{} // case stem (minus _vN) → path
	for _, m := range matches {
		stem := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
		if stem == caseID {
			return m, true // exact filename stem
		}
		base := stripCaseVersion(stem)
		if base == caseID {
			return m, true // exact case, versioned file
		}
		if _, seen := distinct[base]; !seen {
			distinct[base] = m
		}
	}
	if len(distinct) == 1 {
		for _, p := range distinct {
			return p, true // unambiguous prefix
		}
	}
	return "", false // ambiguous — refuse rather than pick one
}

// toolCaseOpen returns a labelled case's brief so the agent can OPEN it.
//
// Both casebook modes need this and neither had it. The agent's only case-aware
// verb was app_answer, which requires a question — so asked to "give me the
// opening" it called app_answer with a case_id and no question, got
// "app and question are required", and improvised the case from memory. Observed
// live: it invented a Premier Oil opening, then contradicted itself a turn later.
//
// Role-projected through the same allowlist as everything else, so opening a
// case as the interviewee cannot hand over the questions, and only the
// interviewer seat gets the release inventory. Unknown role fails closed to
// interviewee.
func toolCaseOpen(userID, app, caseID, role string) (map[string]any, bool) {
	if app == "" || caseID == "" {
		return map[string]any{"error": "app and case_id are required"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	seat := caseRoleInterviewee
	if role == caseRoleInterviewer {
		seat = caseRoleInterviewer
	}
	ctxText, ok := caseContextForRole(appDir, caseID, seat)
	if !ok {
		// The commonest cause is an ambiguous id — `Case_001` names three
		// different cases — so say that rather than "not found", which sends the
		// agent looking for a file instead of qualifying the id it already has.
		return map[string]any{
			"error": "could not open '" + caseID + "' — use the full case id " +
				"(e.g. Case_001_PremierOil_PK21); a bare number is ambiguous, and " +
				"`casebook` lists the exact ids",
		}, false
	}
	return map[string]any{
		"app": app, "case_id": caseID, "role": seat, "case": ctxText,
		"note": map[bool]string{
			true:  "You are the INTERVIEWER. Deliver the brief, ask the questions in order, and release an on-request fact only when the candidate's answer touches it.",
			false: "You are the INTERVIEWEE. This is the client brief only — the questions come one at a time from the interviewer.",
		}[seat == caseRoleInterviewer],
	}, true
}
