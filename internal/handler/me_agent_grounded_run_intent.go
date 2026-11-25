package handler

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// groundedRunIntent — "run my app's workflow" said in plain words, on a chat
// that is GROUNDED on that app.
//
// Measured 2026-11-25: a student on mlsys-research (chat grounded on the app,
// admin default model claude-code-sonnet — the sandbox lane) typed "Run the
// baseline design for 9.2 and explain each number to me". controlIntent did
// not match ("run the baseline ARM" is the nearest phrase), so the turn stayed
// in the claude-code sandbox, which has no workflow_run tool, and nothing ran.
//
// The ungrounded router has to stay strict because it also fronts a coding
// agent: "run the baseline" in a repo chat may well be a script. Grounding
// changes the prior. When the user is LOOKING AT an app, a run verb near one of
// that app's own loop names — or near the generic nouns an app's workflows are
// described with (baseline / design / experiment / workflow / loop / cycle) —
// is a request to run the app. Both halves are still required: the verb AND
// the noun, within ~60 chars, in a sentence that is not a question.
//
// QUESTIONS DO NOT COUNT. "how would I run the experiment?" asks for an
// explanation, and the sandbox lane can give one; flipping lanes on it would
// move a teaching turn off the model the user picked. Polite requests phrased
// as questions ("can you run the baseline?") DO count — the subject is "you",
// which is a request for action, not "I", which is a request for instructions.
// Note this rule governs only this grounded arm: controlIntent's pre-existing
// literals (e.g. "run the experiment") still match inside a question, and are
// left exactly as they were.

// groundedRunVerb — the verbs that ask for an execution. "do" is included for
// "do the baseline design"; questions ("do I …") are screened out first.
const groundedRunVerb = `\b(?:run|start|launch|kick(?:ed)?\s+off|fire|execute|re-?run|do)\b`

// groundedRunGenericRe — a run verb near a noun that names an app workflow in
// general terms. Bounded gap; "." is allowed inside the gap so "the 9.2 design"
// keeps working (sentences are already split on sentence-ending punctuation).
var groundedRunGenericRe = regexp.MustCompile(groundedRunVerb +
	`.{0,60}?\b(?:baseline|design|experiment|workflow|loop|cycle)s?\b`)

// groundedRunVerbRe is the cheap pre-check: no run verb, no loop lookup.
var groundedRunVerbRe = regexp.MustCompile(groundedRunVerb)

// groundedSentenceEndRe matches sentence-ending punctuation followed by
// whitespace or end of text, and newlines. A bare "." inside "9.2" or "v1.3"
// does not end a sentence.
var groundedSentenceEndRe = regexp.MustCompile(`[.!?]+(?:\s+|$)|\n+`)

// groundedQuestionLeadRe — a sentence that asks for INFORMATION whatever its
// punctuation: a wh-word, or an auxiliary followed by a first-person /
// impersonal subject ("how do I", "should we", "is it", "does this"). "can
// you …" / "could you …" are not here on purpose: those are requests.
var groundedQuestionLeadRe = regexp.MustCompile(
	`^(?:how|what|what's|whats|why|when|where|which|who|whose)\b|` +
		`^(?:do|does|did|should|would|could|can|may|might|shall|is|are|was|were|will)\s+(?:i|we|one|it|this|that|these|those|there)\b`)

// groundedAuxLeadRe — a sentence led by an auxiliary. With a trailing "?" it is
// a yes/no question ("do the experiment results look right?") UNLESS the
// subject is "you" ("can you run the baseline?"), which is a request. Without
// the "?" it may be an imperative ("do the baseline design").
var groundedAuxLeadRe = regexp.MustCompile(
	`^(?:do|does|did|should|would|could|can|may|might|shall|is|are|was|were|will)\s+(\S+)`)

// groundedLoopStopNames — loop ids too generic to stand alone as a signal.
// An app with a loop called `test` must not turn "run the test suite" into a
// workflow dispatch; these names collide with ordinary dev-tooling verbs.
var groundedLoopStopNames = map[string]bool{
	"test": true, "tests": true, "build": true, "install": true, "lint": true,
	"format": true, "setup": true, "dev": true, "start": true, "run": true,
	"main": true, "check": true, "ci": true, "default": true, "app": true,
	"deploy": true, "update": true,
}

// groundedAppFromCtx returns the app the chat is grounded on, "" if none.
// Same key stashViewingApp reads.
func groundedAppFromCtx(ctx map[string]any) string {
	if ctx == nil {
		return ""
	}
	app, _ := ctx["app"].(string)
	app = strings.TrimSpace(app)
	if !validAppSlug(app) {
		return ""
	}
	return app
}

// lastUserText is the latest user message, lowercased; "" if none.
func lastUserText(msgs []chatMessage) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			return strings.ToLower(msgs[i].Content)
		}
	}
	return ""
}

// isInfoQuestion reports whether one sentence asks for information rather
// than action. The caller passes a trimmed, lowercased sentence and whether it
// ended in "?".
func isInfoQuestion(sentence string, endsInQ bool) bool {
	// "so how do i…", "ok, what…" — drop one short leading discourse marker.
	for _, lead := range []string{"so ", "ok ", "ok, ", "okay ", "okay, ", "and ", "but ", "hi ", "hey ", "um ", "also "} {
		if strings.HasPrefix(sentence, lead) {
			sentence = strings.TrimSpace(strings.TrimPrefix(sentence, lead))
			break
		}
	}
	if groundedQuestionLeadRe.MatchString(sentence) {
		return true
	}
	if endsInQ {
		if m := groundedAuxLeadRe.FindStringSubmatch(sentence); m != nil && m[1] != "you" && m[1] != "u" {
			return true
		}
	}
	return false
}

// actionSentences splits text into sentences and keeps the ones that are not
// information questions.
func actionSentences(text string) []string {
	var out []string
	keep := func(s, sep string) {
		s = strings.TrimSpace(s)
		if s != "" && !isInfoQuestion(s, strings.Contains(sep, "?")) {
			out = append(out, s)
		}
	}
	last := 0
	for _, loc := range groundedSentenceEndRe.FindAllStringIndex(text, -1) {
		keep(text[last:loc[0]], text[loc[0]:loc[1]])
		last = loc[1]
	}
	keep(text[last:], "")
	return out
}

// loopNameRe builds the matcher for one loop id: a run verb within ~60 chars
// before the id, where the id may be spelled raw (`case_eval`) or as words
// ("case eval", "case-eval"). nil for ids too generic to count.
func loopNameRe(loop string) *regexp.Regexp {
	id := strings.ToLower(strings.TrimSpace(loop))
	if id == "" {
		return nil
	}
	var parts []string
	for _, p := range strings.FieldsFunc(id, func(r rune) bool { return r == '_' || r == '-' || r == ' ' }) {
		parts = append(parts, regexp.QuoteMeta(p))
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 && (groundedLoopStopNames[id] || len(id) < 3) {
		return nil
	}
	return regexp.MustCompile(groundedRunVerb + `.{0,60}?\b` + strings.Join(parts, `[\s_-]+`) + `s?\b`)
}

// groundedRunIntent reports whether the latest user turn, on a chat grounded
// on an app, asks to run one of that app's workflows. loopsOf resolves the
// grounded app's loop ids; it is only called once the cheaper checks pass and
// may be nil (then only the generic nouns count).
func groundedRunIntent(msgs []chatMessage, ctx map[string]any, loopsOf func(app string) []string) bool {
	app := groundedAppFromCtx(ctx)
	if app == "" {
		return false
	}
	text := lastUserText(msgs)
	if text == "" || !groundedRunVerbRe.MatchString(text) {
		return false
	}
	sentences := actionSentences(text)
	if len(sentences) == 0 {
		return false
	}
	for _, s := range sentences {
		// "run the github workflow", "start the event loop" — the programming
		// senses of these nouns stay on the coding lane even when grounded.
		if !codeConstructContext(s) && groundedRunGenericRe.MatchString(s) {
			return true
		}
	}
	if loopsOf == nil {
		return false
	}
	loops := loopsOf(app)
	for _, l := range loops {
		re := loopNameRe(l)
		if re == nil {
			continue
		}
		for _, s := range sentences {
			if re.MatchString(s) {
				return true
			}
		}
	}
	return false
}

// ── loop-name lookup, cached ────────────────────────────────────────────────

// appLoopNamesTTL bounds how stale a loop list may be. A loop added to an app
// becomes routable within this window; the lookup can hit xp.io over HTTP, so
// it must not run on every chat turn.
const appLoopNamesTTL = 2 * time.Minute

// appLoopNamesCacheMax caps the cache; past it the map is simply reset.
const appLoopNamesCacheMax = 2048

type appLoopNamesEntry struct {
	names []string
	at    time.Time
}

var (
	appLoopNamesMu    sync.Mutex
	appLoopNamesCache = map[string]appLoopNamesEntry{}
	// appLoopNamesLoader is swappable for tests.
	appLoopNamesLoader = loadAppLoopNames
)

// cachedAppLoopNames returns the loop ids of (userID, app), cached for
// appLoopNamesTTL. Empty results are cached too, so an unknown app does not
// trigger a fetch on every turn.
func cachedAppLoopNames(userID, app string) []string {
	if userID == "" || app == "" {
		return nil
	}
	key := userID + "\x00" + app
	now := time.Now()
	appLoopNamesMu.Lock()
	if e, ok := appLoopNamesCache[key]; ok && now.Sub(e.at) < appLoopNamesTTL {
		appLoopNamesMu.Unlock()
		return e.names
	}
	appLoopNamesMu.Unlock()

	names := appLoopNamesLoader(userID, app)

	appLoopNamesMu.Lock()
	if len(appLoopNamesCache) >= appLoopNamesCacheMax {
		appLoopNamesCache = map[string]appLoopNamesEntry{}
	}
	appLoopNamesCache[key] = appLoopNamesEntry{names: names, at: now}
	appLoopNamesMu.Unlock()
	return names
}

// loadAppLoopNames reads the app's loop ids through the same discovery the
// Workflows page uses: the local tenant/operator spec first (no I/O beyond a
// stat), then readAppSpecBytes — the user's applied save, the installed spec
// echo, then the published xp.io spec.
func loadAppLoopNames(userID, app string) []string {
	loops, _ := readLoopsFromAnywhere(userID, app)
	if len(loops) == 0 {
		if spec := readAppSpecForParse(userID, app, ""); len(spec) > 0 {
			loops, _ = readYamlLoopsBytes(spec)
		}
	}
	names := make([]string, 0, len(loops))
	for _, l := range loops {
		if n := strings.TrimSpace(l.Name); n != "" {
			names = append(names, n)
		}
	}
	return names
}
