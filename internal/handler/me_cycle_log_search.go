// me_cycle_log_search.go — GET /api/v1/me/cycles/:app/:loop/:ts/search?q=&type=
//
// Grep a single cycle's run-log + issues for a query string. Today the only way
// to "find" something in a run is to scroll the Run log / Stages views; this
// streams the same three on-disk sources me_cycle_log.go reads and returns the
// matching rows so the UI can offer a search box with click-to-scroll.
//
// Sources (mirrors cycleConversation's path patterns):
//  1. <cycle dir>/.llm_conversation.jsonl — the LLM turns (prompt/response/thinking)
//  2. data/journal.jsonl                  — stage/tool events, filtered to this
//     loop AND to this cycle's time window (ts >= the cycle's start)
//  3. <cycle dir>/step_errors.json        — the cycle's recorded step errors
//
// `type` narrows the sources: "llm" → conversation only, "stage" → journal only,
// "error" → step_errors only; empty/other → all three. Matching is
// case-insensitive over the salient text fields (prompt/response/thinking/note/
// error/skill). Results are capped at 50, each snippet ≤ 200 chars. Read-only,
// best-effort — a missing source contributes nothing, never an error.
package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	cycleSearchMatchCap   = 50
	cycleSearchSnippetLen = 200
)

// searchMatch is one hit returned to the UI.
type searchMatch struct {
	Ts      string `json:"ts"`
	Event   string `json:"event"`
	Field   string `json:"field"`
	Snippet string `json:"snippet"`
	Index   int    `json:"index"`
}

// MeCycleLogSearch — GET /me/cycles/:app/:loop/:ts/search?q=&type=llm|stage|error
func MeCycleLogSearch(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	ts := c.Param("ts")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) || !slugRe.MatchString(ts) {
		fail(c, http.StatusBadRequest, 1400, "invalid app/loop/ts")
		return
	}
	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		fail(c, http.StatusBadRequest, 1400, "q required")
		return
	}
	kind := c.Query("type") // "", llm, stage, error

	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	matches, capped := searchCycleLog(appDir, loop, ts, q, kind)
	var unavailable string
	if len(matches) == 0 {
		// "no matches" and "the transcript is unreachable" are opposite answers
		// and looked identical: one means your term is not there, the other
		// means nothing was searched. Scope the reachability check to THIS
		// (loop, ts) cycle, not "does this app have any cycles visible at all" —
		// an app with some cycles visible (a different loop, a different site)
		// can still be missing the one being asked about, and the coarse,
		// app-wide check called that "genuinely empty" (200 with 0 matches for a
		// run this pod never saw, indistinguishable from the term not being
		// there).
		if why := unavailableReasonForCycle(appDir, loop, ts, "the cycle transcript this searches"); why != "" {
			// Before giving up: this may be the caller's OWN install, whose
			// cycle dir lives on the scheduler (home/office k3s) rather than
			// on this pod. MeCycleLog's conversation view already bridges that
			// gap for the transcript via cycle_read; do the same here instead
			// of reporting "unavailable" for a run the scheduler can actually
			// produce. The journal/"stage" source is intentionally skipped —
			// cycle_read only returns the one cycle dir's files, not the
			// app-wide journal.jsonl (see cycleTranscriptViaScheduler).
			if rm, rc, err, tried := searchCycleViaScheduler(ginReqCtx(c), userID, app, loop, ts, q, kind); tried {
				switch {
				case err == nil:
					matches, capped = rm, rc
					why = ""
				case errors.Is(err, errCycleNotOnScheduler):
					why = ""
				default:
					why = "the cycle transcript this searches could not be read from the scheduler: " + err.Error()
				}
			}
			unavailable = why
		}
	}
	resp := gin.H{
		"app": app, "loop": loop, "ts": ts,
		"q": q, "type": kind,
		"matches": matches, "count": len(matches), "capped": capped,
	}
	if unavailable != "" {
		resp["unavailable"] = unavailable
	}
	ok(c, "ok", resp)
}

// searchCycleViaScheduler is searchCycleLog's counterpart for a cycle this
// pod cannot see on disk: it fetches the caller's own cycle dir from the
// scheduler (the same bridge MeCycleLog's conversation view uses) and
// searches the LLM transcript + step errors in memory. tried=false when the
// app is not the caller's own scheduler-side install (an operator-shared
// app, or genuinely absent everywhere), so the caller keeps its own
// "not available" answer.
func searchCycleViaScheduler(ctx context.Context, userID, app, loop, ts, q, kind string) (matches []searchMatch, capped bool, err error, tried bool) {
	if _, direct, viaIntent, _ := ownerWriteTarget(userID, app); direct || !viaIntent || !safeSeg(loop) || !safeSeg(ts) {
		return nil, false, nil, false
	}
	res, err := cycleFilesViaScheduler(ctx, userID, app, loop, ts, true)
	if err != nil {
		return nil, false, err, true
	}
	m, c := searchCycleFiles(res.files, q, kind)
	return m, c, nil, true
}

// searchCycleFiles mirrors searchCycleLog's "llm" and "error" sources against
// files already read into memory (e.g. fetched from the scheduler via
// cycle_read) instead of this pod's disk. There is no "stage" source here:
// the scheduler read returns only the one cycle dir's files, never the
// app-wide journal.jsonl.
func searchCycleFiles(files cycleFiles, q, kind string) ([]searchMatch, bool) {
	needle := strings.ToLower(q)
	matches := []searchMatch{}
	idx := 0
	capped := false
	add := func(ts, event, field, full string) bool {
		if len(matches) >= cycleSearchMatchCap {
			capped = true
			return false
		}
		matches = append(matches, searchMatch{
			Ts: ts, Event: event, Field: field,
			Snippet: searchSnippet(full, needle), Index: idx,
		})
		idx++
		return true
	}

	wantLLM := kind == "" || kind == "llm"
	wantError := kind == "" || kind == "error"

	if wantLLM && !capped {
		scanCycleFilesJSONL(files[".llm_conversation.jsonl"], func(r map[string]any) bool {
			rts := asStr(r["ts"])
			event := asStr(r["event"])
			if event == "" {
				event = "llm"
			}
			for _, field := range []string{"prompt", "response", "thinking", "skill"} {
				v := asStr(r[field])
				if v != "" && strings.Contains(strings.ToLower(v), needle) {
					if !add(rts, event, field, v) {
						return false
					}
				}
			}
			return true
		})
	}

	if wantError && !capped {
		for _, se := range parseStepErrorsForSearch(files["step_errors.json"]) {
			combined := se.Step + " " + se.Skill + " " + se.Error
			if !strings.Contains(strings.ToLower(combined), needle) {
				continue
			}
			full := se.Error
			if full == "" {
				full = se.Step
			}
			if !add(se.Ts, "error", "error", full) {
				break
			}
		}
	}
	return matches, capped
}

// scanCycleFilesJSONL is scanCycleSearchJSONL for bytes already in memory.
func scanCycleFilesJSONL(b []byte, fn func(map[string]any) bool) {
	if len(b) == 0 {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if !fn(row) {
			return
		}
	}
}

// searchCycleLog greps one cycle's transcript + journal + step errors for q
// (case-insensitive), capped at cycleSearchMatchCap. `kind` narrows the sources
// ("llm"|"stage"|"error"; empty = all). Shared by the HTTP handler + the
// search_run_log chat tool so both behave identically. Read-only, best-effort.
func searchCycleLog(appDir, loop, ts, q, kind string) ([]searchMatch, bool) {
	needle := strings.ToLower(q)
	matches := []searchMatch{}
	idx := 0
	capped := false
	// add records a hit; returns false once the cap is reached so callers stop.
	add := func(ts, event, field, full string) bool {
		if len(matches) >= cycleSearchMatchCap {
			capped = true
			return false
		}
		matches = append(matches, searchMatch{
			Ts: ts, Event: event, Field: field,
			Snippet: searchSnippet(full, needle), Index: idx,
		})
		idx++
		return true
	}

	wantLLM := kind == "" || kind == "llm"
	wantStage := kind == "" || kind == "stage"
	wantError := kind == "" || kind == "error"

	// 1. LLM turns for this cycle (prompt / response / thinking).
	if wantLLM && !capped {
		convPath, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "cycles", loop, ts, ".llm_conversation.jsonl"))
		scanCycleSearchJSONL(convPath, func(r map[string]any) bool {
			rts := asStr(r["ts"])
			event := asStr(r["event"])
			if event == "" {
				event = "llm"
			}
			for _, field := range []string{"prompt", "response", "thinking", "skill"} {
				v := asStr(r[field])
				if v != "" && strings.Contains(strings.ToLower(v), needle) {
					if !add(rts, event, field, v) {
						return false
					}
				}
			}
			return true
		})
	}

	// 2. Journal stage/tool events from this cycle's start onward (loop-scoped).
	if wantStage && !capped {
		start := digitsOnlyTs(ts)
		journalPath, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "journal.jsonl"))
		scanCycleSearchJSONL(journalPath, func(r map[string]any) bool {
			if lp, ok := r["loop"].(string); ok && lp != "" && lp != loop {
				return true
			}
			rts := asStr(r["ts"])
			if digitsOnlyTs(rts) < start {
				return true
			}
			event := asStr(r["event"])
			if event == "" {
				event = "stage"
			}
			for _, field := range []string{"note", "error", "skill", "stage", "message", "detail"} {
				v := asStr(r[field])
				if v != "" && strings.Contains(strings.ToLower(v), needle) {
					if !add(rts, event, field, v) {
						return false
					}
				}
			}
			return true
		})
	}

	// 3. Recorded step errors for this cycle.
	if wantError && !capped {
		cdir, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "cycles", loop, ts))
		errPath := filepath.Join(cdir, "step_errors.json")
		for _, se := range readStepErrorsForSearch(errPath) {
			combined := se.Step + " " + se.Skill + " " + se.Error
			if !strings.Contains(strings.ToLower(combined), needle) {
				continue
			}
			full := se.Error
			if full == "" {
				full = se.Step
			}
			if !add(se.Ts, "error", "error", full) {
				break
			}
		}
	}
	return matches, capped
}

// scanCycleSearchJSONL streams a JSONL file line by line, calling fn for each
// parsed row; fn returns false to stop early (cap reached). Missing file → no-op.
func scanCycleSearchJSONL(path string, fn func(map[string]any) bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		if !fn(row) {
			return
		}
	}
}

// stepErrorSearch is the subset of a step_errors.json row we search over. The
// runner writes {step, skill, error}; ts is absent in the array shape (left "").
type stepErrorSearch struct {
	Ts    string `json:"ts"`
	Step  string `json:"step"`
	Skill string `json:"skill"`
	Error string `json:"error"`
}

// readStepErrorsForSearch reads step_errors.json (an array of {step,error,ts}
// records, or a {errors:[...]} wrapper). Best-effort: any error → empty slice.
func readStepErrorsForSearch(path string) []stepErrorSearch {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseStepErrorsForSearch(b)
}

// parseStepErrorsForSearch is readStepErrorsForSearch's parse half, usable on
// bytes already in memory (the scheduler's cycle_read response) as well as a
// file read off disk.
func parseStepErrorsForSearch(b []byte) []stepErrorSearch {
	if len(b) == 0 {
		return nil
	}
	var arr []stepErrorSearch
	if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
		return arr
	}
	var wrap struct {
		Errors []stepErrorSearch `json:"errors"`
	}
	if json.Unmarshal(b, &wrap) == nil {
		return wrap.Errors
	}
	return nil
}

// searchSnippet returns a ≤cycleSearchSnippetLen window of `full` centered on the
// first case-insensitive occurrence of `needle` (lowercased), so the UI shows
// context around the hit rather than the head of a multi-KB prompt.
func searchSnippet(full, needle string) string {
	low := strings.ToLower(full)
	pos := strings.Index(low, needle)
	if pos < 0 {
		pos = 0
	}
	// Center the window on the match, clamped to the string bounds.
	half := (cycleSearchSnippetLen - len(needle)) / 2
	if half < 0 {
		half = 0
	}
	start := pos - half
	if start < 0 {
		start = 0
	}
	end := start + cycleSearchSnippetLen
	if end > len(full) {
		end = len(full)
	}
	snippet := full[start:end]
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(full) {
		snippet = snippet + "…"
	}
	return snippet
}
