// me_cycle_log_search.go — GET /api/v1/me/cycles/:app/:loop/:ts/search?q=&type=
//
// Grep a single cycle's run-log + issues for a query string. Today the only way
// to "find" something in a run is to scroll the Run log / Stages views; this
// streams the same three on-disk sources me_cycle_log.go reads and returns the
// matching rows so the UI can offer a search box with click-to-scroll.
//
// Sources (mirrors cycleConversation's path patterns):
//   1. <cycle dir>/.llm_conversation.jsonl — the LLM turns (prompt/response/thinking)
//   2. data/journal.jsonl                  — stage/tool events, filtered to this
//      loop AND to this cycle's time window (ts >= the cycle's start)
//   3. <cycle dir>/step_errors.json        — the cycle's recorded step errors
//
// `type` narrows the sources: "llm" → conversation only, "stage" → journal only,
// "error" → step_errors only; empty/other → all three. Matching is
// case-insensitive over the salient text fields (prompt/response/thinking/note/
// error/skill). Results are capped at 50, each snippet ≤ 200 chars. Read-only,
// best-effort — a missing source contributes nothing, never an error.
package handler

import (
	"bufio"
	"encoding/json"
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
	ok(c, "ok", gin.H{
		"app": app, "loop": loop, "ts": ts,
		"q": q, "type": kind,
		"matches": matches, "count": len(matches), "capped": capped,
	})
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
