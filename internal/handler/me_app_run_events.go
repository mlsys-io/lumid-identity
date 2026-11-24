package handler

// Per-step run events — the step timeline a cloud run self-reports.
//
// The cycle dir (step_log.json, one <step>.json per step) lives on the
// scheduler's volume, which identity does not mount. So a cloud run reached the
// Studio run page with no steps at all, or — through the scheduler read — as a
// single `engine_command` step with no stage and no timing. The runner now
// sends one entry per step inside the existing `events` object:
//
//	events: {offers, step_errors, outcome, reason,          // unchanged
//	         steps: [{step_id, stage, kind, started_at, ended_at, ok, summary}],
//	         steps_dropped: N}                               // only when capped
//
// NESTED in `events`, not a new column and not a top-level list: the column
// already exists (no migration), and runRowFromStore unmarshals it as an OBJECT
// to find a failed run's reason — a list there would silently drop that reason.
//
// Bounded here as well as at the producer: this column is written by a bridge
// caller, and a limit that only exists on the other side of the wire is not a
// limit.

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	runStepEventsMax       = 200
	runStepSummaryMaxRunes = 200
	runStepIDMaxRunes      = 128
	// The non-step part of events keeps its original 16 KiB ceiling; the
	// whole column (steps included) is held under 48 KiB of a 64 KiB TEXT.
	runEventsLegacyMaxBytes = 16 * 1024
	runEventsMaxBytes       = 48 * 1024
)

var (
	runStepStages = map[string]bool{"observe": true, "hypothesize": true, "act": true, "analyze": true, "learn": true}
	runStepKinds  = map[string]bool{"llm": true, "tool": true, "stage": true, "command": true}
)

// runStepEvent is one step of a run as the runner reported it.
type runStepEvent struct {
	StepID    string   `json:"step_id"`
	Stage     *string  `json:"stage"`
	Kind      string   `json:"kind"`
	StartedAt *float64 `json:"started_at"`
	EndedAt   *float64 `json:"ended_at"`
	OK        bool     `json:"ok"`
	Summary   string   `json:"summary"`
}

func clipRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func epochOrNil(v any) *float64 {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 {
		return nil
	}
	return &f
}

// sanitizeRunStepEvents keeps only well-formed entries, whitelisting every
// field: an unknown stage or kind is normalised rather than stored verbatim.
func sanitizeRunStepEvents(raw []any) []runStepEvent {
	out := make([]runStepEvent, 0, len(raw))
	for _, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		sid, _ := m["step_id"].(string)
		sid = clipRunes(sid, runStepIDMaxRunes)
		if sid == "" {
			continue
		}
		e := runStepEvent{StepID: sid, Kind: "tool", OK: true}
		if s, _ := m["stage"].(string); runStepStages[strings.ToLower(strings.TrimSpace(s))] {
			st := strings.ToLower(strings.TrimSpace(s))
			e.Stage = &st
		}
		if k, _ := m["kind"].(string); runStepKinds[k] {
			e.Kind = k
		}
		e.StartedAt = epochOrNil(m["started_at"])
		e.EndedAt = epochOrNil(m["ended_at"])
		if b, ok := m["ok"].(bool); ok {
			e.OK = b
		}
		if s, _ := m["summary"].(string); s != "" {
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[:i]
			}
			e.Summary = clipRunes(s, runStepSummaryMaxRunes)
		}
		out = append(out, e)
	}
	return out
}

// capRunStepEvents bounds the list by count, then by bytes. Same policy as the
// producer: keep the head and the LAST event (usually where a run died); over
// the byte budget, blank successful steps' summaries before dropping any.
func capRunStepEvents(evs []runStepEvent, budget int) ([]runStepEvent, int) {
	n0 := len(evs)
	if len(evs) > runStepEventsMax {
		evs = append(append([]runStepEvent{}, evs[:runStepEventsMax-1]...), evs[len(evs)-1])
	}
	size := func() int { b, _ := json.Marshal(evs); return len(b) }
	if size() > budget {
		for i := range evs {
			if evs[i].OK {
				evs[i].Summary = ""
			}
		}
	}
	for len(evs) > 1 && size() > budget {
		evs = append(evs[:len(evs)-2], evs[len(evs)-1])
	}
	if len(evs) > 0 && size() > budget {
		evs = nil
	}
	return evs, n0 - len(evs)
}

// normalizeRunEvents is the write half: what goes into me_app_runs.events.
// nil means "nothing to store" (the caller then leaves an earlier value alone).
func normalizeRunEvents(v any) *string {
	if v == nil {
		return nil
	}
	m, isObj := v.(map[string]any)
	if !isObj {
		// Not the object shape — the original behaviour, unchanged.
		raw, err := json.Marshal(v)
		if err != nil || len(raw) <= 2 {
			return nil
		}
		e := string(raw)
		if len(e) > runEventsLegacyMaxBytes {
			e = `{"_truncated":true,"_bytes":` + strconv.Itoa(len(raw)) + `}`
		}
		return &e
	}
	rest := make(map[string]any, len(m))
	for k, x := range m {
		if k != "steps" && k != "steps_dropped" {
			rest[k] = x
		}
	}
	var steps []runStepEvent
	if arr, ok := m["steps"].([]any); ok {
		steps = sanitizeRunStepEvents(arr)
	}
	dropped := 0
	if f, ok := m["steps_dropped"].(float64); ok && f > 0 && f < 1e9 {
		dropped = int(f)
	}
	restRaw, err := json.Marshal(rest)
	if err != nil {
		return nil
	}
	var obj map[string]any
	if len(restRaw) > runEventsLegacyMaxBytes {
		// Same marker as before for the legacy part — but the step timeline
		// is no longer lost along with it.
		obj = map[string]any{"_truncated": true, "_bytes": len(restRaw)}
	} else {
		obj = rest
	}
	if len(steps) > 0 {
		base, _ := json.Marshal(obj)
		// room for `,"steps":` + `,"steps_dropped":N`
		budget := runEventsMaxBytes - len(base) - 64
		kept, d := capRunStepEvents(steps, budget)
		dropped += d
		if len(kept) > 0 {
			obj["steps"] = kept
		}
		if dropped > 0 {
			obj["steps_dropped"] = dropped
		}
	}
	if len(obj) == 0 {
		return nil
	}
	raw, err := json.Marshal(obj)
	if err != nil || len(raw) <= 2 {
		return nil
	}
	e := string(raw)
	return &e
}

// runStepEventsFromColumn is the read half: the step list in a stored events
// column, or nil when the run reported none (older runners, legacy shapes).
func runStepEventsFromColumn(raw *string) []runStepEvent {
	if raw == nil || *raw == "" {
		return nil
	}
	var ev struct {
		Steps []any `json:"steps"`
	}
	if json.Unmarshal([]byte(*raw), &ev) != nil || len(ev.Steps) == 0 {
		return nil
	}
	evs := sanitizeRunStepEvents(ev.Steps)
	if len(evs) > runStepEventsMax {
		evs, _ = capRunStepEvents(evs, runEventsMaxBytes)
	}
	return evs
}

// cycleRunStepEvents returns the caller's OWN recorded step events for one
// cycle. Owner-scoped by user_sub, same predicate as cycleComputeJobs.
func cycleRunStepEvents(userID, app, loop, ts string) []runStepEvent {
	runTs, ok := cycleIDToRunTs(ts)
	if !ok || userID == "" || common.DB == nil {
		return nil
	}
	var row models.MeAppRun
	if err := common.DB.Select("events").
		Where("user_sub = ? AND app IN ? AND `loop` = ? AND run_ts = ?", // loop is reserved
			userID, appAliases(app), loop, runTs).
		Take(&row).Error; err != nil {
		return nil
	}
	return runStepEventsFromColumn(row.Events)
}

// cycleStepsFromRunEvents maps the timeline into the inspector's step shape,
// so the existing UI shows real step names and states when no cycle dir can
// be read.
func cycleStepsFromRunEvents(evs []runStepEvent) []cycleStep {
	out := make([]cycleStep, 0, len(evs))
	for _, e := range evs {
		s := cycleStep{StepID: e.StepID, OK: e.OK}
		if e.Stage != nil {
			s.Stage = *e.Stage
		}
		if e.StartedAt != nil && e.EndedAt != nil && *e.EndedAt >= *e.StartedAt {
			s.Duration = *e.EndedAt - *e.StartedAt
		}
		if e.OK {
			s.OutputSummary = e.Summary
		} else {
			s.Error = e.Summary
		}
		out = append(out, s)
	}
	return out
}

// hasNoSteps reports whether a detail payload carries no steps.
func hasNoSteps(data gin.H) bool {
	switch s := data["steps"].(type) {
	case nil:
		return true
	case []cycleStep:
		return len(s) == 0
	case []any:
		return len(s) == 0
	}
	return false
}

// composeCycleDetail is MeCycleDetail's response, given what each source
// returned. Pure, so the shapes are testable without auth, disk or a store.
// A nil result means 404.
//
//   - events present: returned as `events`; mapped into `steps` when the cycle
//     dir gave none (unreadable, or read but empty).
//   - events absent: the response is exactly what it was before.
//   - dir not found AND no "unavailable" reason, but the store recorded a
//     timeline: that run happened, so it is served from the store rather
//     than 404'd.
func composeCycleDetail(app, loop, ts string, data gin.H, found bool, why string,
	jobs []computeJobRef, evs []runStepEvent) gin.H {
	if !found {
		if why == "" && len(evs) == 0 {
			return nil
		}
		data = gin.H{"app": app, "loop": loop, "ts": ts, "steps": []any{}}
		if why != "" {
			data["unavailable"] = why
		} else {
			data["source"] = "run_store"
		}
	}
	data["compute_jobs"] = jobs
	if len(evs) > 0 {
		data["events"] = evs
		if hasNoSteps(data) {
			data["steps"] = cycleStepsFromRunEvents(evs)
			data["steps_source"] = "run_store"
		}
	}
	return data
}
