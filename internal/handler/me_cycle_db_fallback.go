package handler

// Reconstructing the cycle/run history from the RUN STORE.
//
// Identity mounts exactly one volume — the signing keys — so every handler that
// walks data/cycles or data/journal.jsonl returns empty for every app and every
// user. Measured 2026-09-13: cycle-log total 0, /me/cycles 0, /me/runs 0.
// resolveAppDir hides it rather than helping: it falls through to
// materialiseTenantApp, which supplies the PUBLISHED bundle (specs, prompts,
// cases), so nothing 404s while every RUNTIME artifact is absent.
//
// The consequences are not subtle. `tenantHasRuns` is derived from /me/cycles,
// and in WorkflowObservabilityPanel it gates the FailureCard, the step-error
// pill, StageDetail and `lastRan` — and health() short-circuits to "Not run yet"
// without it. So every workflow renders the truth for ~200ms (from the
// DB-backed last_run_ok on the workflow row) and is then overwritten by "Not run
// yet" for good, and a FAILED cycle is indistinguishable from one that never
// happened.
//
// me_app_runs has the universal half of every cycle — when, which loop, ok,
// duration, the metrics blob and (since the same change) cost. That is enough
// for the list and the run tree. It is NOT enough for the per-step drill-down or
// the transcript, which live only in the cycle dir; those degrade honestly
// instead (see the `unavailable` reason on the detail/log handlers).
//
// MeTrajectory has done exactly this since 2026-09-05 (me_trajectory.go:497) for
// the same reason. This generalises it rather than inventing a second answer.

import (
	"encoding/json"
	"time"

	"lumid_identity/models"

	"lumid_identity/internal/common"
)

// runTsToCycleID renders a run-store timestamp as the cycle-dir id every other
// surface parses (20260914T010203Z).
//
// The store holds unix seconds; the UI's date parsers (fmtWhen, cycleDate) only
// understand the dir-id form and return null for a decimal epoch — which is why
// DB-reconstructed trajectory nodes render with no timestamp at all. Converting
// here means one shape reaches every consumer.
func runTsToCycleID(runTs int64) string {
	if runTs <= 0 {
		return ""
	}
	// Anything below ~1971 is not a unix second; treat it as already-an-id that
	// overflowed into the column rather than inventing a 1970 date.
	if runTs < 31_536_000 {
		return ""
	}
	return time.Unix(runTs, 0).UTC().Format("20060102T150405Z")
}

// cycleRowsFromDB builds cycleListItems from the run store. `appFilter` and
// `loopFilter` may be empty.
func cycleRowsFromDB(userSub, appFilter, loopFilter string) []cycleListItem {
	if userSub == "" || common.DB == nil {
		return nil
	}
	var rows []models.MeAppRun
	q := common.DB.Where("user_sub = ?", userSub)
	if appFilter != "" {
		q = q.Where("app IN ?", appAliases(appFilter))
	}
	if loopFilter != "" {
		q = q.Where("`loop` = ?", loopFilter) // reserved word — backtick-quote
	}
	if q.Order("run_ts DESC").Limit(500).Find(&rows).Error != nil {
		return nil
	}
	out := make([]cycleListItem, 0, len(rows))
	for _, r := range rows {
		if item, ok := cycleRowFromStore(r); ok {
			out = append(out, item)
		}
	}
	return out
}

// cycleRowFromStore builds ONE list item from ONE store row.
//
// Split out so it can be exercised — and compared against the disk path's
// converter — without a database. A shape assertion that restates what the
// producer does instead of calling it only guards the side it calls.
func cycleRowFromStore(r models.MeAppRun) (cycleListItem, bool) {
	ts := runTsToCycleID(r.RunTs)
	if ts == "" {
		return cycleListItem{}, false
	}
	item := cycleListItem{App: r.App, Loop: r.Loop, Ts: ts, OK: r.Ok}
	if r.DurationS != nil {
		item.Duration = *r.DurationS
	}
	var m map[string]any
	if r.Metrics != "" && json.Unmarshal([]byte(r.Metrics), &m) == nil {
		if cost, ok := m["cost"].(map[string]any); ok {
			if v, ok := cost["cost_usd"].(float64); ok {
				item.CostUSD = v
			}
			if v, ok := cost["total_tokens"].(float64); ok {
				item.TotalTokens = v
			}
		}
		if v, ok := m["branch_label"].(string); ok {
			item.BranchLabel = v
		}
		if v, ok := m["parent_run_id"].(string); ok {
			item.ParentRunID = v
		}
	}
	// StepCount and Running stay zero/false on purpose. The store has no
	// per-step rows, and a run still in flight has not reported yet — claiming
	// either would be inventing detail the source lacks.
	return item, true
}

// mergeCycleRows appends DB rows the disk walk did not already produce.
//
// Both sources, not one: an operator install running on the scheduler's own
// volume really is readable here and carries step counts and in-flight state
// the store cannot. Disk wins on a collision for exactly that reason — it is the
// richer record of the same cycle, not a different one.
func mergeCycleRows(disk, db []cycleListItem) []cycleListItem {
	seen := make(map[string]bool, len(disk))
	for _, d := range disk {
		seen[d.App+"\x00"+d.Loop+"\x00"+d.Ts] = true
	}
	out := disk
	for _, d := range db {
		if seen[d.App+"\x00"+d.Loop+"\x00"+d.Ts] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// runRowsFromDB is the /me/runs half of the same reconstruction.
//
// collectRuns had exactly one non-disk source — the n8n executions API — so on
// a cloud pod the endpoint could only ever return VISUAL runs. Every scheduled
// cycle the platform ran was missing, which is what made the Home rail's "Run
// failed → Diagnose" row the only place in the product where a failure was
// visible at all.
func runRowsFromDB(userSub string, since, until time.Time) []RunRow {
	if userSub == "" || common.DB == nil {
		return nil
	}
	var rows []models.MeAppRun
	q := common.DB.Where("user_sub = ? AND run_ts >= ? AND run_ts <= ?",
		userSub, since.Unix(), until.Unix())
	if q.Order("run_ts DESC").Limit(500).Find(&rows).Error != nil {
		return nil
	}
	out := make([]RunRow, 0, len(rows))
	for _, r := range rows {
		if row, ok := runRowFromStore(r); ok {
			out = append(out, row)
		}
	}
	return out
}

// runRowFromStore builds ONE RunRow from ONE store row.
//
// Every field has to match journalRowToRun's shape for the same cycle, or a run
// both sources know about appears twice with the two rows disagreeing about
// what it is called. WorkflowSlug is "app:loop", not the bare loop; Name is the
// loop; StartedISO is the cycle id, not RFC3339.
func runRowFromStore(r models.MeAppRun) (RunRow, bool) {
	ts := runTsToCycleID(r.RunTs)
	if ts == "" {
		return RunRow{}, false
	}
	row := RunRow{
		RunID:        "scheduled:" + r.App + ":" + r.Loop + ":" + ts,
		WorkflowSlug: r.App + ":" + r.Loop,
		Kind:         "scheduled",
		Name:         r.Loop,
		App:          r.App,
		State:        "succeeded",
		StartedAt:    float64(r.RunTs),
		StartedISO:   ts,
	}
	if !r.Ok {
		// THE POINT OF THIS WHOLE FILE. A failed cycle used to be
		// indistinguishable from one that never happened, at every surface
		// except the Home rail.
		row.State = "failed"
	}
	// The error text behind the failure, so FailureCard has something to render.
	// Without it a failed run states only that it failed — which is where the
	// reader was already.
	if r.Events != nil && *r.Events != "" {
		var ev struct {
			StepErrors []string `json:"step_errors"`
			Outcome    string   `json:"outcome"`
			Reason     string   `json:"reason"`
		}
		if json.Unmarshal([]byte(*r.Events), &ev) == nil {
			if len(ev.StepErrors) > 0 {
				row.Reason = ev.StepErrors[0]
			} else if ev.Reason != "" {
				row.Reason = ev.Reason
			} else if ev.Outcome != "" {
				row.Reason = ev.Outcome
			}
		}
	}
	if r.DurationS != nil {
		row.DurationSec = *r.DurationS
	}
	var m map[string]any
	if r.Metrics != "" && json.Unmarshal([]byte(r.Metrics), &m) == nil {
		// SPECIFIC BEATS TERSE — and this used to run the other way round:
		// `outcome` ("bad_cases") overwrote a step error already found above,
		// replacing the CAUSE with its CATEGORY.
		outcome, _ := m["outcome"].(string)
		if why := runFailureReason(m, outcome); why != "" &&
			(row.Reason == "" || row.Reason == outcome) {
			row.Reason = why
		}
		if cost, ok := m["cost"].(map[string]any); ok {
			if v, ok := cost["cost_usd"].(float64); ok {
				row.CostCents = v * 100
			}
		}
	}
	return row, true
}

// mergeRunRows appends store rows the disk walk did not already produce.
func mergeRunRows(disk, db []RunRow) []RunRow {
	seen := make(map[string]bool, len(disk))
	for _, d := range disk {
		seen[d.RunID] = true
	}
	out := disk
	for _, d := range db {
		if !seen[d.RunID] {
			out = append(out, d)
		}
	}
	return out
}

// runFailureReason — the most specific explanation a failed cycle offers.
//
// A failed run used to state only that it failed, which is where the reader
// already was. The explanation existed the whole time: the runtime writes it to
// .lumid/journal.jsonl AND self-reports it into me_app_runs.metrics, and both
// row builders dropped it on the floor.
//
// Measured 2026-09-16. Four scoped runs died with
//
//	metrics.command_engine.error =
//	  "unknown case id(s): ['Case_001_DieselTruck_PK20_v5']"
//
// — a stringified list, i.e. a platform bug — and the user saw a run that
// silently did nothing, four times, and reported it as "跑不起来" (won't run).
// It ran. It said why. Nothing showed it.
//
// Ordered most specific first, because the terse `outcome` code ("bad_cases")
// names a CATEGORY and the error names the CAUSE. runRowFromStore used to let
// outcome overwrite a step error it had already found, which is the same
// mistake in the other direction.
//
// Shared by both row builders deliberately: this file's own header warns that
// every field must match journalRowToRun "or a run both sources know about
// appears twice with the two rows disagreeing about what it is called".
func runFailureReason(metrics map[string]any, outcome string) string {
	if metrics != nil {
		if s, _ := metrics["error"].(string); s != "" {
			return s
		}
		// Pattern-C engines (a loop whose BODY is a compute DAG) nest theirs
		// under compute_engine. Without this a failed fleet dispatch surfaced as
		// its outcome string — measured 2026-09-21, a run refused by Lumilake
		// with "write on object-prefix/... denied" displayed as reason "ran",
		// which tells the reader nothing and looks like a success word.
		if ce, ok := metrics["compute_engine"].(map[string]any); ok {
			if s, _ := ce["error"].(string); s != "" {
				return s
			}
		}
		// Pattern-B engines nest their own result under command_engine.
		if ce, ok := metrics["command_engine"].(map[string]any); ok {
			if s, _ := ce["error"].(string); s != "" {
				return s
			}
			if inner, ok := ce["metrics"].(map[string]any); ok {
				if s, _ := inner["error"].(string); s != "" {
					return s
				}
			}
		}
	}
	return outcome
}
