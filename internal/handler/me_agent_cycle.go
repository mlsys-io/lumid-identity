package handler

import (
	"encoding/json"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// recordChatCycle turns an app-grounded chat turn into a RUN RECORD.
//
// The gap this closes: an app's loop is declared `@trigger` ("it runs when you
// talk"), and the app's own Workflows page tells the user each turn is one
// cycle that lands in their daily feed. It wasn't true. Chat called the app's
// tools directly inside identity and never produced a run, so `me://today`
// reported 0 cycles, `last_run_ts` stayed null, and the trajectory view was
// permanently empty — there was nothing to visualise, inspect or measure.
//
// Why a DB row and not a journal line: the file path (`data/journal.jsonl` under
// the tenant apps dir) lives on the scheduler's PVC, which identity does not
// mount. Writing into the materialised bundle cache instead would be silently
// discarded on its next refresh — that cache is deliberately read-only. So the
// record goes where the other cross-node state already went (MeChat, MeDraft):
// MySQL, via models.MeAppRun, which is exactly the app-agnostic run record the
// trajectory and experiments surfaces already read.
//
// Idempotent on (user_sub, app, loop, run_ts), matching InternalAppRunRecord —
// the scheduler's self-report and a chat turn write the same shape, so one
// history is assembled from both rather than two that disagree.
func recordChatCycle(userSub, app, loop, model string, toolCalls []toolCallResult, startedAt time.Time) {
	if common.DB == nil || userSub == "" || app == "" {
		return
	}
	if loop == "" {
		return
	}
	dur := time.Since(startedAt).Seconds()
	metrics := chatCycleMetrics(toolCalls)
	mj := "{}"
	if raw, err := json.Marshal(metrics); err == nil {
		mj = string(raw)
	}
	row := models.MeAppRun{
		UserSub: userSub, App: app, Loop: loop, RunTs: startedAt.Unix(),
		Model: model, Ok: true, DurationS: &dur, Metrics: mj,
		// Distinguishable from a scheduled run: a turn is one interactive cycle,
		// and a reader that averages them with batch runs should be able to tell.
		Source: "chat",
	}
	// `loop` is a MySQL reserved word — backtick-quote it in raw SQL.
	_ = common.DB.Where("user_sub = ? AND app = ? AND `loop` = ? AND run_ts = ?",
		userSub, app, loop, row.RunTs).Assign(row).FirstOrCreate(&models.MeAppRun{}).Error
}

// chatCycleMetrics summarises what the turn actually did, from the tool calls it
// made. Kept to facts the tools themselves reported — no inference about
// quality, because an unearned metric is worse than an absent one.
func chatCycleMetrics(toolCalls []toolCallResult) map[string]any {
	m := map[string]any{"interactive": true}
	tools := []string{}
	failed := 0
	for _, tc := range toolCalls {
		if tc.Name == "" {
			continue
		}
		tools = append(tools, tc.Name)
		if !tc.OK {
			failed++
		}
		res := tc.Result
		if res == nil {
			continue
		}
		// The app's answer tool reports which case it worked and whether the
		// score was ground-truth backed. Those are the two facts a scorecard
		// needs, and the only ones we can state without guessing.
		if v, ok := res["case_id"].(string); ok && v != "" {
			m["case_id"] = v
		}
		if v, ok := res["mode"].(string); ok && v != "" {
			m["mode"] = v
		}
		if v, ok := res["grounded"].(bool); ok {
			m["grounded"] = v
		}
		// A dispatched ARM, when the turn queued one. Mirrors what the
		// scheduler's _self_report_run stamps, so an arm dispatched from chat
		// and one dispatched from the panel are countable together in the one
		// cross-tenant store (me_app_runs) — the per-tenant ledger cannot be
		// aggregated across tenants at all.
		if v, ok := res["arm"].(string); ok && v != "" {
			m["arm"] = v
		}
		if v, ok := res["experiment"].(string); ok && v != "" {
			m["experiment"] = v
		}
		if v, ok := res["score"].(float64); ok {
			m["score"] = v
		}
		// The judge already resolves which QUESTION it scored (total_scope — the
		// matched question id, or "case") and the per-axis breakdown. Both were
		// computed and thrown away, which is why the Results surface could only
		// offer a blank per-axis column and said so in its own prose. A scorecard
		// needs a row label and the axes; these are them.
		if v, ok := res["total_scope"].(string); ok && v != "" {
			m["q_id"] = v
		}
		if v, ok := res["axes"]; ok && v != nil {
			m["axes"] = v
		}
		// Panel shape travels with the score or it cannot be read honestly later:
		// a number from one surviving seat is a different object from one two
		// seats agreed on, and only the turn that produced it knows which.
		// Accept both shapes: the tool sets an int in-process, but anything that
		// round-trips this map through JSON hands back a float64, and a type
		// assertion that only knows one of them drops the field silently.
		switch v := res["panel_n"].(type) {
		case int:
			m["panel_n"] = v
		case float64:
			m["panel_n"] = int(v)
		}
		if v, ok := res["independent"].(bool); ok {
			m["independent"] = v
		}
		// Who ANSWERED. Interviewer mode scores the human; benchmark mode scores
		// the analyst. Averaging the two together is exactly the corruption
		// commands/_session.py::summary's single_subject logic exists to prevent,
		// and without this field the chat path has no way to tell them apart.
		if v, ok := res["subject"].(string); ok && v != "" {
			m["subject"] = v
		}
	}
	if len(tools) > 0 {
		m["tools"] = strings.Join(tools, ",")
	}
	if failed > 0 {
		m["failed_tools"] = failed
	}
	return m
}

// triggerLoopFor returns the app's @trigger loop — the one whose contract is
// "runs when you talk". A chat turn is a cycle of THAT loop; recording it
// against a scheduled loop would corrupt that schedule's run history. Empty
// when the app declares no trigger loop, which is the signal not to record.
//
// Reads the PUBLISHED spec via fetchRepoSpecYAML, the same cross-node fallback
// the workflow rows use — identity does not mount the scheduler's PVC, so the
// local file is usually absent — and parses it with readYamlLoopsBytes rather
// than growing a second loops[] parser that could disagree with the first.
func triggerLoopFor(userSub, app string) string {
	spec, ok := fetchRepoSpecYAML(userSub, app)
	if !ok {
		return ""
	}
	loops, err := readYamlLoopsBytes(spec)
	if err != nil {
		return ""
	}
	for _, l := range loops {
		if strings.EqualFold(strings.TrimSpace(l.Schedule), "@trigger") {
			return l.Name
		}
	}
	return ""
}
