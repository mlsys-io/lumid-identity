package handler

import (
	"fmt"
	"strings"
)

// Canonical chat tools — the verb contract (LumidOS docs/architecture/VERBS.md)
// applied to the Studio chat: <noun>_<verb>, eight verbs, modes as parameters.
//
//	workflow_get     one workflow, the list, or their health
//	workflow_run     run now, or queue one of a study's experiments
//	workflow_define  enable / pause / reschedule
//	workflow_cancel  stop an in-flight run
//	run_get          the runs list, one run, or a queued job's result
//	run_feedback     every verdict on a run: rate it, promote/discard it,
//	                 approve/revamp/dismiss its held step, branch from it
//
// They replace run_loop_now, dispatch_experiment_arm, stop_loop, patch_loop,
// list_workflows, workflow_detail, loops_health, list_runs, run_detail,
// run_result, run_promote, run_discard, give_feedback, review_action and
// branch_run, which stay dispatchable (an in-flight prompt that names one keeps
// working) but are no longer advertised.
//
// RESOLVED FIRST, NOT RE-IMPLEMENTED. Each canonical call is translated into
// the old tool it stands for BEFORE any gate runs — run approval
// (runDispatchTools), destructive approval and "Always" grants
// (destructiveTools), data-scope refetch (toolDataScopes), and the dispatchTool
// backstop are all keyed on the tool name. Translating late would let
// run_feedback reach run_promote without the approval run_promote requires.
// One implementation per job; these names are only the grammar in front of it.

// canonicalToolDefs are the tool schemas the model sees.
func canonicalToolDefs() []map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	obj := func(desc string) map[string]any { return map[string]any{"type": "object", "description": desc} }
	return []map[string]any{
		{
			"name": "workflow_run",
			"description": "Run one of the user's workflows. mode \"now\" (default) fires one run immediately — when the user asks to run a workflow, call this in the same turn. " +
				"mode \"queue\" queues runs of one experiment of a study (study + experiment + samples). Pass the workflow's own parameters in `args` — the SUBJECT of the run; many workflows do nothing useful without them (quant-research's backtest needs {\"action\":\"submit\",\"symbol\":…,\"strategy\":…}). " +
				"Do NOT run to answer a question — read results with run_get instead.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent":      str("the installed agent (app) name"),
					"workflow":   str("the workflow (loop) name"),
					"mode":       map[string]any{"type": "string", "enum": []string{"now", "queue"}},
					"args":       obj("the workflow's invocation args (its {{ args.* }})"),
					"cases":      str("optional item scope: an id or comma-separated ids"),
					"study":      str("mode queue: the study id"),
					"experiment": str("mode queue: the experiment of that study to run"),
					"samples":    map[string]any{"type": "integer", "description": "mode queue: runs to queue (default 1, max 20)"},
				},
				"required": []string{"agent"},
			},
		},
		{
			"name":        "workflow_get",
			"description": "Read the user's workflows. With agent+workflow: that workflow's detail. Without: the list; view \"health\" gives status (ok|failing|stale|never|manual), consecutive failures and last error for every workflow.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent":    str("agent (app) name"),
					"workflow": str("workflow (loop) name"),
					"view":     map[string]any{"type": "string", "enum": []string{"list", "health"}},
					"kind":     map[string]any{"type": "string", "description": "list filter: scheduled | visual"},
				},
			},
		},
		{
			"name":        "workflow_define",
			"description": "Change a workflow's definition: enabled=false pauses it, enabled=true resumes, schedule sets its cron.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent":    str("agent (app) name"),
					"workflow": str("workflow (loop) name"),
					"enabled":  map[string]any{"type": "boolean"},
					"schedule": str("cron expression"),
				},
				"required": []string{"agent", "workflow"},
			},
		},
		{
			"name":        "workflow_cancel",
			"description": "Stop a workflow's in-flight run.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent":    str("agent (app) name"),
					"workflow": str("workflow (loop) name"),
				},
				"required": []string{"agent", "workflow"},
			},
		},
		{
			"name":        "run_get",
			"description": "Read runs. With id: that run's detail (a run id like scheduled:<agent>:<workflow>:<ts>) or, for the job_id workflow_run returned, that queued run's result. Without id: recent runs, filterable by workflow and state.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":       str("run id, or the job_id workflow_run returned"),
					"workflow": str("list filter: <agent>:<workflow>"),
					"state":    str("list filter: succeeded | failed | running | skipped | canceled"),
					"limit":    map[string]any{"type": "integer"},
				},
			},
		},
		{
			"name": "run_feedback",
			"description": "Record the user's verdict on a run. Call it whenever the user says something evaluative about a result — quote them in `note`. " +
				"verdict good|bad|neutral rates the run (the ts part of the id may be \"latest\"); " +
				"promote marks it the chosen branch, discard greys it out; " +
				"approve|revamp|dismiss answers the run's held step (revamp needs step_instructions); " +
				"branch starts a new experiment from this run, `note` saying what it should explore and `config` its overrides. " +
				"promote, discard, approve/revamp/dismiss and branch need the user's approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": str("run id: scheduled:<agent>:<workflow>:<ts>"),
					"verdict": map[string]any{"type": "string", "enum": []string{
						"good", "bad", "neutral", "promote", "discard", "approve", "revamp", "dismiss", "branch"}},
					"note":              str("the user's words: why, or (branch) what the new experiment should explore"),
					"step_id":           str("approve|revamp|dismiss: the held step"),
					"step_instructions": str("revamp: the new instructions for that step"),
					"outbox_ref":        str("approve: the held item's outbox ref"),
					"config":            obj("branch: config overrides for the new experiment"),
				},
				"required": []string{"id", "verdict"},
			},
		},
	}
}

// supersededChatTools maps each old tool to the canonical one that replaces it.
// Hidden from the catalog; still dispatchable.
var supersededChatTools = map[string]string{
	"run_loop_now":            "workflow_run",
	"dispatch_experiment_arm": "workflow_run",
	"stop_loop":               "workflow_cancel",
	"patch_loop":              "workflow_define",
	"list_workflows":          "workflow_get",
	"workflow_detail":         "workflow_get",
	"loops_health":            "workflow_get",
	"list_runs":               "run_get",
	"run_detail":              "run_get",
	"run_result":              "run_get",
	"run_promote":             "run_feedback",
	"run_discard":             "run_feedback",
	"give_feedback":           "run_feedback",
	"review_action":           "run_feedback",
	"branch_run":              "run_feedback",
}

func argStr(args map[string]any, k string) string {
	s, _ := args[k].(string)
	return strings.TrimSpace(s)
}

// copyArgs copies the named keys that are present.
func copyArgs(dst, src map[string]any, keys ...string) {
	for _, k := range keys {
		if v, ok := src[k]; ok {
			dst[k] = v
		}
	}
}

// resolveCanonicalTool translates a canonical tool call into the tool that
// implements it. Any other name passes through unchanged. An error means the
// canonical call is malformed; it never dispatches.
func resolveCanonicalTool(name string, args map[string]any) (string, map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	out := map[string]any{}
	switch name {
	case "workflow_run":
		if argStr(args, "mode") == "queue" {
			copyArgs(out, args, "samples", "cases", "args")
			out["app"] = argStr(args, "agent")
			out["experiment"] = argStr(args, "study")
			out["arm"] = argStr(args, "experiment")
			if out["experiment"] == "" || out["arm"] == "" {
				return "", nil, fmt.Errorf("workflow_run mode \"queue\" needs study and experiment")
			}
			if w := argStr(args, "workflow"); w != "" {
				out["loop"] = w
			}
			return "dispatch_experiment_arm", out, nil
		}
		copyArgs(out, args, "args", "cases")
		out["app"], out["loop"] = argStr(args, "agent"), argStr(args, "workflow")
		if out["loop"] == "" {
			return "", nil, fmt.Errorf("workflow_run needs workflow (or mode \"queue\" with study and experiment)")
		}
		return "run_loop_now", out, nil
	case "workflow_get":
		agent, wf := argStr(args, "agent"), argStr(args, "workflow")
		if agent != "" && wf != "" {
			return "workflow_detail", map[string]any{"slug": agent + ":" + wf}, nil
		}
		if argStr(args, "view") == "health" {
			return "loops_health", out, nil
		}
		copyArgs(out, args, "kind")
		return "list_workflows", out, nil
	case "workflow_define":
		copyArgs(out, args, "enabled", "schedule")
		out["app"], out["loop"] = argStr(args, "agent"), argStr(args, "workflow")
		return "patch_loop", out, nil
	case "workflow_cancel":
		return "stop_loop", map[string]any{"app": argStr(args, "agent"), "loop": argStr(args, "workflow")}, nil
	case "run_get":
		id := argStr(args, "id")
		switch {
		case id == "":
			copyArgs(out, args, "workflow", "state", "limit")
			return "list_runs", out, nil
		case strings.Contains(id, ":"):
			return "run_detail", map[string]any{"run_id": id}, nil
		default:
			return "run_result", map[string]any{"job_id": id}, nil
		}
	case "run_feedback":
		verdict := argStr(args, "verdict")
		parts := strings.SplitN(argStr(args, "id"), ":", 4)
		if len(parts) != 4 || parts[0] != "scheduled" || parts[1] == "" || parts[2] == "" || parts[3] == "" {
			return "", nil, fmt.Errorf("run_feedback needs a scheduled run id: scheduled:<agent>:<workflow>:<ts>")
		}
		app, loop, ts := parts[1], parts[2], parts[3]
		switch verdict {
		case "promote", "discard":
			return "run_" + verdict, map[string]any{"app": app, "loop": loop, "ts": ts}, nil
		case "good", "bad", "neutral":
			rating := map[string]int{"good": 1, "bad": -1, "neutral": 0}[verdict]
			return "give_feedback", map[string]any{"app": app, "loop": loop, "ts": ts, "rating": rating, "note": argStr(args, "note")}, nil
		case "approve", "revamp", "dismiss":
			if verdict == "revamp" && argStr(args, "step_instructions") == "" {
				return "", nil, fmt.Errorf("run_feedback verdict \"revamp\" needs step_instructions")
			}
			copyArgs(out, args, "step_id", "step_instructions", "outbox_ref")
			out["app"], out["loop"], out["decision"] = app, loop, verdict
			return "review_action", out, nil
		case "branch":
			if argStr(args, "note") == "" {
				return "", nil, fmt.Errorf("run_feedback verdict \"branch\" needs a note saying what to explore")
			}
			out = map[string]any{"app": app, "loop": loop, "from_ts": ts, "note": argStr(args, "note")}
			if cfg, ok := args["config"].(map[string]any); ok && len(cfg) > 0 {
				out["variant"] = cfg
			}
			return "branch_run", out, nil
		}
		return "", nil, fmt.Errorf("run_feedback verdict must be good, bad, neutral, promote, discard, approve, revamp, dismiss or branch")
	}
	return name, args, nil
}
