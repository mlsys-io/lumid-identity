package handler

import (
	"fmt"
	"strings"
)

// Per-surface capability summary (FLB-QR-07).
//
// The same sentence behaves differently in Studio, the Data Warehouse chat and
// an app's chat rail because each gets a different tool catalog — role gates,
// Simple mode's allowlist, a persona's AllowedTools. Nothing told the model
// (or, through it, the user) what THIS chat can do, so a request the surface
// could not serve was answered by several minutes of searching instead of one
// sentence naming what is missing. The summary is derived from the FINAL tool
// list, after every filter, so it cannot claim a capability the turn lacks.

type chatCapability struct {
	label string
	// any of these tools grants the capability
	tools []string
	// where to send the user when this chat lacks it
	elsewhere string
}

var chatCapabilities = []chatCapability{
	{"Query FinData (markets, prices, SQL)", []string{"query_findata", "data_query"}, "the Data Warehouse chat"},
	{"Resolve the user's registered strategies (name -> strategy_id)", []string{"app_read"}, "Quant Research → Strategies"},
	{"Submit backtests / run an app's workflows", []string{"workflow_run"}, "the app's own page (e.g. a strategy row's Backtest)"},
	{"Read LQT decision history for a strategy (strategy_cycles)", []string{"lqt_mailbox_read"}, "a strategy's Discuss chat in Quant Research (full tool view)"},
	{"Deploy a strategy to LQT", []string{"lqt_mailbox_submit"}, "Quant Research → Strategies → Register"},
	{"Add a shared skill to an installed app", []string{"add_skill_to_workflow"}, "the marketplace's 'Add to app…'"},
	{"Run jobs on the GPU fleet (FlowMesh / Lumilake)", []string{"submit_workflow", "optimize_workflow"}, "an operator"},
	{"Search the web", []string{"web_search"}, ""},
}

// capabilityHint renders the summary for the tools this turn actually has.
// Empty when there are no tools (the claude-code path brings its own).
func capabilityHint(tools []map[string]any) string {
	if len(tools) == 0 {
		return ""
	}
	have := make(map[string]bool, len(tools))
	for _, d := range tools {
		if n, _ := d["name"].(string); n != "" {
			have[n] = true
		}
	}
	var b strings.Builder
	b.WriteString("\n\n## What this chat can do (derived from your tools this turn)\n")
	for _, c := range chatCapabilities {
		yes := false
		for _, t := range c.tools {
			if have[t] {
				yes = true
				break
			}
		}
		if yes {
			fmt.Fprintf(&b, "- %s: yes\n", c.label)
		} else if c.elsewhere != "" {
			fmt.Fprintf(&b, "- %s: NO here — available in %s\n", c.label, c.elsewhere)
		} else {
			fmt.Fprintf(&b, "- %s: NO here\n", c.label)
		}
	}
	b.WriteString("If the user asks for something marked NO, say so in one sentence and name where it " +
		"is available — do not search other tools or files for a workaround. If a tool call is " +
		"refused or fails twice for the same reason, stop and report the exact error and what " +
		"would fix it (a permission, an id, a surface) instead of trying unrelated tools. " +
		"When the user asks what you can do here, answer from this list.\n")
	return b.String()
}
