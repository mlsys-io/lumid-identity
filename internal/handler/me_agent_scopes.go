package handler

// Server-authoritative tool → data-scope map (3a).
//
// When a mutating chat tool succeeds, the stream emits the data scopes it
// invalidated on the `tool_call` event; the frontend dispatches its
// `studio:data` refetch from THAT payload (chat/protocol.ts), falling back to
// its own client map only for older servers. Keeping the source of truth here
// means a NEW mutating tool refetches the right pages with no frontend change —
// closing the "forgot to wire the tool into TOOL_EFFECTS → stale UI" bug class.
//
// Scope vocabulary mirrors the frontend DataScope union (chat/effects.ts):
//   apps workflows loops runs cycles drafts knowledge config experiments users ui prompts
var toolDataScopes = map[string][]string{
	// loop / workflow execution + schedule
	"run_loop":     {"runs", "cycles", "loops", "workflows"},
	"run_loop_now": {"runs", "cycles", "loops", "workflows"},
	"patch_loop":   {"loops", "workflows"},
	"pause_workflow": {"loops", "workflows"},
	"delete_loop":  {"loops", "workflows", "apps"},
	// app lifecycle
	"install_app":            {"apps", "workflows", "loops"},
	"uninstall_app":          {"apps", "workflows", "loops"},
	"fork_app":               {"apps"},
	"app_update":             {"apps", "workflows"},
	"compose_workflow":       {"workflows", "drafts"},
	"add_skill_to_workflow":  {"workflows", "apps"},
	// drafts / inbox
	"send_draft":    {"drafts"},
	"edit_draft":    {"drafts"},
	"dismiss_draft": {"drafts"},
	// review + config
	"review_action":  {"cycles", "runs"},
	"app_config_set": {"apps", "config", "workflows"},
	// app-surface authoring (chat edits/regenerates a page) → re-render the
	// live surface + the app page.
	"app_ui_set":      {"ui", "apps", "config"},
	"app_ui_generate": {"ui", "apps", "config"},
	// run lifecycle (advisory markers the trajectory/run views read)
	"run_promote": {"runs", "cycles"},
	"run_discard": {"runs", "cycles"},
	// prompt editor (writes a local prompt-card override) → re-render the
	// prompts surface + the app page.
	"app_prompt_set":   {"prompts", "apps"},
	"app_prompt_reset": {"prompts", "apps"},
	// branch-with-intention records a control signal the run/lineage views read.
	"branch_run": {"runs", "cycles", "workflows"},
	// knowledge
	"xp_ingest":        {"knowledge"},
	"xp_feedback":      {"knowledge"},
	"subscribe_to_bank": {"knowledge"},
	// admin control plane
	"admin_set_user_role":   {"users"},
	"admin_set_user_status": {"users"},
	// generic app-ops bridge — a form-action/qa write can touch anything the
	// app owns, so invalidate the broad scopes the indexes/cards read.
	"app_action": {"apps", "workflows", "loops", "runs", "cycles", "drafts"},
	"qa_call":    {"apps", "workflows", "runs"},
}

// toolDataScopesFor returns the refetch scopes a successful call to `name`
// invalidated, or nil if the tool touches no cached data.
func toolDataScopesFor(name string) []string {
	return toolDataScopes[name]
}
