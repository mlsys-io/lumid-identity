package handler

// Generic "operate any app from the chat" bridge for the chat agent.
//
// Studio app surfaces are built from templates + API/CLI/MCP: every action a
// page exposes is a declared primitive (a `lumid:form action:` verb, a
// `submit_qa` endpoint, or a `me://`/`qa://` data source). These tools let the
// AI invoke those same primitives so anything a page can do, the chat can do —
// reusing the EXACT allowlists the UI already enforces:
//
//   app_actions(app?)        — discover an app's declared actions/sources (read)
//   app_read(source)         — GET an allowlisted data source              (read)
//   show_app_surface(app)    — render an app's surface inline in chat      (read)
//   app_ui_get(app,surface?) — read a surface's editable source            (read)
//   app_action(action,vals)  — invoke an allowlisted form-action      (APPROVAL)
//   qa_call(method,path,body)— invoke an allowlisted QuantArena write  (APPROVAL)
//   app_ui_set(app,...)      — write/replace a surface's source        (APPROVAL)
//   app_ui_generate(app)     — AI-generate a surface (page.yaml)        (APPROVAL)
//   run_promote(app,ts)      — mark a run as the chosen branch          (APPROVAL)
//   run_discard(app,ts)      — grey out a run                           (APPROVAL)
//
// Security: app_action reuses the formActions allowlist (me_form_action.go);
// app_read/qa_call mirror the directive resolver's scheme/path allowlist
// (directives.tsx); app_ui_set/app_ui_generate write ONLY to a surface in the
// caller's OWN tenant install (resolveOwnedAppDir refuses operator-shared apps),
// validate page specs through compilePageSpec, and honor the same optimistic
// lock as the UI editor; run_promote/run_discard shell the same lumid-trajectory
// CLI the UI uses, HOME-scoped to the tenant. Every mutating tool is in
// destructiveTools (approval-gated).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
)

// ── tool definitions (merged into buildToolDefs) ─────────────────────────────

func appOpsToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "app_actions",
			"description": "Discover what you can DO on an installed app: its declared actions (form-action verbs + their fields), readable data sources, and QuantArena calls — parsed from the app's own UI surfaces. Call this before app_action so you know the exact verb + field names. Omit `app` to use the app in the current viewing context.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"app": map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"}},
			},
		},
		{
			"name":        "app_read",
			"description": "Read an allowlisted app data source and return its JSON — the same feeds app pages render. Sources: me://gpu-rentals, me://workflows?app=<slug>, me://loops/health, me://apps, me://drafts, me://today, qa://cluster/pricing. Use this to answer 'what are my GPU rentals', 'what's the GPU price', 'how are my workflows'. No approval needed (read-only).",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"source": map[string]any{"type": "string", "description": "e.g. me://gpu-rentals or qa://cluster/pricing"}},
				"required":   []string{"source"},
			},
		},
		{
			"name":        "show_app_surface",
			"description": "Render an app's home surface inline in the chat as a live, interactive card (the same tables/forms/stats the app page shows). Use when the user wants to SEE or work with an app's page without leaving the chat.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":     map[string]any{"type": "string", "description": "app slug"},
					"surface": map[string]any{"type": "string", "description": "optional named surface (defaults to home)"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "app_action",
			"description": "Invoke an app's declared form-action (a mutation — e.g. gpu_rental.create, gpu_rental.cancel). Get the exact verb + field names from app_actions first. Requires user approval. For paid/destructive actions, state the cost/effect in your message before calling so the approval prompt is informed.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": map[string]any{"type": "string", "description": "form-action verb, e.g. gpu_rental.create"},
					"values": map[string]any{"type": "object", "description": "field values for the action (strings ok; the backend coerces)"},
				},
				"required": []string{"action"},
			},
		},
		{
			"name":        "qa_call",
			"description": "Invoke a QuantArena write that an app surface declares via submit_qa/qa_post/qa_delete (e.g. join a competition, register a strategy). Only allowlisted paths are permitted. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"method": map[string]any{"type": "string", "description": "POST or DELETE"},
					"path":   map[string]any{"type": "string", "description": "QuantArena path, e.g. /api/v1/competitions/28/join"},
					"body":   map[string]any{"type": "object", "description": "optional JSON body"},
				},
				"required": []string{"method", "path"},
			},
		},
		{
			"name":        "app_ui_get",
			"description": "Read the EDITABLE source of an app's page (its Studio surface) so you can modify it. Returns {format: markdown|page.yaml, source, sha}. Call this before app_ui_set so you have the current source + sha (the sha is the optimistic lock). No approval needed (read-only).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":     map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"surface": map[string]any{"type": "string", "description": "named surface (defaults to home)"},
				},
			},
		},
		{
			"name":        "app_ui_set",
			"description": "Write/replace the source of an app's page (its Studio surface) — this is how you EDIT an app's UI from chat. Send `markdown` for a markdown surface or `spec` (raw page.yaml text) for a structured page surface; app_ui_get tells you which `format` the surface is. Pass `base_sha` from app_ui_get to avoid clobbering a concurrent edit. Only your OWN installed apps are editable (operator-shared apps are read-only — fork first). page.yaml specs are validated before saving. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"surface":  map[string]any{"type": "string", "description": "named surface (defaults to home)"},
					"markdown": map[string]any{"type": "string", "description": "new markdown source (for a markdown surface)"},
					"spec":     map[string]any{"type": "string", "description": "new page.yaml source text (for a structured page surface)"},
					"base_sha": map[string]any{"type": "string", "description": "sha from app_ui_get (optimistic lock; optional)"},
				},
				"required": []string{"app"},
			},
		},
		{
			"name":        "app_ui_generate",
			"description": "AI-generate (or regenerate + improve) an app's page from its config + skills, producing a validated structured page.yaml and making it the home surface. Use when the user wants a page built or refreshed for them rather than hand-editing. Writes to your OWN installed app only. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app": map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
				},
			},
		},
		{
			"name":        "run_promote",
			"description": "Promote one of an app's runs — mark it as the chosen branch (advisory; never rewrites run history). Use when the user picks a winning/champion run. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"ts":   map[string]any{"type": "string", "description": "run timestamp id, e.g. 20060102T150405Z"},
					"loop": map[string]any{"type": "string", "description": "optional workflow name to narrow the search"},
				},
				"required": []string{"ts"},
			},
		},
		{
			"name":        "run_discard",
			"description": "Discard one of an app's runs — grey it out (advisory; never deletes run history). Use when the user wants a bad/abandoned run set aside. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"ts":   map[string]any{"type": "string", "description": "run timestamp id, e.g. 20060102T150405Z"},
					"loop": map[string]any{"type": "string", "description": "optional workflow name to narrow the search"},
				},
				"required": []string{"ts"},
			},
		},
		{
			"name":        "app_prompt_list",
			"description": "List an app's analyst & judge PROMPT cards (analyst_system, analyst_skill_*, judge_*). Returns each prompt's name, source (local override vs shared:<skill repo>), whether it's editable, and its sha. Call this before app_prompt_get/app_prompt_set. No approval needed (read-only).",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"app": map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"}},
			},
		},
		{
			"name":        "app_prompt_get",
			"description": "Read one of an app's prompt cards (its markdown content) so you can review or edit it. Returns {content, source, sha, editable}. The sha is the optimistic lock for app_prompt_set. No approval needed (read-only).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"name": map[string]any{"type": "string", "description": "prompt file name, e.g. judge_score_qual.md"},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "app_prompt_set",
			"description": "Write/replace an app's prompt card — this is how you EDIT an analyst or judge prompt from chat. Writes a LOCAL override in your OWN installed app (the shared skill prompt is never mutated; operator-shared apps are read-only — fork first). Pass `base_sha` from app_prompt_get to avoid clobbering a concurrent edit. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":      map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"name":     map[string]any{"type": "string", "description": "prompt file name, e.g. judge_score_qual.md"},
					"content":  map[string]any{"type": "string", "description": "the new prompt markdown"},
					"base_sha": map[string]any{"type": "string", "description": "sha from app_prompt_get (optimistic lock; optional)"},
				},
				"required": []string{"name", "content"},
			},
		},
		{
			"name":        "app_prompt_reset",
			"description": "Reset an app's prompt card to its inherited shared default by removing the LOCAL override (the shared skill prompt is never touched). Use when the user wants to discard their prompt edits. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"name": map[string]any{"type": "string", "description": "prompt file name, e.g. judge_score_qual.md"},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "branch_run",
			"description": "Branch from an existing run with an exploration intention — records a 'branch from here' control signal carrying a free-text note ('what should this attempt explore?') plus an optional config variant. The proposer/hypothesize stage reads the note as its directive on the next run. Use when the user wants to try a new direction off a prior run. Requires user approval.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":     map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"loop":    map[string]any{"type": "string", "description": "workflow name the run belongs to"},
					"from_ts": map[string]any{"type": "string", "description": "the run id to branch from, e.g. 20060102T150405Z"},
					"note":    map[string]any{"type": "string", "description": "the exploration intention — what this attempt should explore"},
					"variant": map[string]any{"type": "object", "description": "optional config overrides for the branched attempt"},
				},
				"required": []string{"loop", "from_ts", "note"},
			},
		},
		{
			"name":        "search_run_log",
			"description": "Search a single run's logs/issues — its LLM transcript, stage journal, and step errors — for a query string. Use to answer 'find the errors in the last run', 'where did it mention X'. Optional `type` narrows to llm | stage | error. Returns matches with snippets. No approval needed (read-only).",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "app slug (defaults to the app you're viewing)"},
					"loop": map[string]any{"type": "string", "description": "workflow name the run belongs to"},
					"ts":   map[string]any{"type": "string", "description": "the run id, e.g. 20060102T150405Z"},
					"q":    map[string]any{"type": "string", "description": "case-insensitive query string"},
					"type": map[string]any{"type": "string", "description": "optional source filter: llm | stage | error"},
				},
				"required": []string{"loop", "ts", "q"},
			},
		},
	}
}

// dispatchAppOpsTool handles the five app-ops tools; returns (result, handled).
func dispatchAppOpsTool(c *gin.Context, userID, role, name string, args map[string]any) (map[string]any, bool, bool) {
	switch name {
	case "app_actions":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		if app == "" {
			return map[string]any{"error": "app required (or open an app first)"}, false, true
		}
		if !validAppSlug(app) {
			return map[string]any{"error": "invalid app name"}, false, true
		}
		return appActionsCatalog(userID, app), true, true

	case "app_read":
		src := strVal(args, "source")
		if src == "" {
			return map[string]any{"error": "source required"}, false, true
		}
		data, err := appReadSource(c, userID, src)
		if err != nil {
			return map[string]any{"error": err.Error()}, false, true
		}
		return map[string]any{"source": src, "data": data}, true, true

	case "show_app_surface":
		app := strVal(args, "app")
		if app == "" {
			return map[string]any{"error": "app required"}, false, true
		}
		if !validAppSlug(app) {
			return map[string]any{"error": "invalid app name"}, false, true
		}
		surface := strVal(args, "surface")
		if surface == "" {
			surface = "home"
		}
		// The result is a render directive — the frontend (entityCards) mounts
		// an AppSurfaceCard for {app, surface}. No data fetched server-side.
		return map[string]any{"render": "app_surface", "app": app, "surface": surface}, true, true

	case "app_action":
		action := strVal(args, "action")
		if action == "" {
			return map[string]any{"error": "action required"}, false, true
		}
		values, _ := args["values"].(map[string]any)
		if values == nil {
			values = map[string]any{}
		}
		res, err := dispatchFormAction(c, userID, role, action, values)
		// Audit trail — mutating app actions invoked by the AI on the user's
		// behalf. Greppable as [app-ops]. Include the failure reason so an
		// incident review can tell "not allowed" from a backend 502.
		if err != nil {
			log.Printf("[app-ops] action=%s user=%s ok=false err=%v", action, userID, err)
			return map[string]any{"error": err.Error(), "action": action}, false, true
		}
		log.Printf("[app-ops] action=%s user=%s ok=true", action, userID)
		out := map[string]any{}
		if m, ok := res.(gin.H); ok {
			for k, v := range m {
				out[k] = v
			}
		} else if m, ok := res.(map[string]any); ok {
			for k, v := range m {
				out[k] = v
			}
		} else {
			out["result"] = res
		}
		// Set the dispatcher's own keys LAST so an action result that happens to
		// carry its own "action"/"ok" can't shadow them (entityCards reads both).
		out["action"] = action
		out["ok"] = true
		return out, true, true

	case "qa_call":
		method := strings.ToUpper(strVal(args, "method"))
		path := strVal(args, "path")
		body, _ := args["body"].(map[string]any)
		res, err := qaCall(c, method, path, body)
		if err != nil {
			log.Printf("[app-ops] qa_call %s %s user=%s ok=false err=%v", method, path, userID, err)
			return map[string]any{"error": err.Error(), "path": path}, false, true
		}
		log.Printf("[app-ops] qa_call %s %s user=%s ok=true", method, path, userID)
		return map[string]any{"ok": true, "method": method, "path": path, "result": res}, true, true

	case "app_ui_get":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppUIGet(userID, app, strVal(args, "surface"))
		return res, okRes, true

	case "app_ui_set":
		if strVal(args, "app") == "" {
			args["app"] = groundedApp(c)
		}
		res, okRes := toolAppUISet(userID, args)
		app := strVal(args, "app")
		log.Printf("[app-ops] app_ui_set app=%s user=%s ok=%v", app, userID, okRes)
		return res, okRes, true

	case "app_ui_generate":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppUIGenerate(c, userID, app)
		log.Printf("[app-ops] app_ui_generate app=%s user=%s ok=%v", app, userID, okRes)
		return res, okRes, true

	case "run_promote", "run_discard":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		verb := "promote"
		if name == "run_discard" {
			verb = "discard"
		}
		res, okRes := toolRunMark(userID, verb, app, strVal(args, "ts"), strVal(args, "loop"))
		log.Printf("[app-ops] %s app=%s ts=%s user=%s ok=%v", name, app, strVal(args, "ts"), userID, okRes)
		return res, okRes, true

	case "app_prompt_list":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppPromptList(userID, app)
		return res, okRes, true

	case "app_prompt_get":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppPromptGet(userID, app, strVal(args, "name"))
		return res, okRes, true

	case "app_prompt_set":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppPromptSet(userID, app, args)
		log.Printf("[app-ops] app_prompt_set app=%s name=%s user=%s ok=%v", app, strVal(args, "name"), userID, okRes)
		return res, okRes, true

	case "app_prompt_reset":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolAppPromptReset(userID, app, strVal(args, "name"))
		log.Printf("[app-ops] app_prompt_reset app=%s name=%s user=%s ok=%v", app, strVal(args, "name"), userID, okRes)
		return res, okRes, true

	case "branch_run":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolBranchRun(userID, app, args)
		log.Printf("[app-ops] branch_run app=%s loop=%s from=%s user=%s ok=%v", app, strVal(args, "loop"), strVal(args, "from_ts"), userID, okRes)
		return res, okRes, true

	case "search_run_log":
		app := strVal(args, "app")
		if app == "" {
			app = groundedApp(c)
		}
		res, okRes := toolSearchRunLog(userID, app, args)
		return res, okRes, true
	}
	return nil, false, false
}

// safeAppJoin joins a bundle-relative surface path to appDir, rejecting
// traversal / absolute / NUL so a surface path can never escape the app bundle.
func safeAppJoin(appDir, rel string) (string, error) {
	if rel == "" || strings.ContainsAny(rel, "\x00") || strings.Contains(rel, "..") || filepath.IsAbs(rel) {
		return "", &appOpsError{"invalid surface path"}
	}
	abs := filepath.Clean(filepath.Join(appDir, rel))
	if abs != appDir && !strings.HasPrefix(abs, appDir+string(filepath.Separator)) {
		return "", &appOpsError{"surface path escapes app"}
	}
	return abs, nil
}

// writeFileAtomic writes b to path via tmp+rename so readers never see a
// partial surface. Parent dirs are created if missing.
func writeFileAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return &appOpsError{"cannot create surface directory"}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return &appOpsError{"cannot write surface"}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return &appOpsError{"cannot save surface"}
	}
	return nil
}

// resolveSurfacePaths maps a surface name to its declared markdown / page-spec
// path (mirrors the resolution in updateAppSurface). Exactly one of mdPath /
// pagePath is non-empty on success.
func resolveSurfacePaths(ui *appUI, name string) (mdPath, pagePath string, ok bool) {
	if p, has := ui.Surfaces[name]; has {
		if low := strings.ToLower(p); strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") {
			return "", p, true
		}
		return p, "", true
	}
	if name == "home" && ui.Surface != nil {
		return ui.Surface.Markdown, ui.Surface.Page, true
	}
	return "", "", false
}

// toolAppUIGet returns a surface's editable source + sha + format (read-only).
func toolAppUIGet(userID, app, surface string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	name := surface
	if name == "" {
		name = "home"
	}
	ui := readAppUI(appDir)
	if ui == nil || (ui.Surface == nil && len(ui.Surfaces) == 0) {
		return map[string]any{"error": "app declares no ui surface"}, false
	}
	mdPath, pagePath, ok := resolveSurfacePaths(ui, name)
	if !ok {
		return map[string]any{"error": "unknown surface: " + name}, false
	}
	rel, format := mdPath, "markdown"
	if pagePath != "" {
		rel, format = pagePath, "page.yaml"
	}
	if rel == "" || strings.HasPrefix(rel, "@") {
		// Template-inherited or native: no local source yet. Report the format
		// so the agent knows whether to author markdown or a page.yaml spec.
		if ui.Surface != nil && ui.Surface.Native != "" && pagePath == "" && mdPath == "" {
			return map[string]any{"app": app, "surface": name, "format": "native", "source": "", "sha": "", "note": "native surface — author markdown via app_ui_set or regenerate via app_ui_generate"}, true
		}
		return map[string]any{"app": app, "surface": name, "format": format, "source": "", "sha": "", "note": "inherited template — app_ui_set will create a local override"}, true
	}
	abs, err := safeAppJoin(appDir, rel)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		return map[string]any{"app": app, "surface": name, "format": format, "path": rel, "source": "", "sha": ""}, true
	}
	return map[string]any{"app": app, "surface": name, "format": format, "path": rel, "source": string(b), "sha": contentSHA(b)}, true
}

// toolAppUISet writes a surface's source. Mirrors updateAppSurface's checks:
// tenant-owned only, page specs validated through compilePageSpec, optimistic
// lock via base_sha, atomic write, xpcloud patch for markdown surfaces.
// Approval-gated (destructiveTools).
func toolAppUISet(userID string, args map[string]any) (map[string]any, bool) {
	app := strVal(args, "app")
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	markdown, _ := args["markdown"].(string)
	spec, _ := args["spec"].(string)
	baseSHA := strVal(args, "base_sha")
	if strings.TrimSpace(markdown) == "" && strings.TrimSpace(spec) == "" {
		return map[string]any{"error": "provide `markdown` (md surface) or `spec` (page.yaml surface)"}, false
	}
	const maxBytes = 256 * 1024
	if len(markdown) > maxBytes || len(spec) > maxBytes {
		return map[string]any{"error": "surface exceeds 256 KB limit"}, false
	}
	name := strVal(args, "surface")
	if name == "" {
		name = "home"
	}
	// WRITE path must be the caller's OWN tenant install — editing the shared
	// copy would change the surface for every tenant + the scheduler.
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			return map[string]any{"error": "this app is operator-shared (read-only) — fork/install your own copy first"}, false
		}
		return map[string]any{"error": "app not found: " + app}, false
	}
	ui := readAppUI(appDir)
	if ui == nil || (ui.Surface == nil && len(ui.Surfaces) == 0) {
		return map[string]any{"error": "app declares no ui surface"}, false
	}
	mdPath, pagePath, ok := resolveSurfacePaths(ui, name)
	if !ok {
		return map[string]any{"error": "unknown surface: " + name}, false
	}

	// Structured page surface — the SPEC is the editable artifact.
	if pagePath != "" {
		if strings.TrimSpace(spec) == "" {
			return map[string]any{"error": "this surface is a structured page — send `spec` (raw " + pagePath + " text), not markdown"}, false
		}
		abs, err := safeAppJoin(appDir, pagePath)
		if err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		if _, cerr := compilePageSpec([]byte(spec)); cerr != nil {
			return map[string]any{"error": "page spec invalid: " + cerr.Error()}, false
		}
		if baseSHA != "" {
			if cur, rerr := os.ReadFile(abs); rerr == nil && contentSHA(cur) != baseSHA {
				return map[string]any{"error": "this page changed since you loaded it — call app_ui_get again and reapply"}, false
			}
		}
		if err := writeFileAtomic(abs, []byte(spec)); err != nil {
			return map[string]any{"error": err.Error()}, false
		}
		return map[string]any{"app": app, "surface": name, "format": "page.yaml", "path": pagePath, "saved": true, "sha": contentSHA([]byte(spec))}, true
	}

	// Markdown surface.
	if strings.TrimSpace(markdown) == "" {
		return map[string]any{"error": "this surface is markdown — send `markdown`, not `spec`"}, false
	}
	if mdPath == "" && ui.Surface != nil && ui.Surface.Native != "" {
		// Native surface — author a local markdown override (detaches native).
		mdPath = appUIWriteRef("home.md")
	}
	// Inherited template / no declared path → canonical .ui/home.md override.
	if mdPath == "" || strings.HasPrefix(mdPath, "@") {
		mdPath = appUIWriteRef("home.md")
	}
	abs, err := safeAppJoin(appDir, mdPath)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if strings.ToLower(filepath.Ext(abs)) != ".md" {
		return map[string]any{"error": "surface must be a .md file"}, false
	}
	if baseSHA != "" {
		if cur, rerr := os.ReadFile(abs); rerr == nil && contentSHA(cur) != baseSHA {
			return map[string]any{"error": "this page changed since you loaded it — call app_ui_get again and reapply"}, false
		}
	}
	if err := writeFileAtomic(abs, []byte(markdown)); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// Point xpcloud.yaml at the (possibly new) override file.
	_ = patchXpcloudUISurface(appDir, name, mdPath)
	return map[string]any{"app": app, "surface": name, "format": "markdown", "path": mdPath, "saved": true, "sha": contentSHA([]byte(markdown))}, true
}

// toolAppUIGenerate AI-generates a page.yaml surface for an OWNED app, reusing
// the same core the HTTP "Generate UI" button calls. Approval-gated.
func toolAppUIGenerate(c *gin.Context, userID, app string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	// Generation persists into the bundle — require ownership (same as the UI).
	_, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			return map[string]any{"error": "this app is operator-shared (read-only) — fork/install your own copy first"}, false
		}
		return map[string]any{"error": "app not found: " + app}, false
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()
	data, status, msg := generateAppUIPage(ctx, userID, app)
	if status != 0 {
		return map[string]any{"error": msg}, false
	}
	// generateAppUIPage returns the full compiled markdown (the HTTP editor uses
	// it for a live preview). Feeding multi-KB of compiled page back into the
	// chat model's context is wasteful and can blow the smaller kv.run models'
	// window — so the CHAT result carries only a short preview + byte count. The
	// page is persisted; the user views it via the deep link / refetched surface.
	if md, ok := data["markdown"].(string); ok {
		data["bytes"] = len(md)
		data["preview"] = truncateStr(strings.TrimSpace(md), 400)
		delete(data, "markdown")
	}
	data["app"] = app
	data["surface"] = "home" // generation always (re)writes the home surface
	data["generated"] = true
	return data, true
}

// toolRunMark promotes/discards a run via the same lumid-trajectory CLI the UI
// uses (HOME-scoped to the caller's tenant). Approval-gated.
func toolRunMark(userID, verb, app, ts, loop string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	// Mirror meRunMark's guards exactly (slugRe permits '/', so also reject path
	// separators) — these become exec args to the trajectory CLI.
	if ts == "" || !slugRe.MatchString(ts) || strings.ContainsAny(ts, "/\\") || strings.Contains(ts, "..") {
		return map[string]any{"error": "valid run ts required (e.g. 20060102T150405Z)"}, false
	}
	cliArgs := []string{verb, "--app", app, "--ts", ts}
	if loop != "" {
		if !slugRe.MatchString(loop) || strings.ContainsAny(loop, "/\\") || strings.Contains(loop, "..") {
			return map[string]any{"error": "invalid loop name"}, false
		}
		cliArgs = append(cliArgs, "--loop", loop)
	}
	obj, err, _ := runTrajectoryCLI(userID, cliArgs...)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if obj == nil {
		obj = map[string]any{}
	}
	obj["app"] = app
	obj["ts"] = ts
	obj[verb+"d"] = true
	return obj, true
}

// ── prompt tools (WS-8 / WS-7 chat twins) ───────────────────────────────────

// toolAppPromptList mirrors MeAppPrompts: local + inherited shared prompt cards.
func toolAppPromptList(userID, app string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	_, owned, _ := resolveOwnedAppDir(userID, app)
	byName := map[string]*promptInfo{}
	order := []string{}
	upsert := func(name string) *promptInfo {
		if p, has := byName[name]; has {
			return p
		}
		p := &promptInfo{Name: name}
		byName[name] = p
		order = append(order, name)
		return p
	}
	for _, repo := range appPromptSkillImports(appDir) {
		sdir := skillPromptsDir(userID, repo)
		if sdir == "" {
			continue
		}
		for _, n := range readMdNames(sdir) {
			p := upsert(n)
			p.Source = "shared:" + repo
			p.Editable = owned
			if b, err := os.ReadFile(filepath.Join(sdir, n)); err == nil {
				p.SHA = contentSHA(b)
			}
		}
	}
	for _, n := range readMdNames(localPromptsDir(appDir)) {
		p := upsert(n)
		p.Source = "local"
		p.Editable = owned
		if b, err := os.ReadFile(filepath.Join(localPromptsDir(appDir), n)); err == nil {
			p.SHA = contentSHA(b)
		}
	}
	prompts := make([]promptInfo, 0, len(order))
	for _, n := range order {
		prompts = append(prompts, *byName[n])
	}
	return map[string]any{"app": app, "prompts": prompts}, true
}

// toolAppPromptGet mirrors MeAppPrompt: a prompt card's content + source + sha.
func toolAppPromptGet(userID, app, name string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	if !validPromptName(name) {
		return map[string]any{"error": "valid prompt name required (.md only)"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	path, source := resolvePromptRead(userID, appDir, name)
	if path == "" {
		return map[string]any{"error": "prompt not found: " + name}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{"error": "cannot read prompt"}, false
	}
	if len(b) > promptMaxBytes {
		b = b[:promptMaxBytes]
	}
	_, owned, _ := resolveOwnedAppDir(userID, app)
	return map[string]any{
		"app": app, "name": name, "content": string(b),
		"source": source, "sha": contentSHA(b), "editable": owned,
	}, true
}

// toolAppPromptSet mirrors MeUpdateAppPrompt: write a LOCAL override (own app
// only), optimistic lock, atomic. Approval-gated (destructiveTools).
func toolAppPromptSet(userID, app string, args map[string]any) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	name := strVal(args, "name")
	if !validPromptName(name) {
		return map[string]any{"error": "valid prompt name required (.md only)"}, false
	}
	content, _ := args["content"].(string)
	if strings.TrimSpace(content) == "" {
		return map[string]any{"error": "content required"}, false
	}
	if len(content) > promptMaxBytes {
		return map[string]any{"error": "prompt exceeds 256 KB limit"}, false
	}
	baseSHA := strVal(args, "base_sha")
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			return map[string]any{"error": "this app is operator-shared (read-only) — fork/install your own copy first"}, false
		}
		return map[string]any{"error": "app not found: " + app}, false
	}
	abs, err := safeAppJoin(appDir, filepath.Join(promptDirRel, name))
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if strings.ToLower(filepath.Ext(abs)) != ".md" {
		return map[string]any{"error": "prompt must be a .md file"}, false
	}
	if baseSHA != "" {
		if cur, rerr := os.ReadFile(abs); rerr == nil && contentSHA(cur) != baseSHA {
			return map[string]any{"error": "this prompt changed since you loaded it — call app_prompt_get again and reapply"}, false
		}
	}
	if err := writeFileAtomic(abs, []byte(content)); err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	return map[string]any{"app": app, "name": name, "saved": true, "sha": contentSHA([]byte(content))}, true
}

// toolAppPromptReset mirrors MeDeleteAppPrompt: remove the LOCAL override only
// (revert to the inherited shared prompt). Approval-gated.
func toolAppPromptReset(userID, app, name string) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	if !validPromptName(name) {
		return map[string]any{"error": "valid prompt name required (.md only)"}, false
	}
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			return map[string]any{"error": "this app is operator-shared (read-only) — fork/install your own copy first"}, false
		}
		return map[string]any{"error": "app not found: " + app}, false
	}
	abs, err := safeAppJoin(appDir, filepath.Join(promptDirRel, name))
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return map[string]any{"error": "cannot remove prompt override"}, false
	}
	return map[string]any{"app": app, "name": name, "reverted": true}, true
}

// ── branch_run tool (WS-8 / WS-5) ────────────────────────────────────────────

// toolBranchRun records a "branch from here" control signal carrying the
// exploration intention (note) + optional config variant, mirroring the
// MeTrajectorySignal write path. The proposer stage reads the pending signal's
// note as its directive on the next run. Approval-gated (destructiveTools).
func toolBranchRun(userID, app string, args map[string]any) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	loop := strVal(args, "loop")
	fromTs := strVal(args, "from_ts")
	note := strings.TrimSpace(strVal(args, "note"))
	if loop == "" || !slugRe.MatchString(loop) {
		return map[string]any{"error": "valid loop required"}, false
	}
	if fromTs == "" || !slugRe.MatchString(fromTs) || strings.ContainsAny(fromTs, "/\\") || strings.Contains(fromTs, "..") {
		return map[string]any{"error": "valid from_ts required (e.g. 20060102T150405Z)"}, false
	}
	if note == "" {
		return map[string]any{"error": "note required — say what this attempt should explore"}, false
	}
	var variant map[string]any
	if v, ok := args["variant"].(map[string]any); ok {
		variant = v
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	rec := signalRecord{
		Ts:     time.Now().UTC().Format(time.RFC3339),
		Action: "branch",
		Loop:   loop,
		FromID: fromTs,
		Config: variant,
		Note:   note,
		By:     userID,
		Status: "pending",
	}
	controlDir, err := ResolveRuntimeWritePath(appDir, "data/control")
	if err != nil {
		return map[string]any{"error": "could not prepare control dir"}, false
	}
	if err := os.MkdirAll(controlDir, 0o775); err != nil {
		return map[string]any{"error": "could not prepare control dir"}, false
	}
	path := filepath.Join(controlDir, "signals.jsonl")
	line, err := json.Marshal(rec)
	if err != nil {
		return map[string]any{"error": "could not encode signal"}, false
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return map[string]any{"error": "could not open signals log"}, false
	}
	if _, werr := f.Write(append(line, '\n')); werr != nil {
		f.Close()
		return map[string]any{"error": "could not write signal"}, false
	}
	f.Close()
	return map[string]any{
		"app": app, "loop": loop, "from_ts": fromTs,
		"branched": true, "note": note, "pending": countPendingSignals(path),
	}, true
}

// ── search_run_log tool (WS-8 / WS-6) ────────────────────────────────────────

// toolSearchRunLog mirrors MeCycleLogSearch: grep one run's transcript +
// journal + step errors for q. Read-only.
func toolSearchRunLog(userID, app string, args map[string]any) (map[string]any, bool) {
	if app == "" || !validAppSlug(app) {
		return map[string]any{"error": "valid app required (or open an app first)"}, false
	}
	loop := strVal(args, "loop")
	ts := strVal(args, "ts")
	q := strings.TrimSpace(strVal(args, "q"))
	kind := strVal(args, "type")
	if loop == "" || !slugRe.MatchString(loop) {
		return map[string]any{"error": "valid loop required"}, false
	}
	if ts == "" || !slugRe.MatchString(ts) {
		return map[string]any{"error": "valid ts required (e.g. 20060102T150405Z)"}, false
	}
	if q == "" {
		return map[string]any{"error": "q required"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	matches, capped := searchCycleLog(appDir, loop, ts, q, kind)
	return map[string]any{
		"app": app, "loop": loop, "ts": ts, "q": q, "type": kind,
		"matches": matches, "count": len(matches), "capped": capped,
	}, true
}

func strVal(args map[string]any, k string) string {
	if s, ok := args[k].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// appSlugRe — a single app-dir name: alphanumeric start, then word/.-_ chars.
// Deliberately excludes "/" and can't be ".." (first char must be alnum), so
// an attacker-supplied app can't traverse out of the tenant apps dir when it
// flows into resolveAppDir's filepath.Join.
var appSlugRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validAppSlug(app string) bool {
	return appSlugRe.MatchString(app) && !strings.Contains(app, "..")
}

// stashViewingApp records the viewing-context app on the gin context so
// app-ops tools default to it when `app` is omitted. Called by the chat
// handlers right after binding the request body.
func stashViewingApp(c *gin.Context, ctx map[string]any) {
	if ctx == nil {
		return
	}
	if app, ok := ctx["app"].(string); ok && app != "" {
		c.Set("viewing_app", app)
	}
}

// groundedActionsHint appends a one-line-per-verb summary of what the AI can
// DO on the grounded app, so it offers concrete actions unprompted. Returns ""
// when the app declares no actions.
func groundedActionsHint(userID, app string) string {
	cat := appActionsCatalog(userID, app)
	actions, _ := cat["actions"].([]map[string]any)
	qaCalls, _ := cat["qa_calls"].([]map[string]any)
	if len(actions) == 0 && len(qaCalls) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nThis app (%s) is operable from chat. You can act on the user's behalf via app_action (call app_actions first for field schemas). Available actions:\n", app)
	for _, a := range actions {
		verb, _ := a["verb"].(string)
		if verb != "" {
			fmt.Fprintf(&b, "  - %s\n", verb)
		}
	}
	if len(qaCalls) > 0 {
		b.WriteString("  - plus QuantArena calls via qa_call (see app_actions)\n")
	}
	b.WriteString("Mutating actions need user approval — state cost/effect first.\n")
	return b.String()
}

// groundedApp pulls the app from the viewing context the chat request carried.
func groundedApp(c *gin.Context) string {
	if v, ok := c.Get("viewing_app"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ── app_read: mirror the directive resolver's scheme allowlist ───────────────

func appReadSource(c *gin.Context, userID, src string) (any, error) {
	switch {
	case strings.HasPrefix(src, "me://"):
		p := strings.TrimLeft(strings.TrimPrefix(src, "me://"), "/")
		switch {
		case p == "gpu-rentals":
			return gpuRentalsData(userID), nil
		case p == "apps":
			return toolListApps(userID), nil
		case p == "loops/health" || p == "loops-health":
			res, _ := toolLoopsHealth(userID)
			return res, nil
		case p == "today":
			return toolTodaySummary(userID), nil
		case p == "workflows" || strings.HasPrefix(p, "workflows?"):
			appFilter := ""
			if i := strings.IndexByte(p, '?'); i >= 0 {
				if vals, err := url.ParseQuery(p[i+1:]); err == nil {
					appFilter = vals.Get("app")
				}
			}
			all := toolListWorkflows(c, userID, "")
			if appFilter != "" {
				if wfs, ok := all["workflows"].([]WorkflowRow); ok {
					filtered := make([]WorkflowRow, 0, len(wfs))
					for _, w := range wfs {
						if w.App == appFilter {
							filtered = append(filtered, w)
						}
					}
					return map[string]any{"workflows": filtered, "count": len(filtered)}, nil
				}
			}
			return all, nil
		case p == "drafts" || strings.HasPrefix(p, "drafts?"):
			return toolListDrafts(userID, ""), nil
		default:
			return nil, errReadNotAllowed(src)
		}
	case src == "qa://cluster/pricing":
		ctx, cancel := context.WithTimeout(c.Request.Context(), 6e9)
		defer cancel()
		return httpGetJSON(ctx, internalBaseURL()+"/api/v1/cluster/pricing")
	default:
		return nil, errReadNotAllowed(src)
	}
}

func errReadNotAllowed(src string) error {
	return &appOpsError{"source not allowed: " + src}
}

type appOpsError struct{ msg string }

func (e *appOpsError) Error() string { return e.msg }

// internalBaseURL is where lumid_identity reaches its own public endpoints
// (cluster pricing is served on the same origin behind nginx). Overridable.
func internalBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("SELF_BASE_URL")); v != "" {
		return v
	}
	return "https://lum.id"
}

// ── app_actions: parse the installed app's surfaces for declared primitives ──

var fencedLumidRe = regexp.MustCompile("(?s)```lumid:([a-z-]+)\\n(.*?)```")

func appActionsCatalog(userID, app string) map[string]any {
	dir := resolveAppDir(userID, app)
	if dir == "" {
		return map[string]any{"error": "app not installed: " + app}
	}
	uiDir := appUIDir(dir)
	entries, _ := os.ReadDir(uiDir)

	actions := []map[string]any{}
	reads := map[string]bool{}
	qaCalls := []map[string]any{}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(uiDir, e.Name()))
		if err != nil {
			continue
		}
		for _, m := range fencedLumidRe.FindAllStringSubmatch(string(raw), -1) {
			kind, bodyYAML := m[1], m[2]
			var body map[string]any
			if yaml.Unmarshal([]byte(bodyYAML), &body) != nil {
				continue
			}
			switch kind {
			case "form":
				if act, ok := body["action"].(string); ok && act != "" {
					actions = append(actions, map[string]any{
						"verb":    act,
						"fields":  extractFields(body["fields"]),
						"surface": strings.TrimSuffix(e.Name(), ".md"),
					})
				}
				if sq, ok := body["submit_qa"].(string); ok && sq != "" {
					qaCalls = append(qaCalls, parseQaRef(sq))
				}
			case "table", "stat", "chart", "list", "search-table", "workflow":
				if s, ok := body["source"].(string); ok && s != "" {
					reads[s] = true
				}
				if st, ok := body["source_template"].(string); ok && st != "" {
					reads[st] = true
				}
				// row_actions / actions with qa_post / qa_delete
				for _, key := range []string{"actions", "row_actions"} {
					if arr, ok := body[key].([]any); ok {
						for _, a := range arr {
							if am, ok := a.(map[string]any); ok {
								if qp, ok := am["qa_post"].(string); ok && qp != "" {
									qaCalls = append(qaCalls, map[string]any{"method": "POST", "path": qp})
								}
								if qd, ok := am["qa_delete"].(string); ok && qd != "" {
									qaCalls = append(qaCalls, map[string]any{"method": "DELETE", "path": qd})
								}
							}
						}
					}
				}
			}
		}
	}

	readList := make([]string, 0, len(reads))
	for s := range reads {
		readList = append(readList, s)
	}
	return map[string]any{
		"app":      app,
		"actions":  actions,
		"reads":    readList,
		"qa_calls": qaCalls,
	}
}

// extractFields pulls {key,label,type,required} from a form's fields[] so the
// agent knows what to pass to app_action.
func extractFields(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, f := range arr {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		field := map[string]any{}
		for _, k := range []string{"key", "label", "type", "required", "default", "placeholder", "options", "options_source"} {
			if val, ok := fm[k]; ok {
				field[k] = val
			}
		}
		out = append(out, field)
	}
	return out
}

func parseQaRef(s string) map[string]any {
	parts := strings.Fields(s)
	if len(parts) == 2 {
		return map[string]any{"method": strings.ToUpper(parts[0]), "path": parts[1]}
	}
	return map[string]any{"method": "POST", "path": s}
}

// ── qa_call: allowlisted QuantArena writes (submit_qa / qa_post / qa_delete) ──

// qaWriteAllowed gates which QA paths the agent may write to. Mirrors the
// write surfaces lumid-market declares; conservative prefix allowlist.
var qaWriteAllowed = regexp.MustCompile(`^/api/v1/(competitions|strategies|simulation|backtest|portfolios)(/|$)`)

func qaAPIBase() string {
	if v := strings.TrimSpace(os.Getenv("LUMID_QA_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	// Docker host gateway (daemon.json bip) — QuantArena main API.
	return "http://172.20.0.1:9988"
}

// qaCall performs an allowlisted QuantArena write on behalf of the caller,
// authed with a freshly-minted user JWT (QA runs AUTH_MODE=introspect and
// accepts lum.id RS256 JWTs).
func qaCall(c *gin.Context, method, path string, body map[string]any) (any, error) {
	if method != http.MethodPost && method != http.MethodDelete {
		return nil, &appOpsError{"qa_call only allows POST or DELETE"}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Reject traversal — the prefix allowlist below is meaningless if a path
	// like /api/v1/competitions/../../admin/x normalizes past it server-side.
	if strings.Contains(path, "..") {
		return nil, &appOpsError{"qa path not allowed (traversal)"}
	}
	// Strip any query for the allowlist check, keep it for the request.
	checkPath := path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		checkPath = path[:i]
	}
	if !qaWriteAllowed.MatchString(checkPath) {
		return nil, &appOpsError{"qa path not allowed: " + checkPath}
	}
	userID, ok := currentUserID(c)
	if !ok {
		return nil, &appOpsError{"not authenticated"}
	}
	email, role := userEmailRole(userID)
	token, _, _, err := common.IssueJWT(userID, email, role, []string{"lumid:read", "lumid:trading"})
	if err != nil {
		return nil, &appOpsError{"mint token: " + err.Error()}
	}

	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, qaAPIBase()+path, rdr)
	if err != nil {
		return nil, &appOpsError{err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &appOpsError{"qa unreachable: " + err.Error()}
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var out any
	if len(rawBody) > 0 {
		_ = json.Unmarshal(rawBody, &out)
	}
	if resp.StatusCode >= 400 {
		// Prefer the parsed JSON; fall back to the raw (truncated) body so a
		// non-JSON gateway error (nginx 502 HTML) is diagnosable, not "<nil>".
		detail := fmt.Sprintf("%v", out)
		if out == nil {
			detail = strings.TrimSpace(string(rawBody))
			if len(detail) > 300 {
				detail = detail[:300]
			}
		}
		return nil, &appOpsError{fmt.Sprintf("qa %d: %s", resp.StatusCode, detail)}
	}
	return out, nil
}
