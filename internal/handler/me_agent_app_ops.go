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
//   app_action(action,vals)  — invoke an allowlisted form-action      (APPROVAL)
//   qa_call(method,path,body)— invoke an allowlisted QuantArena write  (APPROVAL)
//
// Security: app_action reuses the formActions allowlist (me_form_action.go);
// app_read/qa_call mirror the directive resolver's scheme/path allowlist
// (directives.tsx); every mutating tool is in destructiveTools (approval-gated).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
				"type":       "object",
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
				"type":       "object",
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
				"type":       "object",
				"properties": map[string]any{
					"method": map[string]any{"type": "string", "description": "POST or DELETE"},
					"path":   map[string]any{"type": "string", "description": "QuantArena path, e.g. /api/v1/competitions/28/join"},
					"body":   map[string]any{"type": "object", "description": "optional JSON body"},
				},
				"required": []string{"method", "path"},
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
		// behalf. Greppable as [app-ops] for ops review.
		log.Printf("[app-ops] action=%s user=%s ok=%v", action, userID, err == nil)
		if err != nil {
			return map[string]any{"error": err.Error(), "action": action}, false, true
		}
		out := map[string]any{"action": action, "ok": true}
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
		return out, true, true

	case "qa_call":
		method := strings.ToUpper(strVal(args, "method"))
		path := strVal(args, "path")
		body, _ := args["body"].(map[string]any)
		res, err := qaCall(c, method, path, body)
		log.Printf("[app-ops] qa_call %s %s user=%s ok=%v", method, path, userID, err == nil)
		if err != nil {
			return map[string]any{"error": err.Error(), "path": path}, false, true
		}
		return map[string]any{"ok": true, "method": method, "path": path, "result": res}, true, true
	}
	return nil, false, false
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
	uiDir := filepath.Join(dir, "ui")
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
	var out any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 400 {
		return nil, &appOpsError{fmt.Sprintf("qa %d: %v", resp.StatusCode, out)}
	}
	return out, nil
}
