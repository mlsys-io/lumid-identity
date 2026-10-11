package handler

// Native, caller-scoped implementations of the chat's app READ tools.
//
// These used to go to the LumidOS tool bridge (lumidos-server:9100 →
// lumid-scheduler tools-api). That server resolves bundles against the
// operator's own ~/.xp regardless of X-Lumid-Tenant-Sub: when the bridge was
// briefly restored on 2026-10-11 (deploy_infra #290, reverted in #291), a
// role=user `agent_list` returned the OPERATOR's 22 apps. Everything here
// answers from what identity already owns and scopes per caller — the same
// data /me/apps and the Studio Library serve — or from xp.io's PUBLIC catalog
// (an unauthenticated read can only ever see public repos).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// nativeAppTool handles the app read tools (and install, which is already an
// intent identity owns) without the bridge. handled=false means "not mine".
func nativeAppTool(c *gin.Context, userID, name string, args map[string]any) (map[string]any, bool, bool) {
	switch name {
	case "agent_list", "app_list":
		return toolListApps(userID), true, true

	case "agent_install", "app_install":
		// Approval was already enforced by dispatchTool's destructive gate
		// under this name. Same intent the Studio Library writes.
		slug, _ := args["slug"].(string)
		if slug == "" {
			return map[string]any{"error": "slug required"}, false, true
		}
		asName, _ := args["new_name"].(string)
		if asName == "" {
			asName, _ = args["as"].(string)
		}
		id := writeIntentDirect(userID, "install", map[string]any{
			"slug": slug, "runtime": "local", "as": asName,
		})
		if id == "" {
			return map[string]any{"error": "intent write failed"}, false, true
		}
		return map[string]any{"intent_id": id, "status": "pending",
			"note": "Tell the user the install is in progress; it usually finishes in 5-15 seconds."}, true, true

	case "agent_marketplace", "app_marketplace":
		q, _ := args["q"].(string)
		if q == "" {
			q, _ = args["query"].(string)
		}
		kind, _ := args["kind"].(string)
		if kind == "" {
			kind = "agent"
		}
		res, err := publicRepoSearch(c.Request.Context(), q, kind, 10)
		if err != nil {
			return map[string]any{"error": "marketplace: " + err.Error()}, false, true
		}
		return map[string]any{"query": q, "kind": kind, "results": res, "count": len(res)}, true, true

	case "agent_detail", "app_detail":
		slug, _ := args["slug"].(string)
		res, err := publicRepoDetail(c.Request.Context(), slug)
		if err != nil {
			return map[string]any{"error": err.Error()}, false, true
		}
		return res, true, true
	}
	return nil, false, false
}

// bridgeAllowed: the LumidOS bridge runs every tool as the operator, so only
// the operator may reach it. For anyone else it fails closed, even if the
// tools-api is restored, until that server scopes each call to the caller.
func bridgeAllowed(role string) bool {
	return role == "super_admin"
}

func xpioPublicGet(ctx context.Context, path string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, xpcloudBaseURL()+path, nil)
	if err != nil {
		return nil, 0, err
	}
	// Deliberately NO Authorization header: a public read can't see private repos.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, err
}

func publicRepoSearch(ctx context.Context, q, kind string, limit int) ([]map[string]any, error) {
	body, code, err := xpioPublicGet(ctx, fmt.Sprintf("/api/v1/repos/search?kind=%s&q=%s&limit=%d",
		url.QueryEscape(kind), url.QueryEscape(q), limit))
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("xp.io search returned HTTP %d", code)
	}
	var parsed struct {
		Repos []map[string]any `json:"repos"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(parsed.Repos))
	for _, r := range parsed.Repos {
		if v, _ := r["visibility"].(string); v != "" && v != "public" {
			continue
		}
		out = append(out, map[string]any{
			"slug":         fmt.Sprintf("%v/%v", r["owner_sub"], r["name"]),
			"name":         r["name"],
			"display_name": r["display_name"],
			"summary":      r["summary"],
			"version":      r["version"],
			"kind":         r["kind"],
		})
	}
	return out, nil
}

func publicRepoDetail(ctx context.Context, slug string) (map[string]any, error) {
	parts := strings.Split(slug, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(slug, "..") {
		return nil, fmt.Errorf("slug must be <owner>/<name>")
	}
	body, code, err := xpioPublicGet(ctx, "/api/v1/repos/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1]))
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, fmt.Errorf("no public agent %q on the marketplace", slug)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("xp.io returned HTTP %d", code)
	}
	var r map[string]any
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if v, _ := r["visibility"].(string); v != "" && v != "public" {
		return nil, fmt.Errorf("no public agent %q on the marketplace", slug)
	}
	keep := map[string]any{"slug": slug}
	for _, k := range []string{"name", "display_name", "kind", "summary", "tags", "version", "head_sha", "updated_at", "stars", "downloads"} {
		if v, ok := r[k]; ok {
			keep[k] = v
		}
	}
	return keep, nil
}
