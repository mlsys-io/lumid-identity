package handler

// /api/v1/me/apps — user-scoped install + uninstall surface.
//
// Install/uninstall require running Python (sdk.ops.apps.app_install
// resolves the slug → repo URL, clones, parses xpcloud.yaml, validates
// the manifest, optionally pulls skill_imports). That Python lives on
// the operator host with the proper venv + secrets — not in this Go
// container. So the handler writes an INTENT FILE to
// ~/.lumilake/me-intents/<uuid>.json and returns 202 Accepted with the
// intent_id. A small picker on the scheduler side (separate task)
// consumes the intent dir, runs the action via the venv'd CLI, and
// writes <uuid>.result.json next to the intent file. The frontend
// polls GET /me/intents/:id for the result.
//
// Auth: session JWT or PAT with apps:write scope (PAT scope check is
// stubbed in P0 — currentUserID() is sufficient gate; full scope
// enforcement lands with task #6).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// intentDir returns the absolute path to ~/.lumilake/me-intents on the
// operator host. The directory is created on demand (the bind-mount
// gives us write access in P0).
func intentDir() string {
	return filepath.Join(operatorHome(), ".lumilake", "me-intents")
}

// tenantRoot returns the per-user app root on the operator host.
// Convention (multi-tenant phase 1, 2026-05-22): each user gets a
// HOME-shaped dir at /home/webmaster/.tenants/<user_sub>/ containing
// .xp/apps/ and .lumilake/. The intent picker sets HOME to this dir
// before calling app_install, so Path.home()-based installs land here.
//
// Operator's own apps stay at /home/webmaster/.xp/apps/ untouched; the
// scheduler discovers loops from BOTH that root and every tenant dir.
func tenantRoot(userSub string) string {
	return filepath.Join(operatorHome(), ".tenants", userSub)
}

// tenantAppsDir is the apps/ root for a specific user — composes with
// tenantRoot above. Equivalent to ~/.xp/apps for that tenant.
func tenantAppsDir(userSub string) string {
	return filepath.Join(tenantRoot(userSub), ".xp", "apps")
}

// slugRe — xp.io app slugs are alphanumeric+hyphen, optionally namespaced
// like `owner/name` or shorthand `name` (resolved by the scheduler).
var slugRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)

type meAppsInstallBody struct {
	Slug    string `json:"slug"    binding:"required"`
	Runtime string `json:"runtime"` // "local" | "cloud"; defaults to local in P0
	As      string `json:"as"`      // optional rename
}

// POST /api/v1/me/apps
// Body: {"slug":"owner/name","runtime":"local"}
// Returns: 202 {data: {intent_id, status:"pending"}}.
func MeAppsInstall(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body meAppsInstallBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.Slug) {
		fail(c, http.StatusBadRequest, 1400, "invalid slug — expected alphanumeric, dot, slash, hyphen, underscore, ≤128 chars")
		return
	}
	if body.Runtime == "" {
		body.Runtime = "local"
	}
	if body.Runtime != "local" && body.Runtime != "cloud" {
		fail(c, http.StatusBadRequest, 1400, "runtime must be local|cloud")
		return
	}
	if body.As != "" && !slugRe.MatchString(body.As) {
		fail(c, http.StatusBadRequest, 1400, "invalid 'as' name")
		return
	}
	id := writeIntent(c, "install", userID, map[string]any{
		"slug":    body.Slug,
		"runtime": body.Runtime,
		"as":      body.As,
	})
	if id == "" {
		return // writeIntent already wrote the error response
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "intent queued",
		"data": gin.H{"intent_id": id, "status": "pending"},
	})
}

// DELETE /api/v1/me/apps/:app — uninstall via intent.
func MeAppsUninstall(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	// Uninstall targets a single directory name under the caller's tenant app
	// tree. Be PERMISSIVE on charset (legacy drafts composed before slugs were
	// enforced can carry spaces / uppercase, e.g. "Musk X Trade Monitor-draft")
	// so the user can always clean them up — but hard-block path traversal.
	if app == "" || len(app) > 160 || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") || strings.HasPrefix(app, ".") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	id := writeIntent(c, "uninstall", userID, map[string]any{"app": app})
	if id == "" {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "intent queued",
		"data": gin.H{"intent_id": id, "status": "pending"},
	})
}

// GET /api/v1/me/apps — list installed apps for the current user.
// Reads from the caller's tenant root + appends operator-shared apps
// (the historical ~/.xp/apps/ tree) so the operator's own loops still
// surface for everyone. Each row carries a `tenant` flag so the UI
// can disambiguate shared vs personal installs.
func MeAppsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	type appCard struct {
		Name      string `json:"name"`
		HasMfst   bool   `json:"has_manifest"`
		HasXPCld  bool   `json:"has_xpcloud"`
		HasOverr  bool   `json:"has_user_overrides"`
		Tenant    bool   `json:"tenant"`         // true = this user's tenant root; false = operator-shared
		UI        *appUI `json:"ui,omitempty"`   // optional Studio sidebar + surface declaration (xpcloud.yaml::ui)
	}
	out := make([]appCard, 0, 16)

	walk := func(root string, isTenant bool) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dir := filepath.Join(root, e.Name())
			_, mfstErr := os.Stat(filepath.Join(dir, "manifest.json"))
			_, xpErr := os.Stat(filepath.Join(dir, "xpcloud.yaml"))
			_, ovErr := os.Stat(filepath.Join(dir, ".user-overrides.yaml"))
			// Best-effort parse of the optional ui: block (nil when absent
			// or unparseable) so the Studio sidebar can render app-declared
			// entries + surfaces. readAppUI lives in me_app_ui.go.
			var ui *appUI
			if xpErr == nil {
				ui = readAppUI(dir)
			}
			out = append(out, appCard{
				Name:     e.Name(),
				HasMfst:  mfstErr == nil,
				HasXPCld: xpErr == nil,
				HasOverr: ovErr == nil,
				Tenant:   isTenant,
				UI:       ui,
			})
		}
	}
	// Caller's own tenant — primary surface.
	walk(tenantAppsDir(userID), true)
	// Operator-shared apps (existing ~/.xp/apps tree) appear after,
	// flagged tenant:false so the UI can show them as read-only.
	walk(filepath.Join(operatorHome(), ".xp", "apps"), false)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"apps": out},
	})
	return // (kept to mirror the early-return on error below; non-fatal)
}


// GET /api/v1/me/intents/:id — fetch intent status + result.
// Result file is written by the scheduler-side picker (separate task).
// In P0 returns "pending" until that picker lands.
func MeIntentGet(c *gin.Context) {
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`).MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid intent id")
		return
	}
	dir := intentDir()
	intentPath := filepath.Join(dir, id+".json")
	resultPath := filepath.Join(dir, id+".result.json")

	// Read the intent envelope so we can return the ts/action even
	// before the picker has processed it.
	b, err := os.ReadFile(intentPath)
	if err != nil {
		fail(c, http.StatusNotFound, 1404, "intent not found")
		return
	}
	var envelope map[string]any
	_ = json.Unmarshal(b, &envelope)

	// Did the picker complete it?
	if rb, err := os.ReadFile(resultPath); err == nil {
		var result map[string]any
		_ = json.Unmarshal(rb, &result)
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"intent_id": id,
				"status":    "completed",
				"intent":    envelope,
				"result":    result,
			},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"intent_id": id,
			"status":    "pending",
			"intent":    envelope,
		},
	})
}

// writeIntent atomically writes <uuid>.json into ~/.lumilake/me-intents/
// and returns the uuid. The dir is made WORLD-WRITABLE (0o777) so the
// lumid-scheduler can write its .result.json next to the intent regardless
// of which uid it runs as — identity-in-container and the scheduler map to
// DIFFERENT host uids (the old code chmod'd 0o775 + chown 1001, but the
// scheduler now runs as 1000, so it lost write and every install stalled
// with a PermissionError on the result file). UID-agnostic perms avoid that.
// On write failure it writes a fail() response to c and returns "".
func writeIntent(c *gin.Context, action, userSub string, payload map[string]any) string {
	dir := intentDir()
	if err := os.MkdirAll(dir, 0o777); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mkdir intents: "+err.Error())
		return ""
	}
	// Idempotently force 0o777 — earlier deploys / this same function used to
	// set 0o775, which locked out the scheduler's result write. Ignore error.
	_ = os.Chmod(dir, 0o777)

	id := uuid.New().String()
	envelope := map[string]any{
		"intent_id":  id,
		"action":     action,
		"user_sub":   userSub,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"payload":    payload,
	}
	body, _ := json.MarshalIndent(envelope, "", "  ")
	// tmp+rename for atomic visibility — the scheduler may scan mid-write.
	tmp := filepath.Join(dir, id+".json.tmp")
	final := filepath.Join(dir, id+".json")
	// 0o666 so the scheduler (any uid) can rewrite/replace if needed.
	if err := os.WriteFile(tmp, body, 0o666); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write intent: "+err.Error())
		return ""
	}
	if err := os.Rename(tmp, final); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rename intent: "+err.Error())
		return ""
	}
	_ = os.Chmod(final, 0o666)
	return id
}
