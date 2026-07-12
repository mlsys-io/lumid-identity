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
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

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
	// Kind gate — installable ACTOR kinds only. Post the unified-component
	// rename (sdk/kinds.py): `agent` is the deployable actor (was `app`;
	// normalize_kind folds app→agent), so BOTH are installable; `memory` is
	// the knowledge-bank kind you subscribe to (was the old `agent`). Skills
	// are imported, datasets mounted, strategy/workflow browse-only. Fail-OPEN
	// when the kind can't be resolved (bare slugs, drafts, xpcloud down) — the
	// Python installer re-checks authoritatively and returns the same pointers.
	switch kind := marketplaceRepoKind(c, body.Slug); kind {
	case "", "app", "agent", "autoresearch":
		// installable — proceed
	default:
		fail(c, http.StatusUnprocessableEntity, 1422, kindInstallPointer(kind, body.Slug))
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

// POST /api/v1/me/apps/:app/update — pull upstream updates into an installed
// app (three-way merge via ops.app_update). Queued as an intent the scheduler
// runs (it has the venv + tenant mounts), same pattern as install/uninstall.
func MeAppUpdate(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	var body struct {
		DryRun bool `json:"dry_run"`
	}
	_ = c.ShouldBindJSON(&body) // optional
	id := writeIntent(c, "update", userID, map[string]any{"app": app, "dry_run": body.DryRun})
	if id == "" {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "update queued",
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
		Name     string `json:"name"`
		HasMfst  bool   `json:"has_manifest"`
		HasXPCld bool   `json:"has_xpcloud"`
		HasOverr bool   `json:"has_user_overrides"`
		Tenant   bool   `json:"tenant"` // true = this user's tenant root; false = operator-shared
		Status   string `json:"status"` // "ready" | "installing" | "failed"
		Error    string `json:"error,omitempty"`
		UI       *appUI `json:"ui,omitempty"` // optional Studio sidebar + surface declaration (xpcloud.yaml::ui)
	}
	out := make([]appCard, 0, 16)
	onDisk := map[string]bool{} // names backed by a real install (dedupe vs pending intents)

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
			_, mfstOK := ResolveManifestPath(dir)
			_, xpOK := ResolveSpecPath(dir)
			_, ovErr := os.Stat(filepath.Join(dir, ".user-overrides.yaml"))
			// Best-effort parse of the optional ui: block (nil when absent
			// or unparseable) so the Studio sidebar can render app-declared
			// entries + surfaces. readAppUI lives in me_app_ui.go.
			var ui *appUI
			if xpOK {
				ui = readAppUI(dir)
			}
			onDisk[e.Name()] = true
			out = append(out, appCard{
				Name:     e.Name(),
				HasMfst:  mfstOK,
				HasXPCld: xpOK,
				HasOverr: ovErr == nil,
				Tenant:   isTenant,
				Status:   "ready",
				UI:       ui,
			})
		}
	}
	// Caller's own tenant — primary surface.
	walk(tenantAppsDir(userID), true)
	// Operator-shared apps (existing ~/.xp/apps tree) appear after,
	// flagged tenant:false so the UI can show them as read-only.
	walk(filepath.Join(operatorHome(), ".xp", "apps"), false)

	// Merge in-flight + failed installs for THIS caller so an optimistic
	// card shows immediately (the picker writes the real dir up to ~60s
	// later). Strictly user_sub-filtered: the me-intents dir is shared
	// across users, so an unfiltered scan would leak other tenants' installs.
	for _, pc := range pendingInstallCards(userID, onDisk) {
		out = append(out, appCard{
			Name:   pc.name,
			Tenant: true,
			Status: pc.status,
			Error:  pc.err,
		})
	}

	// Cross-node enrichment: on UKS identity (svc node) can't read the
	// scheduler's app PVC (compute node, RWO), and kind=agent apps install to
	// .xp/agents (not the .xp/apps dir walk() scans) — so tenant cards arrive
	// as bare DB stubs with no ui: block, and the Studio sidebar has nothing to
	// render. Backfill the ui: (+ mark xpcloud-backed) from the caller's
	// PUBLISHED xp.io spec, the same fallback MeAppConfig uses. Best-effort;
	// only for ready tenant cards missing a ui block.
	for i := range out {
		if !out[i].Tenant || out[i].Status != "ready" || out[i].UI != nil {
			continue
		}
		if spec, ok := fetchRepoSpecYAML(userID, out[i].Name); ok {
			if ui := parseAppUI(spec); ui != nil {
				out[i].UI = ui
			}
			out[i].HasXPCld = true
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"apps": out},
	})
	return // (kept to mirror the early-return on error below; non-fatal)
}

// pendingCard is a synthetic app card derived from an unresolved or failed
// install intent (no on-disk app yet).
type pendingCard struct {
	name   string
	status string // "installing" | "failed"
	err    string
}

// pendingInstallCards reads THIS user's install intents from the DB queue and
// returns synthetic My-Apps cards. On UKS identity can't see the scheduler's
// apps PVC (different node, RWO), so `onDisk` is usually empty and the DB queue
// doubles as the node-agnostic install registry: a `done` row surfaces as a
// `ready` card here even though the file isn't locally visible. user_sub
// filtering is mandatory. Newest intent per app name wins.
func pendingInstallCards(userSub string, onDisk map[string]bool) []pendingCard {
	var rows []models.MeAppIntent
	if err := common.DB.
		Where("user_sub = ? AND action = ?", userSub, "install").
		Order("created_at desc").
		Limit(200).
		Find(&rows).Error; err != nil {
		return nil
	}
	seen := map[string]bool{}
	var cards []pendingCard
	for i := range rows {
		r := rows[i]
		var payload map[string]any
		if r.Payload != "" {
			_ = json.Unmarshal([]byte(r.Payload), &payload)
		}
		appName := installAppName(payload)
		if appName == "" || onDisk[appName] || seen[appName] {
			continue
		}
		switch r.Status {
		case "done":
			seen[appName] = true
			ok, msg := true, ""
			if r.Result != "" {
				ok, msg = installResultOK([]byte(r.Result))
			}
			if ok {
				cards = append(cards, pendingCard{name: appName, status: "ready"})
			} else {
				cards = append(cards, pendingCard{name: appName, status: "failed", err: msg})
			}
		case "failed":
			seen[appName] = true
			_, msg := installResultOK([]byte(r.Result))
			if msg == "" {
				msg = "install failed"
			}
			cards = append(cards, pendingCard{name: appName, status: "failed", err: msg})
		default: // pending | claimed
			// Age guard: skip stale (>1h) unresolved intents so a dead/abandoned
			// intent doesn't clutter My Apps forever.
			if time.Since(r.CreatedAt) > time.Hour {
				continue
			}
			seen[appName] = true
			cards = append(cards, pendingCard{name: appName, status: "installing"})
		}
	}
	return cards
}

// installResultOK interprets a picker result file. The picker writes
// top-level `ok:true` to mean "intent processed" even when the install
// itself failed — the real failure is nested in `data` as an HTTP-ish
// status (>=400) and/or an `error`/`body.detail` string. Returns
// (success, errorMessage).
func installResultOK(rb []byte) (bool, string) {
	var res struct {
		OK    bool           `json:"ok"`
		Error string         `json:"error"`
		Data  map[string]any `json:"data"`
	}
	if json.Unmarshal(rb, &res) != nil {
		return false, "install failed"
	}
	if !res.OK {
		if res.Error != "" {
			return false, res.Error
		}
		return false, "install failed"
	}
	// ok:true — inspect the nested data for an embedded failure.
	if res.Data != nil {
		if st, ok := res.Data["status"].(float64); ok && st >= 400 {
			if e, _ := res.Data["error"].(string); e != "" {
				return false, e
			}
			if body, ok := res.Data["body"].(map[string]any); ok {
				if d, _ := body["detail"].(string); d != "" {
					return false, d
				}
			}
			return false, "install failed (HTTP " + strconv.Itoa(int(st)) + ")"
		}
		if e, _ := res.Data["error"].(string); e != "" {
			return false, e
		}
	}
	return true, ""
}

// installAppName derives the display name for an install intent from its
// payload: the explicit `as` rename, else the last path segment of the slug.
func installAppName(payload map[string]any) string {
	if payload == nil {
		return ""
	}
	if as, _ := payload["as"].(string); strings.TrimSpace(as) != "" {
		return strings.TrimSpace(as)
	}
	slug, _ := payload["slug"].(string)
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return ""
	}
	if i := strings.LastIndex(slug, "/"); i >= 0 {
		slug = slug[i+1:]
	}
	return strings.TrimSuffix(slug, "-draft")
}

// GET /api/v1/me/intents/:id — fetch intent status + result from the DB queue.
// Returns status "completed" once the picker posts a result (done|failed),
// else "pending". The bearer column is NEVER included in the returned
// envelope (it lives outside `payload`).
func MeIntentGet(c *gin.Context) {
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !meIntentIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid intent id")
		return
	}
	var row models.MeAppIntent
	if err := common.DB.Where("id = ?", id).First(&row).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "intent not found")
		return
	}
	var payload map[string]any
	if row.Payload != "" {
		_ = json.Unmarshal([]byte(row.Payload), &payload)
	}
	envelope := gin.H{
		"intent_id":  row.ID,
		"action":     row.Action,
		"user_sub":   row.UserSub,
		"created_at": row.CreatedAt.UTC().Format(time.RFC3339),
		"payload":    payload,
	}
	if row.Status == "done" || row.Status == "failed" {
		var result map[string]any
		if row.Result != "" {
			_ = json.Unmarshal([]byte(row.Result), &result)
		}
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

// MeInstallIntentDelete — DELETE /me/install-intents/:name. Permanently
// removes the caller's install intent(s) for an app NAME (json + result),
// so a failed/optimistic install card can actually be dismissed. Scoped to
// the caller's own intents (user_sub match); path-traversal blocked. This is
// a synchronous file delete — no picker round-trip — because a failed install
// has no app on disk to uninstall.
func MeInstallIntentDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	name := c.Param("name")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	// Delete THIS user's install intents whose derived app name matches.
	var rows []models.MeAppIntent
	if err := common.DB.Where("user_sub = ? AND action = ?", userID, "install").
		Find(&rows).Error; err != nil {
		ok_(c, "dismissed", gin.H{"removed": 0})
		return
	}
	var delIDs []string
	for i := range rows {
		var payload map[string]any
		if rows[i].Payload != "" {
			_ = json.Unmarshal([]byte(rows[i].Payload), &payload)
		}
		if installAppName(payload) == name {
			delIDs = append(delIDs, rows[i].ID)
		}
	}
	if len(delIDs) > 0 {
		common.DB.Where("id IN ?", delIDs).Delete(&models.MeAppIntent{})
	}
	ok_(c, "dismissed", gin.H{"removed": len(delIDs)})
}

// writeIntent enqueues an intent into the DB-backed queue (see
// me_intents_db.go / models.MeAppIntent) and returns its id. Replaces the old
// pod-local file queue, which never crossed from identity to the scheduler on
// UKS. On failure it writes a fail() response to c and returns "".
func writeIntent(c *gin.Context, action, userSub string, payload map[string]any) string {
	id, err := insertIntent(action, userSub, payload)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "queue intent: "+err.Error())
		return ""
	}
	return id
}
