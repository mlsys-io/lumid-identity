package handler

// Kind-aware marketplace actions — the hierarchy contract.
//
// xp.io repo kinds are hierarchical, not flat: apps INSTALL; skills are
// IMPORTED by apps (xpcloud.yaml skill_imports[]); knowledge agents are
// SUBSCRIBED into the caller's KG; datasets are MOUNTED by apps; strategy/
// workflow are browse-only. This file holds:
//
//   - marketplaceRepoKind / kindInstallPointer — the install kind-gate
//     helpers used by MeAppsInstall (fail-open: the Python installer is the
//     authoritative backstop with identical messages).
//   - POST /me/apps/:app/skills        — queue an `add_skill` intent: append
//     {repo, version} to an INSTALLED tenant app's local xpcloud.yaml and
//     pull the skill files into the tenant's skills root. Tenant-owned apps
//     only (operator-shared bundles are read-only to users).
//   - POST /me/knowledge/subscriptions — queue a `subscribe_bank` intent:
//     delta-sync a published kind=agent bank into the caller's KG (the
//     picker's existing _process_subscribe_bank does the work).
//
// Like every /me/apps mutation, the filesystem writes happen in the
// lumid-scheduler picker (one writer, one UID) — these endpoints validate
// and write intent envelopes only; the UI polls the intent result.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// marketplaceRepoKind resolves an owner/name slug's kind from xpcloud.
// Returns "" (= fail open) for bare names, drafts, or xpcloud errors.
func marketplaceRepoKind(c *gin.Context, slug string) string {
	if !strings.Contains(slug, "/") || strings.HasSuffix(slug, "-draft") {
		return ""
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()
	resp, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/repos/"+slug)
	if err != nil {
		return ""
	}
	kind, _ := resp["kind"].(string)
	return kind
}

// kindInstallPointer mirrors sdk/ops/apps.py's per-kind error wording so the
// UI shows the same guidance whichever layer catches the install.
func kindInstallPointer(kind, slug string) string {
	switch kind {
	case "skill":
		return "this is a skill — skills are imported by apps, not installed standalone. Use 'Add to app…' on the marketplace, or add it to an app's xpcloud.yaml skill_imports[]"
	case "agent":
		return "this is a knowledge agent — subscribe instead of installing. Use 'Subscribe' on the marketplace, or `lumid xp subscribe --source-slug " + slug + "`"
	case "dataset":
		return "this is a dataset — datasets are mounted by apps via xpcloud.yaml datasets[], not installed standalone"
	case "strategy":
		return "this is a strategy — strategies run on Lumid Market, not as installed apps"
	case "workflow":
		return "this is a workflow repo — workflows run inside apps (xpcloud.yaml loops[]), not as standalone installs"
	}
	return fmt.Sprintf("kind=%s repos are not installable as apps", kind)
}

type meAddSkillBody struct {
	SkillRepo string `json:"skill_repo" binding:"required"` // owner/name
	Version   string `json:"version"`                       // optional; picker defaults to repo head
}

// MeAppAddSkill — POST /me/apps/:app/skills
// Queues an add_skill intent for an installed tenant app. 202 {intent_id}.
func MeAppAddSkill(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) || strings.Contains(app, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	var body meAddSkillBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.SkillRepo) || !strings.Contains(body.SkillRepo, "/") {
		fail(c, http.StatusBadRequest, 1400, "skill_repo must be owner/name")
		return
	}

	// Target must be a TENANT-owned install — operator-shared bundles are
	// read-only to users (different UID; and editing a shared app would
	// change it for everyone).
	appDir := filepath.Join(tenantAppsDir(userID), app)
	if st, err := os.Stat(appDir); err != nil || !st.IsDir() {
		// Distinguish "shared, not yours" from "not installed at all" for a
		// clearer message.
		if shared := resolveAppDir(userID, app); shared != "" {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		fail(c, http.StatusNotFound, 1404, "app not installed in your account")
		return
	}

	// Best-effort kind check — adding a non-skill repo to skill_imports would
	// just break the app's next cycle. Fail-open on lookup errors.
	if kind := marketplaceRepoKind(c, body.SkillRepo); kind != "" && kind != "skill" {
		fail(c, http.StatusUnprocessableEntity, 1422, "repo "+body.SkillRepo+" is kind="+kind+", not a skill")
		return
	}

	id := writeIntent(c, "add_skill", userID, map[string]any{
		"app":        app,
		"skill_repo": body.SkillRepo,
		"version":    body.Version,
	})
	if id == "" {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "intent queued",
		"data": gin.H{"intent_id": id, "status": "pending"},
	})
}

type meSubscribeBody struct {
	SourceSlug    string `json:"source_slug" binding:"required"` // owner/name of a kind=agent repo
	TargetAgentID string `json:"target_agent_id"`                // optional; picker defaults to repo name
}

// MeKnowledgeSubscribe — POST /me/knowledge/subscriptions
// Queues a subscribe_bank intent (delta-sync a published agent bank into the
// caller's tenant KG). 202 {intent_id}.
func MeKnowledgeSubscribe(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body meSubscribeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.SourceSlug) || !strings.Contains(body.SourceSlug, "/") {
		fail(c, http.StatusBadRequest, 1400, "source_slug must be owner/name")
		return
	}
	if body.TargetAgentID != "" && !slugRe.MatchString(body.TargetAgentID) {
		fail(c, http.StatusBadRequest, 1400, "invalid target_agent_id")
		return
	}
	// Best-effort: subscribing to a non-agent repo would pull nothing useful.
	if kind := marketplaceRepoKind(c, body.SourceSlug); kind != "" && kind != "agent" {
		fail(c, http.StatusUnprocessableEntity, 1422, "repo "+body.SourceSlug+" is kind="+kind+", not a knowledge agent")
		return
	}

	id := writeIntent(c, "subscribe_bank", userID, map[string]any{
		"source_slug":     body.SourceSlug,
		"target_agent_id": body.TargetAgentID,
	})
	if id == "" {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "intent queued",
		"data": gin.H{"intent_id": id, "status": "pending"},
	})
}
