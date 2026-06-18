package handler

// Account self-service tools for the me-agent chatbox — close the
// account.pat / account.profile parity gaps. These operate on the CALLER's own
// account only (no role gate; every user manages their own tokens/profile).
// Minting is deliberately omitted: a freshly-minted PAT secret would land in
// the chat transcript, so creation stays in the dashboard. List + revoke +
// profile-rename are safe to drive from chat.

import (
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func accountToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "account_list_pat",
			"description": "List YOUR active personal access tokens (id, name, prefix, scopes, last used). No secrets are returned.",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "account_revoke_pat",
			"description": "Revoke one of YOUR personal access tokens by id (use account_list_pat to find the id). Irreversible.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string", "description": "the token id to revoke"},
				},
				"required": []string{"id"},
			},
		},
		{
			"name":        "account_set_profile",
			"description": "Update YOUR own display name.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "new display name (1-80 chars)"},
				},
				"required": []string{"name"},
			},
		},
		{
			"name": "delete_loop",
			"description": "Delete a workflow/loop from one of YOUR apps. Its run history is " +
				"archived (not destroyed). Can't remove the last workflow in an app.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"app":  map[string]any{"type": "string", "description": "the app slug (must be your own tenant app)"},
					"loop": map[string]any{"type": "string", "description": "the loop/workflow name to remove"},
				},
				"required": []string{"app", "loop"},
			},
		},
	}
}

// toolDeleteLoop removes a loop from the caller's own app, reusing the same
// helper as the HTTP MeLoopDelete handler.
func toolDeleteLoop(userID string, args map[string]any) (map[string]any, bool) {
	app := strings.TrimSpace(toStr(args["app"]))
	loop := strings.TrimSpace(toStr(args["loop"]))
	if app == "" || loop == "" {
		return map[string]any{"error": "app and loop are required"}, false
	}
	remaining, status, _, msg := removeLoopFromApp(userID, app, loop)
	if status != 200 {
		return map[string]any{"error": msg}, false
	}
	return map[string]any{"deleted": true, "app": app, "loop": loop, "remaining": remaining}, true
}

func toolAccountListPat(userID string) (map[string]any, bool) {
	var rows []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("created_at DESC").Limit(100).Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		item := map[string]any{
			"id":     r.ID,
			"name":   r.Name,
			"prefix": r.Prefix,
			"scopes": strings.Fields(r.Scopes),
			"source": r.Source,
		}
		if r.LastUsedAt != nil {
			item["last_used_at"] = r.LastUsedAt.Unix()
		}
		out = append(out, item)
	}
	return map[string]any{"tokens": out, "count": len(out)}, true
}

func toolAccountRevokePat(c *gin.Context, userID string, args map[string]any) (map[string]any, bool) {
	id := strings.TrimSpace(toStr(args["id"]))
	if id == "" {
		return map[string]any{"error": "token id required (see account_list_pat)"}, false
	}
	var existing models.Token
	if err := common.DB.Where("id = ? AND user_id = ?", id, userID).First(&existing).Error; err != nil {
		return map[string]any{"error": "token not found (must be one of your own)"}, false
	}
	if existing.RevokedAt != nil {
		return map[string]any{"error": "token already revoked"}, false
	}
	if err := common.DB.Model(&existing).Update("revoked_at", gorm.Expr("NOW()")).Error; err != nil {
		return map[string]any{"error": "persist: " + err.Error()}, false
	}
	writeAudit(c, userID, userID, "pat:revoke", "token="+existing.Prefix+"… (via chatbox)")
	return map[string]any{"revoked": true, "id": id}, true
}

func toolAccountSetProfile(c *gin.Context, userID string, args map[string]any) (map[string]any, bool) {
	name := strings.TrimSpace(toStr(args["name"]))
	if name == "" || len(name) > 80 {
		return map[string]any{"error": "name must be 1-80 characters"}, false
	}
	if err := common.DB.Model(&models.User{}).Where("id = ?", userID).
		Update("name", name).Error; err != nil {
		return map[string]any{"error": "persist: " + err.Error()}, false
	}
	writeAudit(c, userID, userID, "profile:update", "name (via chatbox)")
	return map[string]any{"updated": true, "name": name}, true
}
