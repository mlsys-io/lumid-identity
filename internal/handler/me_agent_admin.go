package handler

// Admin control-plane tools for the me-agent chatbox.
//
// Closes a control-parity gap surfaced by the qa-sentinel dogfood loop: the
// admin user-management surface (list users, set role/status) existed only in
// the UI, with no chatbox equivalent. These tools let an admin drive it
// conversationally. They are:
//   - advertised ONLY to admin/super_admin (buildToolDefsForRole),
//   - re-checked at dispatch (defense in depth),
//   - audited via writeAudit, and
//   - the mutating ones are in destructiveTools so they pause for approval.
//
// They reuse the same GORM helpers as the AdminUsers* HTTP handlers
// (toUserRow / countActiveTokensByUser / lastLoginByUserID /
// revokeUserSessionsAndTokens / writeAudit) — single source of truth.

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// userEmail looks up a user's email for bridge-JWT minting. Returns "" if not
// found (the bridge mint tolerates an empty email).
func userEmail(userID string) string {
	var u models.User
	if err := common.DB.Select("email").Where("id = ?", userID).First(&u).Error; err == nil {
		return u.Email
	}
	return ""
}

// adminToolDefs returns the admin-only chatbox tool definitions. Appended in
// buildToolDefsForRole only when the caller is admin/super_admin, so the model
// never sees them otherwise.
func adminToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name": "admin_users",
			"description": "List/search platform users (admin only). Returns id, email, role, " +
				"status, active token count, last login. Use before set_user_role/status.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"q":      map[string]any{"type": "string", "description": "case-insensitive substring match on email or name"},
					"status": map[string]any{"type": "string", "enum": []string{"active", "suspended", "pending", "all"}, "description": "filter by status (default all)"},
					"role":   map[string]any{"type": "string", "enum": []string{"user", "admin", "super_admin", "all"}, "description": "filter by role (default all)"},
					"limit":  map[string]any{"type": "integer", "description": "max rows (default 50, max 200)"},
				},
			},
		},
		{
			"name": "admin_set_user_role",
			"description": "Set a user's role (admin only). Promoting to super_admin requires the " +
				"caller to be super_admin. Cannot change your own role. Audited.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_id": map[string]any{"type": "string", "description": "target user id (or use email)"},
					"email":   map[string]any{"type": "string", "description": "target user email (alternative to user_id)"},
					"role":    map[string]any{"type": "string", "enum": []string{"user", "admin", "super_admin"}},
				},
				"required": []string{"role"},
			},
		},
		{
			"name": "admin_set_user_status",
			"description": "Set a user's status (admin only). 'suspended' immediately revokes their " +
				"tokens + sessions. Cannot change your own status. Audited.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_id": map[string]any{"type": "string", "description": "target user id (or use email)"},
					"email":   map[string]any{"type": "string", "description": "target user email (alternative to user_id)"},
					"status":  map[string]any{"type": "string", "enum": []string{"active", "suspended", "pending"}},
				},
				"required": []string{"status"},
			},
		},
		{
			"name": "admin_grant_access",
			"description": "Grant or revoke a user's per-service access level (admin only). " +
				"service ∈ lumid/qa/runmesh/lumilake/flowmesh/xpcloud; level ∈ none/read/write/admin " +
				"('none' revokes the default). Audited. Equivalent to the access matrix UI.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_id": map[string]any{"type": "string", "description": "target user id (or use email)"},
					"email":   map[string]any{"type": "string", "description": "target user email (alternative to user_id)"},
					"service": map[string]any{"type": "string", "enum": accessServices},
					"level":   map[string]any{"type": "string", "enum": []string{"none", "read", "write", "admin"}},
				},
				"required": []string{"service", "level"},
			},
		},
	}
}

// toolAdminGrantAccess mirrors AdminUsersAccessPut (admin_users.go) — upserts a
// user_access_grants row. Admin-gated; audited.
func toolAdminGrantAccess(c *gin.Context, userID, role string, args map[string]any) (map[string]any, bool) {
	if !isAdminRole(role) {
		return map[string]any{"error": "this action requires admin or super_admin"}, false
	}
	svc := strings.ToLower(strings.TrimSpace(toStr(args["service"])))
	level := strings.ToLower(strings.TrimSpace(toStr(args["level"])))
	if !containsStr(accessServices, svc) {
		return map[string]any{"error": "service must be one of " + strings.Join(accessServices, "/")}, false
	}
	if !validGrantLevels[level] {
		return map[string]any{"error": "level must be none|read|write|admin"}, false
	}
	target, ok := resolveTargetUser(args)
	if !ok {
		return map[string]any{"error": "target user not found — pass a valid user_id or email"}, false
	}
	var row models.UserAccessGrant
	if err := common.DB.Where("user_id = ? AND service = ?", target.ID, svc).First(&row).Error; err != nil {
		row = models.UserAccessGrant{ID: uuid.NewString(), UserID: target.ID, Service: svc, Level: level, GrantedBy: userID}
		if err := common.DB.Create(&row).Error; err != nil {
			return map[string]any{"error": "persist: " + err.Error()}, false
		}
	} else {
		row.Level = level
		row.GrantedBy = userID
		if err := common.DB.Save(&row).Error; err != nil {
			return map[string]any{"error": "persist: " + err.Error()}, false
		}
	}
	writeAudit(c, userID, target.ID, "access:grant", fmt.Sprintf("service=%s level=%s (via chatbox)", svc, level))
	return map[string]any{"updated": true, "user_id": target.ID, "service": svc, "level": level}, true
}

func isAdminRole(role string) bool {
	return role == "admin" || role == "super_admin"
}

// toolAdminUsersList mirrors AdminUsersList (admin_users.go) but returns a map.
func toolAdminUsersList(role string, args map[string]any) (map[string]any, bool) {
	if !isAdminRole(role) {
		return map[string]any{"error": "admin_users requires admin or super_admin"}, false
	}
	q, _ := args["q"].(string)
	statusF, _ := args["status"].(string)
	roleF, _ := args["role"].(string)
	limit := 50
	if v, ok := args["limit"].(float64); ok && int(v) > 0 {
		limit = int(v)
	}
	if limit > 200 {
		limit = 200
	}

	db := common.DB.Model(&models.User{})
	switch strings.ToLower(statusF) {
	case "active", "suspended", "pending":
		db = db.Where("status = ?", strings.ToLower(statusF))
	}
	switch strings.ToLower(roleF) {
	case "user", "admin", "super_admin":
		db = db.Where("role = ?", strings.ToLower(roleF))
	}
	if q = strings.TrimSpace(q); q != "" {
		like := "%" + strings.ToLower(q) + "%"
		db = db.Where("LOWER(email) LIKE ? OR LOWER(name) LIKE ?", like, like)
	}
	var rows []models.User
	if err := db.Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return map[string]any{"error": "query failed: " + err.Error()}, false
	}
	ids := make([]string, 0, len(rows))
	for _, u := range rows {
		ids = append(ids, u.ID)
	}
	toks := countActiveTokensByUser(ids)
	ll := lastLoginByUserID(ids)
	out := make([]userRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, toUserRow(u, toks[u.ID], ll[u.ID]))
	}
	return map[string]any{"users": out, "count": len(out)}, true
}

// resolveTargetUser resolves a target by user_id or email.
func resolveTargetUser(args map[string]any) (models.User, bool) {
	var u models.User
	if id, _ := args["user_id"].(string); strings.TrimSpace(id) != "" {
		if err := common.DB.Where("id = ?", id).First(&u).Error; err == nil {
			return u, true
		}
	}
	if email, _ := args["email"].(string); strings.TrimSpace(email) != "" {
		if err := common.DB.Where("email = ?", strings.ToLower(strings.TrimSpace(email))).First(&u).Error; err == nil {
			return u, true
		}
	}
	return u, false
}

// toolAdminUsersSet handles admin_set_user_role / admin_set_user_status.
// field is "role" or "status". Mirrors AdminUsersPatch semantics.
func toolAdminUsersSet(c *gin.Context, userID, role, field string, args map[string]any) (map[string]any, bool) {
	if !isAdminRole(role) {
		return map[string]any{"error": "this action requires admin or super_admin"}, false
	}
	target, ok := resolveTargetUser(args)
	if !ok {
		return map[string]any{"error": "target user not found — pass a valid user_id or email"}, false
	}
	if target.ID == userID {
		return map[string]any{"error": "cannot change your own role or status — ask another admin"}, false
	}

	updates := map[string]any{}
	var detail string
	switch field {
	case "role":
		v := strings.ToLower(strings.TrimSpace(toStr(args["role"])))
		if v != "user" && v != "admin" && v != "super_admin" {
			return map[string]any{"error": "role must be user|admin|super_admin"}, false
		}
		if v == "super_admin" && role != "super_admin" {
			return map[string]any{"error": "only super_admin can promote to super_admin"}, false
		}
		updates["role"] = v
		detail = fmt.Sprintf("role=%s→%s", target.Role, v)
	case "status":
		v := strings.ToLower(strings.TrimSpace(toStr(args["status"])))
		if v != "active" && v != "suspended" && v != "pending" {
			return map[string]any{"error": "status must be active|suspended|pending"}, false
		}
		updates["status"] = v
		detail = fmt.Sprintf("status=%s→%s", target.Status, v)
	default:
		return map[string]any{"error": "unknown field"}, false
	}

	if err := common.DB.Model(&models.User{}).Where("id = ?", target.ID).Updates(updates).Error; err != nil {
		return map[string]any{"error": "persist: " + err.Error()}, false
	}
	writeAudit(c, userID, target.ID, "admin:user:patch", detail+" (via chatbox)")

	if field == "status" && updates["status"] == "suspended" {
		revokeUserSessionsAndTokens(target.ID, "admin:user:suspend (chatbox)")
	}

	var after models.User
	common.DB.Where("id = ?", target.ID).First(&after)
	toks := countActiveTokensByUser([]string{after.ID})
	ll := lastLoginByUserID([]string{after.ID})
	return map[string]any{"updated": true, "user": toUserRow(after, toks[after.ID], ll[after.ID])}, true
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}
