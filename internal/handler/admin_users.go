package handler

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Admin user management + access matrix.
//
// Surfaces the canonical `lumid_identity.users` row as a first-class
// admin object. Downstream services (QA tbl_user, Runmesh sys_user,
// Lumilake principals) FK or mirror from this row; this file is the
// one place where role / status / active-sessions get edited. The
// cross-service access matrix is computed per-user on demand from
// the role + non-revoked, non-expired Token rows — no shadow table
// to keep in sync.
//
// Every mutating handler writes to models.AuditLog so the
// `/admin/audit` endpoint can surface who did what to whom.

// ---- shapes ----

type userRow struct {
	ID                 string    `json:"id"`
	Email              string    `json:"email"`
	EmailVerified      bool      `json:"email_verified"`
	Name               string    `json:"name,omitempty"`
	AvatarURL          string    `json:"avatar_url,omitempty"`
	Role               string    `json:"role"`
	Status             string    `json:"status"`
	InvitationCodeUsed string    `json:"invitation_code_used,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	// Derived on read only.
	ActiveTokenCount int        `json:"active_token_count"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
}

func toUserRow(u models.User, tokens int, lastLogin *time.Time) userRow {
	return userRow{
		ID:                 u.ID,
		Email:              u.Email,
		EmailVerified:      u.EmailVerified,
		Name:               u.Name,
		AvatarURL:          u.AvatarURL,
		Role:               u.Role,
		Status:             u.Status,
		InvitationCodeUsed: u.InvitationCodeUsed,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
		ActiveTokenCount:   tokens,
		LastLoginAt:        lastLogin,
	}
}

// ---- GET /admin/users ----
//
// Filters: ?status=active|suspended|pending|all (default active)
//          ?role=user|admin|all (default all)
//          ?q=<substring>  (matches email OR name, case-insensitive)
//          ?page=1 &page_size=50 (default 1 / 50, max 200)

func AdminUsersList(c *gin.Context) {
	status := strings.ToLower(c.DefaultQuery("status", "all"))
	role := strings.ToLower(c.DefaultQuery("role", "all"))
	q := strings.TrimSpace(c.Query("q"))

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}

	db := common.DB.Model(&models.User{})
	switch status {
	case "active", "suspended", "pending":
		db = db.Where("status = ?", status)
	case "all", "":
	default:
		fail(c, http.StatusBadRequest, 1001, "status must be active|suspended|pending|all")
		return
	}
	switch role {
	case "user", "admin", "super_admin":
		db = db.Where("role = ?", role)
	case "all", "":
	default:
		fail(c, http.StatusBadRequest, 1001, "role must be user|admin|super_admin|all")
		return
	}
	if q != "" {
		like := "%" + strings.ToLower(q) + "%"
		db = db.Where("LOWER(email) LIKE ? OR LOWER(name) LIKE ?", like, like)
	}

	var total int64
	db.Count(&total)

	var rows []models.User
	db.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&rows)

	// Batch-lookup active token counts + last login per user. Two
	// small aggregate queries beat N+1 per user.
	ids := make([]string, 0, len(rows))
	for _, u := range rows {
		ids = append(ids, u.ID)
	}
	tokensByUser := countActiveTokensByUser(ids)
	lastLoginByUser := lastLoginByUserID(ids)

	out := make([]userRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, toUserRow(u, tokensByUser[u.ID], lastLoginByUser[u.ID]))
	}
	ok(c, "ok", gin.H{
		"users":     out,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ---- GET /admin/users/:id ----

func AdminUsersGet(c *gin.Context) {
	id := c.Param("id")
	var u models.User
	if err := common.DB.Where("id = ?", id).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}
	toks := countActiveTokensByUser([]string{id})
	lastLogin := lastLoginByUserID([]string{id})
	ok(c, "ok", gin.H{"user": toUserRow(u, toks[id], lastLogin[id])})
}

// ---- PATCH /admin/users/:id ----
//
// Updates role and/or status. Audit-logged. Self-demotion / self-suspend
// are rejected so an admin can't accidentally lock themselves out —
// that should go through a second admin.

type patchUserReq struct {
	Role   *string `json:"role,omitempty"`   // "user" | "admin"
	Status *string `json:"status,omitempty"` // "active" | "suspended" | "pending"
}

func AdminUsersPatch(c *gin.Context) {
	id := c.Param("id")
	adminID := c.GetString("admin_user_id")

	var req patchUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid request")
		return
	}
	if req.Role == nil && req.Status == nil {
		fail(c, http.StatusBadRequest, 1001, "at least one of role, status required")
		return
	}
	if adminID != "" && adminID == id {
		fail(c, http.StatusBadRequest, 1001,
			"cannot modify your own role or status — ask another admin")
		return
	}

	var before models.User
	if err := common.DB.Where("id = ?", id).First(&before).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}

	updates := map[string]any{}
	if req.Role != nil {
		v := strings.ToLower(*req.Role)
		if v != "user" && v != "admin" && v != "super_admin" {
			fail(c, http.StatusBadRequest, 1001, "role must be user|admin|super_admin")
			return
		}
		// Only super_admins may promote to super_admin, so a regular
		// admin can't self-elevate by editing another admin.
		if v == "super_admin" {
			callerID, _ := currentUserID(c)
			var caller models.User
			if err := common.DB.Where("id = ?", callerID).First(&caller).Error; err != nil ||
				caller.Role != "super_admin" {
				fail(c, http.StatusForbidden, 1005,
					"only super_admin can promote to super_admin")
				return
			}
		}
		updates["role"] = v
	}
	if req.Status != nil {
		v := strings.ToLower(*req.Status)
		if v != "active" && v != "suspended" && v != "pending" {
			fail(c, http.StatusBadRequest, 1001, "status must be active|suspended|pending")
			return
		}
		updates["status"] = v
	}

	if err := common.DB.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
		return
	}
	// A suspended user's cached claude-sandbox PAT must not survive the
	// suspension (per-pod best effort — other replicas age out on re-mint).
	if s, ok := updates["status"].(string); ok && s == "suspended" {
		invalidateSandboxPATCache(id)
	}

	var after models.User
	common.DB.Where("id = ?", id).First(&after)

	writeAudit(c, adminID, id, "admin:user:patch", fmt.Sprintf(
		"role=%s→%s status=%s→%s",
		before.Role, after.Role, before.Status, after.Status,
	))

	// Suspending a user cascades to token + session revocation so the
	// change takes effect on the next request — not whenever their
	// 24h JWT expires.
	if req.Status != nil && strings.EqualFold(*req.Status, "suspended") {
		revokeUserSessionsAndTokens(id, "admin:user:suspend")
	}

	toks := countActiveTokensByUser([]string{id})
	ll := lastLoginByUserID([]string{id})
	ok(c, "updated", gin.H{"user": toUserRow(after, toks[id], ll[id])})
}

// ---- DELETE /admin/users/:id ----
//
// Hard-deletes the user plus their sessions, tokens, identities,
// password resets, access grants, oauth codes, and SSH keys. Audit
// log rows are kept (compliance trail). Refuses to delete self;
// admin/super_admin rows can only be deleted by a super_admin.
//
// Use case: wiping a test account so a fresh Google sign-in
// reproduces the first-time onboarding flow (invitation-code
// dialog, etc).

func AdminUsersDelete(c *gin.Context) {
	id := c.Param("id")
	adminID := c.GetString("admin_user_id")
	if adminID != "" && adminID == id {
		fail(c, http.StatusBadRequest, 1001, "cannot delete your own account")
		return
	}

	var u models.User
	if err := common.DB.Where("id = ?", id).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}
	if u.Role == "super_admin" || u.Role == "admin" {
		callerID, _ := currentUserID(c)
		var caller models.User
		if err := common.DB.Where("id = ?", callerID).First(&caller).Error; err != nil ||
			caller.Role != "super_admin" {
			fail(c, http.StatusForbidden, 1005,
				"only super_admin can delete admin users")
			return
		}
	}

	// Legacy FIRST, deliberately. The two stores cannot share a transaction
	// (separate databases), so one leg can fail after the other committed --
	// and the two orderings fail very differently:
	//
	//   legacy-then-identity: legacy gone, identity row survives -> the user
	//     still logs in. Not deleted, but nothing is silently resurrected and
	//     no credential outlives its owner. Retry is safe and idempotent.
	//   identity-then-legacy: identity gone, legacy row survives -> the next
	//     login REVIVES the account under a new sub. That is the bug.
	//
	// So the unsafe partial state is the one we refuse to create.
	legacyUsers, legacyTokens, lerr := deleteLegacyUser(u.Email)
	if lerr != nil {
		// Report the failure rather than claiming a deletion that did not
		// happen -- the whole point of this fix.
		fail(c, http.StatusInternalServerError, 1500, "delete (legacy mirror): "+lerr.Error())
		return
	}

	err := common.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", id).Delete(&models.Session{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Token{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.Identity{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.PasswordReset{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.UserAccessGrant{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.OAuthCode{}).Error; err != nil {
			return err
		}
		if err := tx.Where("user_id = ?", id).Delete(&models.SSHKey{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", id).Delete(&models.User{}).Error
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete: "+err.Error())
		return
	}

	writeAudit(c, adminID, id, "admin:user:delete",
		fmt.Sprintf("email=%s role=%s legacy_users=%d legacy_pats=%d",
			u.Email, u.Role, legacyUsers, legacyTokens))
	ok(c, "deleted", gin.H{"id": id})
}

// ---- POST /admin/users/:id/revoke-sessions ----
//
// Kills every active PAT and session for this user without changing
// their account status. Handy for "my laptop got stolen" reports.

func AdminUsersRevokeSessions(c *gin.Context) {
	id := c.Param("id")
	adminID := c.GetString("admin_user_id")

	var u models.User
	if err := common.DB.Where("id = ?", id).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}
	n := revokeUserSessionsAndTokens(id, "admin:user:revoke-sessions")
	writeAudit(c, adminID, id, "admin:user:revoke-sessions",
		fmt.Sprintf("revoked=%d", n))
	ok(c, "revoked", gin.H{"revoked": n})
}

// ---- GET /admin/users/:id/access ----
//
// Access matrix aggregator. For each service we care about, return
// the effective access level based on:
//
//   * user.role == "admin"                            → admin everywhere
//   * user.status != "active"                         → none everywhere
//   * any non-revoked, non-expired PAT carries
//     `<service>:*` or `<service>:admin*`             → admin on that service
//   * any such PAT carries `<service>:…:write` or
//     any other `<service>:…` scope                   → write on that service
//   * user exists + active                            → read (default,
//                                                       inherited from role)
//
// The shape is deliberately flat so the UI can render a grid without
// per-service knowledge.

// `findata` gates a Postgres login on the 1.7 TB warehouse behind sql.lum.id.
// It is GRANTED, never defaulted: MeFindataSQL deliberately reads the explicit
// user_access_grants row rather than calling computeAccess, because
// computeAccess falls back to `best := "read"` for every active user — which
// would entitle the whole user base to a warehouse seat the moment this string
// was added here.
var accessServices = []string{"lumid", "qa", "runmesh", "lumilake", "flowmesh", "xpcloud", "findata"}

type accessRow struct {
	Service string `json:"service"` // lumid | qa | runmesh | lumilake | flowmesh | xpcloud
	Level   string `json:"level"`   // none | read | write | admin
	Source  string `json:"source"`  // role | pat:<prefix>… | suspended
}

func AdminUsersAccess(c *gin.Context) {
	id := c.Param("id")
	var u models.User
	if err := common.DB.Where("id = ?", id).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}
	var toks []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", id).
		Find(&toks)

	grants := loadAccessGrants(id)
	rows := make([]accessRow, 0, len(accessServices))
	for _, svc := range accessServices {
		rows = append(rows, computeAccess(svc, u, toks, grants))
	}
	ok(c, "ok", gin.H{"user_id": id, "access": rows})
}

// accessGrantMap — loaded per user once by the caller, passed in as a
// service→level lookup so computeAccess stays pure. Empty map means
// "no explicit grants, fall through to PAT/role".
type accessGrantMap map[string]string

func loadAccessGrants(userID string) accessGrantMap {
	var rows []models.UserAccessGrant
	common.DB.Where("user_id = ?", userID).Find(&rows)
	out := make(accessGrantMap, len(rows))
	for _, r := range rows {
		out[r.Service] = r.Level
	}
	return out
}

func computeAccess(svc string, u models.User, toks []models.Token, grants accessGrantMap) accessRow {
	if u.Status != "active" {
		return accessRow{Service: svc, Level: "none", Source: "suspended"}
	}
	if u.Role == "admin" || u.Role == "super_admin" {
		src := "role"
		if u.Role == "super_admin" {
			src = "role(super)"
		}
		return accessRow{Service: svc, Level: "admin", Source: src}
	}
	// Explicit admin grant → use it (overrides PAT, matches role
	// semantics for this one service).
	if lvl, ok := grants[svc]; ok {
		return accessRow{Service: svc, Level: lvl, Source: "grant"}
	}
	// Authenticated users default to read everywhere; PATs can only
	// upgrade. Walk each scope through parseScope so legacy flat QA
	// vocabulary (read / trading / strategy / admin) and the canonical
	// `<svc>:<level>` shape both land in the matrix correctly.
	best := "read"
	src := "role"
	for _, t := range toks {
		for _, raw := range strings.Fields(t.Scopes) {
			scopeSvc, scopeLvl := parseScope(raw)
			if scopeSvc == "" {
				continue
			}
			if scopeSvc == "*" {
				// Global wildcard — admin on every service.
				return accessRow{Service: svc, Level: "admin", Source: "pat:" + t.Prefix}
			}
			if scopeSvc != svc {
				continue
			}
			if levelRank(scopeLvl) > levelRank(best) {
				best = scopeLvl
				src = "pat:" + t.Prefix
			}
		}
	}
	return accessRow{Service: svc, Level: best, Source: src}
}

// parseScope canonicalises a raw scope string to (service, level).
// Returns ("*", "admin") for the global wildcard and legacy bare "admin".
// Returns ("", "") for unrecognised scopes — callers should reject them.
//
// Accepted shapes:
//
//	"*"                            → global admin
//	"<svc>:admin" / "<svc>:*"      → admin on <svc>
//	"<svc>:write"                  → write on <svc>
//	"<svc>:read"                   → read on <svc>
//	"admin"                        → global admin (legacy)
//	"read"                         → qa:read   (legacy QuantArena)
//	"trading" / "strategy" / "write" → qa:write (legacy QuantArena)
func parseScope(s string) (service, level string) {
	switch s {
	case "*", "admin":
		return "*", "admin"
	case "read":
		return "qa", "read"
	case "trading", "strategy", "write":
		return "qa", "write"
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	svc, lvl := parts[0], parts[1]
	switch lvl {
	case "*", "admin":
		return svc, "admin"
	case "write":
		return svc, "write"
	case "read":
		return svc, "read"
	}
	return "", ""
}

// levelRank orders the matrix levels so callers can compare "can grant this".
func levelRank(l string) int {
	switch l {
	case "admin":
		return 3
	case "write":
		return 2
	case "read":
		return 1
	}
	return 0
}

// ---- PUT /admin/users/:id/access/:service + DELETE ----
//
// Admin-applied fine-grained access grant. Creates or updates one row
// in user_access_grants; the next matrix render picks it up via
// loadAccessGrants. Level "none" is valid — it explicitly revokes the
// default read for a regular user on that service.

type accessPutReq struct {
	Level string `json:"level"`
}

var validGrantLevels = map[string]bool{
	"none": true, "read": true, "write": true, "admin": true,
}

func AdminUsersAccessPut(c *gin.Context) {
	adminID, _ := currentUserID(c)
	uid := c.Param("id")
	svc := c.Param("service")
	if !containsStr(accessServices, svc) {
		fail(c, http.StatusBadRequest, 1001, "unknown service")
		return
	}
	var req accessPutReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if !validGrantLevels[req.Level] {
		fail(c, http.StatusBadRequest, 1001, "level must be none|read|write|admin")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", uid).First(&u).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "user not found")
		return
	}
	var row models.UserAccessGrant
	err := common.DB.Where("user_id = ? AND service = ?", uid, svc).First(&row).Error
	if err != nil {
		row = models.UserAccessGrant{
			ID: uuid.NewString(), UserID: uid, Service: svc,
			Level: req.Level, GrantedBy: adminID,
		}
		if err := common.DB.Create(&row).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
			return
		}
	} else {
		row.Level = req.Level
		row.GrantedBy = adminID
		if err := common.DB.Save(&row).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
			return
		}
	}
	writeAudit(c, adminID, uid, "access:grant",
		fmt.Sprintf("service=%s level=%s", svc, req.Level))
	ok(c, "updated", gin.H{"service": svc, "level": req.Level})
}

func AdminUsersAccessDelete(c *gin.Context) {
	adminID, _ := currentUserID(c)
	uid := c.Param("id")
	svc := c.Param("service")
	if !containsStr(accessServices, svc) {
		fail(c, http.StatusBadRequest, 1001, "unknown service")
		return
	}
	common.DB.Where("user_id = ? AND service = ?", uid, svc).
		Delete(&models.UserAccessGrant{})
	writeAudit(c, adminID, uid, "access:revoke", "service="+svc)
	ok(c, "deleted", nil)
}

func containsStr(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// capabilityScopes is the allowlist of opaque, non-platform "capability" scope
// tags a plain authenticated user may mint on a PAT. These are NOT service
// access levels: parseScope() deliberately does not recognise them, so they
// never appear in computeAccess()/the access matrix and never widen a user's
// role or per-service level. They are least-privilege capability tags that a
// downstream *consumer* (not this auth authority) interprets — e.g. the LQT
// mailbox-consumer authorizes the `universe.refresh` topic when a PAT carries
// `lqt:universe:refresh`, and nothing else. Adding a tag here lets it be minted
// + persisted + returned by introspection verbatim, with zero platform-access
// side effects. Keep this list NARROW (one entry per real capability), never a
// wildcard.
var capabilityScopes = map[string]bool{
	// LQT monitored-universe refresh — authorizes ONLY the `universe.refresh`
	// mailbox topic in lqt-auth (crates/lqt-auth/src/authz.rs). Not a wildcard.
	"lqt:universe:refresh": true,
	// LQT strategy deployment — authorizes the `strategy.deploy` mailbox topic
	// in lqt-auth (crates/lqt-auth/src/authz.rs::TOPIC_AUTHZ). It lets an LQT
	// user publish/deploy their own strategy. This is a normal user-grantable
	// capability tag: it confers NO platform access here (parseScope ignores it)
	// and does NOT imply admin or real-trade — real-trade is gated separately on
	// the LQT side (super_admin). Not a wildcard; scoped to strategy.deploy only.
	"lqt:strategy": true,
	// FinData warehouse SQL — marks a PAT as intended for warehouse work, and
	// makes minting it ALSO issue the user's Postgres credential (see
	// findataSQLShadowMint). Deliberately a capability tag, not a service scope:
	// it confers no platform access here, and entitlement is still decided by
	// the explicit findata grant plus a provisioned role. A user without those
	// gets a tag that does nothing, which is correct — the tag is intent, the
	// grant is permission.
	"findata:sql": true,
	// Claude account-pool proxy — authorizes ONLY the lum.id/claude reverse
	// proxy (claude-proxy consumer). A PAT carrying this tag can route Claude
	// Code requests through the pooled org accounts; it confers no platform
	// access here.
	"claude:proxy": true,
	// Lumilake jobs — authorizes submitting and reading HALO-optimised jobs on
	// the Lumilake control planes (cloud, home, office; per-site via /ll/<site>/).
	//
	// These are the LITERAL strings Lumilake enforces, and they have to be
	// capability tags because parseScope cannot express them: it splits on the
	// FIRST colon, so "lumilake:jobs:read" reads as service "lumilake", level
	// "jobs:read" -- not a valid level -- and returns ("",""). canGrant's
	// `svc == ""` return sits ABOVE the admin bypass, so before this entry NOBODY
	// could mint them, super_admin included. Measured 2026-09-13: Lumilake at all
	// three sites answered 403 "kind-level write on job requires
	// 'lumilake:jobs:write'" to every credential in the estate, and the platform
	// had no way to issue one.
	//
	// Same shape as lqt:strategy above: opaque here (parseScope ignores it, so
	// computeAccess is unchanged), no platform access, no admin implication, and
	// entitlement still enforced downstream by Lumilake itself. Two entries
	// rather than one wildcard, so read and write stay separable.
	"lumilake:jobs:read":  true,
	"lumilake:jobs:write": true,
	// Cancel completes the jobs triad. The plugin policy has mapped
	// (JOB, CANCEL) -> "lumilake:jobs:cancel" since it was written, but the tag
	// was never added here, so it was ungrantable for exactly the same reason as
	// read/write were before 2026-09-13 -- nobody could cancel a Lumilake job
	// through the platform. Found 2026-09-14 while auditing the policy against
	// this list; separable from write on purpose.
	"lumilake:jobs:cancel": true,
	// Lumilake worker listing -- routes/workers.py enumerates the FlowMesh fleet
	// through Lumilake and requires this exact string (lumid.plugins v0.2.5,
	// where WORKER is also a `fleet_kind`, so holding the scope returns the whole
	// fleet rather than an ownership-filtered empty list).
	//
	// SHIPPING THE PLUGIN SCOPE WITHOUT THIS ENTRY MAKES THE SCOPE UNOBTAINABLE.
	// Measured 2026-09-14: PAT mint answered 403 "scope not grantable:
	// lumilake:workers:read" to super_admin, so the 403 Lumilake returns for a
	// caller lacking it was correct in form and impossible to satisfy. Same
	// first-colon parseScope limitation described above.
	"lumilake:workers:read": true,
	// FlowMesh fleet reads — the exact strings the lumid plugin's policy maps for
	// (WORKER, READ) and (NODE, READ), and the two it declares `fleet_kinds`, so
	// holding one returns the whole fleet rather than an ownership-filtered empty
	// list (lumid.plugins v0.2.4+).
	//
	// Studio already receives these on the aud=flowmesh SESSION-BEARER, which is
	// minted directly and never passes through canGrant — so nothing was broken.
	// What was impossible is carrying them on a PAT: parseScope splits on the FIRST
	// colon, reads the level as "workers:read", and returns ("",""), and canGrant's
	// `svc == ""` sits ABOVE the admin bypass. Measured 2026-09-14 while verifying
	// the Lumilake tags: reading workers through /ll/<site>/ forwards the CALLER's
	// bearer to FlowMesh, so a PAT needed a flowmesh worker-read capability and the
	// only mintable option was the `flowmesh:*` wildcard — strictly more privilege
	// than the job needs. These two entries make least-privilege expressible.
	//
	// READ ONLY, deliberately. The write/cancel counterparts (workers:write,
	// nodes:write, workflows:*, tasks:read, results:*, system:read, ssh) share the
	// same parseScope limitation and stay un-grantable until someone needs them;
	// each is its own decision, not a set to be added wholesale.
	"flowmesh:workers:read": true,
	"flowmesh:nodes:read":   true,
	// The rest of the aud=flowmesh SESSION-BEARER's set, minted for EVERY signed-in
	// user by user.go's `case "flowmesh"`. Making them PAT-mintable changes the
	// CREDENTIAL TYPE, not who may do what: the same person already holds all of
	// these the moment they log in. Without them a PAT cannot run a job end to end —
	// Lumilake forwards the CALLER's bearer to FlowMesh, so a submit that clears
	// Lumilake's own gate then dies on
	//   403 "kind-level write on workflow requires 'flowmesh:workflows:write'"
	// (measured 2026-09-14 with a real role=user, after the object-prefix gate was
	// fixed). The wildcard `flowmesh:*` was the only mintable alternative, which is
	// strictly more privilege than running one job needs.
	//
	// Still NOT here, and each its own decision: workers:write, nodes:write,
	// results:write, system:read. Those are not in the session-bearer set either,
	// so adding them WOULD widen what a signed-in user can do.
	"flowmesh:workflows:write": true,
	"flowmesh:workflows:read":  true,
	"flowmesh:tasks:read":      true,
	"flowmesh:results:read":    true,
	"flowmesh:ssh":             true,
}

// capabilityCatalog is capabilityScopes made SERVABLE: the same allowlist, plus
// the one-line label and description the token UI needs to render a checkbox.
//
// WHY THIS EXISTS. The allowlist above is the authority on what may be minted,
// but nothing published it, so lum.id/studio/account/tokens carried its own
// hardcoded array of two entries (claude:proxy, lqt:strategy) and fell thirteen
// behind. That is not a hypothetical: the comment on lqt:strategy above records
// the SAME failure being fixed once already — a scope the docs told people to
// use while the UI gave them no way to ask for it — and the Lumilake and
// FlowMesh entries added 2026-09-13/14 landed straight back into it. A user who
// needs flowmesh:workflows:write may mint it (canGrant returns true for any
// active user) and has no control that offers it.
//
// So the server now answers "what may I ask for", and the UI renders that.
// init() below refuses to start if the two lists ever drift apart again, which
// is the whole point: a new tag cannot be added to the allowlist and silently
// stay invisible.
type capabilityInfo struct {
	Scope string `json:"scope"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

var capabilityCatalog = []capabilityInfo{
	{"claude:proxy", "Claude proxy",
		"Route Claude Code through the org account pool at lum.id/claude."},
	{"lqt:strategy", "LQT strategy deploy",
		"Submit and deploy your own LQT strategies (the strategy.deploy mailbox topic). Confers no admin and no real-trade — live trading is gated separately."},
	{"lqt:universe:refresh", "LQT universe refresh",
		"Trigger a monitored-universe refresh (the universe.refresh mailbox topic). Nothing else."},
	{"findata:sql", "FinData warehouse SQL",
		"Mark this token for warehouse work and issue your Postgres credential. Entitlement still needs a findata grant."},
	{"lumilake:jobs:read", "Lumilake — read jobs",
		"Read HALO-optimised jobs on the Lumilake control planes."},
	{"lumilake:jobs:write", "Lumilake — submit jobs",
		"Submit jobs to the Lumilake control planes."},
	{"lumilake:jobs:cancel", "Lumilake — cancel jobs",
		"Cancel a running Lumilake job."},
	{"lumilake:workers:read", "Lumilake — read workers",
		"List Lumilake workers and their status."},
	{"flowmesh:workflows:write", "FlowMesh — submit workflows",
		"Submit and cancel FlowMesh workflows. This is what a token needs to run a job end to end; the coarse flowmesh:write service level requires an access grant instead."},
	{"flowmesh:workflows:read", "FlowMesh — read workflows",
		"List FlowMesh workflows and their status."},
	{"flowmesh:tasks:read", "FlowMesh — read tasks",
		"List individual FlowMesh tasks."},
	{"flowmesh:results:read", "FlowMesh — read results",
		"Fetch the outputs of a finished FlowMesh task."},
	{"flowmesh:workers:read", "FlowMesh — read workers",
		"List FlowMesh workers and their hardware."},
	{"flowmesh:nodes:read", "FlowMesh — read nodes",
		"List FlowMesh nodes."},
	{"flowmesh:ssh", "FlowMesh — SSH sessions",
		"Open an SSH session task on a FlowMesh worker."},
}

// The two lists must describe the same set, in both directions. A tag on the
// allowlist with no catalog entry is unmintable-in-practice (invisible in the
// UI); a catalog entry with no allowlist tag is a control that mints a scope
// canGrant will refuse. Failing at startup is deliberate — both mistakes are
// silent at runtime and cost a release to notice.
func init() {
	for _, c := range capabilityCatalog {
		if !capabilityScopes[c.Scope] {
			panic("capabilityCatalog lists " + c.Scope + " which is not on the capabilityScopes allowlist")
		}
	}
	if len(capabilityCatalog) != len(capabilityScopes) {
		for scope := range capabilityScopes {
			found := false
			for _, c := range capabilityCatalog {
				if c.Scope == scope {
					found = true
					break
				}
			}
			if !found {
				panic("capabilityScopes allows " + scope + " but capabilityCatalog does not describe it — the token UI would never offer it")
			}
		}
	}
}

// isCapabilityScope reports whether a raw scope is an opaque LQT-style
// capability tag on the allowlist (see capabilityScopes). Such scopes are
// grantable by any active authenticated user and carry no platform access.
func isCapabilityScope(rawScope string) bool {
	return capabilityScopes[rawScope]
}

// canGrant reports whether the calling user is allowed to mint a PAT
// with the given scope, based on their matrix row for the target service.
// Admin role can always grant anything (matches the matrix's role=admin
// → admin-everywhere rule). Global wildcards require admin role.
func canGrant(u models.User, toks []models.Token, rawScope string) bool {
	// Opaque capability tags (e.g. lqt:universe:refresh) are grantable by any
	// active authenticated user: they confer no platform access (parseScope
	// ignores them, so computeAccess is unchanged) and are enforced by the
	// downstream consumer. This is strictly additive to the matrix logic below.
	if isCapabilityScope(rawScope) {
		return u.Status == "active"
	}
	// "claude-pool:<id>" — see isClaudePoolScope (claude_pool_admin.go).
	if isClaudePoolScope(u.ID, rawScope) {
		return u.Status == "active"
	}
	svc, lvl := parseScope(rawScope)
	if svc == "" {
		return false
	}
	if u.Role == "admin" || u.Role == "super_admin" {
		return true
	}
	if svc == "*" {
		// Non-admins can never mint global wildcards.
		return false
	}
	row := computeAccess(svc, u, toks, loadAccessGrants(u.ID))
	return levelRank(row.Level) >= levelRank(lvl)
}

// ---- GET /admin/users/export.csv ----
//
// Flattens the user list + per-service access into a CSV for offline
// review. Uses the same filter params as AdminUsersList but always
// returns every row (no pagination).

func AdminUsersExportCSV(c *gin.Context) {
	status := strings.ToLower(c.DefaultQuery("status", "all"))
	role := strings.ToLower(c.DefaultQuery("role", "all"))
	q := strings.TrimSpace(c.Query("q"))

	db := common.DB.Model(&models.User{})
	switch status {
	case "active", "suspended", "pending":
		db = db.Where("status = ?", status)
	}
	switch role {
	case "user", "admin", "super_admin":
		db = db.Where("role = ?", role)
	}
	if q != "" {
		like := "%" + strings.ToLower(q) + "%"
		db = db.Where("LOWER(email) LIKE ? OR LOWER(name) LIKE ?", like, like)
	}

	var users []models.User
	db.Order("created_at ASC").Limit(10000).Find(&users)

	// Batch-load tokens once so computeAccess doesn't hit the DB per user.
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	tokensByUser := map[string][]models.Token{}
	if len(ids) > 0 {
		var toks []models.Token
		common.DB.Where("user_id IN ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", ids).
			Find(&toks)
		for _, t := range toks {
			tokensByUser[t.UserID] = append(tokensByUser[t.UserID], t)
		}
	}

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="lumid-users.csv"`)

	w := csv.NewWriter(c.Writer)
	header := []string{"id", "email", "name", "role", "status", "created_at"}
	for _, svc := range accessServices {
		header = append(header, "access_"+svc)
	}
	_ = w.Write(header)

	for _, u := range users {
		row := []string{u.ID, u.Email, u.Name, u.Role, u.Status, u.CreatedAt.Format(time.RFC3339)}
		grants := loadAccessGrants(u.ID)
		for _, svc := range accessServices {
			row = append(row, computeAccess(svc, u, tokensByUser[u.ID], grants).Level)
		}
		_ = w.Write(row)
	}
	w.Flush()
}

// ---- GET /admin/audit ----
//
// Read-only view of the audit log. Filter by user_id + event + time
// window. Append-only; no delete endpoint.

type auditRow struct {
	ID         uint64    `json:"id"`
	UserID     string    `json:"user_id,omitempty"`
	TokenID    string    `json:"token_id,omitempty"`
	Event      string    `json:"event"`
	Source     string    `json:"source,omitempty"`
	App        string    `json:"app,omitempty"`
	Detail     string    `json:"detail,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMs int       `json:"duration_ms,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func AdminAuditList(c *gin.Context) {
	userID := c.Query("user_id")
	event := c.Query("event")
	app := c.Query("app")
	// A cohort question is always "in this window" — without a date range the
	// only way to reach last week is to page through everything since.
	since := c.Query("since")
	until := c.Query("until")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "100"))
	if pageSize < 1 {
		pageSize = 100
	}
	if pageSize > 500 {
		pageSize = 500
	}

	db := common.DB.Model(&models.AuditLog{})
	if userID != "" {
		db = db.Where("user_id = ?", userID)
	}
	if event != "" {
		db = db.Where("event = ?", event)
	}
	if app != "" {
		db = db.Where("app = ?", app)
	}
	// RFC3339 in, half-open [since, until). A malformed bound is rejected
	// rather than dropped: a filter that silently does nothing returns the
	// whole table under a heading claiming a window.
	if since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			fail(c, http.StatusBadRequest, 1400, "since must be RFC3339: "+err.Error())
			return
		}
		db = db.Where("created_at >= ?", t)
	}
	if until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			fail(c, http.StatusBadRequest, 1400, "until must be RFC3339: "+err.Error())
			return
		}
		db = db.Where("created_at < ?", t)
	}

	var total int64
	db.Count(&total)

	var rows []models.AuditLog
	db.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&rows)

	out := make([]auditRow, 0, len(rows))
	for _, r := range rows {
		tokenID := ""
		if r.TokenID != "" {
			tokenID = r.TokenID
		}
		out = append(out, auditRow{
			ID:         r.ID,
			UserID:     r.UserID,
			TokenID:    tokenID,
			Event:      r.Event,
			Source:     r.Source,
			App:        r.App,
			Detail:     r.Detail,
			Method:     r.Method,
			Path:       r.Path,
			Status:     r.Status,
			DurationMs: r.DurationMs,
			IP:         r.IP,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
		})
	}
	ok(c, "ok", gin.H{
		"entries":   out,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ---- helpers ----

// writeAudit inserts an append-only audit row. Safe to call from any
// mutating admin handler — errors are logged and swallowed so a write
// failure doesn't block the parent operation.
func writeAudit(c *gin.Context, actorID, targetID, event, detail string) {
	writeAuditApp(c, actorID, targetID, event, "", detail)
}

// writeAuditApp is writeAudit with an owning xpio app, so per-app analytics can
// slice this table by `app` instead of pattern-matching event names.
func writeAuditApp(c *gin.Context, actorID, targetID, event, app, detail string) {
	writeAuditAppMetrics(c, actorID, targetID, event, app, detail, 0, 0)
}

// writeAuditAppMetrics additionally records the outcome status and how long the
// action took. Both columns were declared on audit_log from the first migration
// and never written by anything, so "how often does this fail and how slow is
// it" was unanswerable for every audited action. Pass 0 to leave either unset.
//
// The detail goes in the `detail` TEXT column. It used to be appended to
// UserAgent — a varchar(255) already holding the browser UA plus the actor —
// on the reasoning that this was "easier than a schema change". That silently
// truncates anything long, which is disqualifying for the thing we most want to
// record here: a compiler diagnostic with character offsets into the user's own
// source. The column was declared from the start and never written to.
//
// The actor stays in the UserAgent suffix. That one IS a deliberate dodge for a
// missing column, the format is parseable, and nothing reads it yet.
func writeAuditAppMetrics(c *gin.Context, actorID, targetID, event, app, detail string, status, durationMs int) {
	row := models.AuditLog{
		UserID:     targetID,
		Event:      event,
		Source:     "admin-web",
		App:        app,
		Method:     c.Request.Method,
		Path:       c.Request.URL.Path,
		Status:     status,
		DurationMs: durationMs,
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
		Detail:     detail,
	}
	if actorID != "" {
		row.UserAgent = fmt.Sprintf("%s | actor=%s", row.UserAgent, actorID)
	}
	_ = common.DB.Create(&row).Error
}

// revokeUserSessionsAndTokens flips revoked_at on every open PAT and
// session for the user. Returns the total rowcount flipped.
func revokeUserSessionsAndTokens(userID, reason string) int {
	now := time.Now()
	var n int64
	r1 := common.DB.Model(&models.Token{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	n += r1.RowsAffected

	// Captured BEFORE the update -- afterwards these rows no longer match
	// `revoked_at IS NULL` and the jtis are unrecoverable.
	doomed := liveSessionsForUser(userID, "")
	r2 := common.DB.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	n += r2.RowsAffected

	// An admin suspending an account expects it dead now, not at cookie expiry.
	denylistSessions(context.Background(), doomed)

	_ = reason
	return int(n)
}

func countActiveTokensByUser(userIDs []string) map[string]int {
	out := map[string]int{}
	if len(userIDs) == 0 {
		return out
	}
	type row struct {
		UserID string
		N      int
	}
	var rows []row
	common.DB.Table("tokens").
		Select("user_id, COUNT(*) as n").
		Where("user_id IN ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", userIDs).
		Group("user_id").
		Scan(&rows)
	for _, r := range rows {
		out[r.UserID] = r.N
	}
	return out
}

func lastLoginByUserID(userIDs []string) map[string]*time.Time {
	out := map[string]*time.Time{}
	if len(userIDs) == 0 {
		return out
	}
	type row struct {
		UserID    string
		CreatedAt time.Time
	}
	var rows []row
	common.DB.Table("sessions").
		Select("user_id, MAX(created_at) as created_at").
		Where("user_id IN ?", userIDs).
		Group("user_id").
		Scan(&rows)
	for _, r := range rows {
		t := r.CreatedAt
		out[r.UserID] = &t
	}
	return out
}

// deleteLegacyUser removes the QuantArena-side mirror of a user.
//
// Signup DUAL-WRITES into legacy `tbl_user` (Signup, oauth_google.go,
// user.go) but deletion used to be single-store, so an account deleted
// here came back on the user's next login: findUserOrMirror re-creates it
// from the surviving legacy row with status=active, the old password hash
// and a *different* sub (uuid5("lqa:<legacy id>")). The 200 "deleted" and
// its audit row were both untrue. Measured 2026-09-14.
//
// Two tables matter, and the second is the sharper edge:
//
//   - tbl_user                        — the revival source.
//   - tbl_rm_personal_access_token    — legacy PATs. introspectLegacyLQA
//     keys ONLY on token_hash and treats the tbl_user lookup as
//     enrichment, so it answers Active:true with the token's scopes
//     intact even when the owning user is gone. Deleting the user
//     without these leaves live credentials behind with an empty role.
//
// Returns the number of legacy rows removed so the audit entry can record
// whether the legacy leg actually ran. A disabled shadow is not an error:
// there is simply nothing to mirror.
func deleteLegacyUser(email string) (users int64, tokens int64, err error) {
	// Gate on the CONNECTION, not on Legacy.Enabled -- the two legacy gates
	// in this codebase are deliberately different and the flag is the weaker
	// one. introspectLegacyLQA checks only `common.LegacyDB == nil`, so legacy
	// PATs keep validating whenever the legacy DB is configured, even with
	// shadow disabled; findUserOrMirror additionally checks the flag. Cleaning
	// up only when the flag is on would leave live credentials behind in the
	// flag-off state, which is exactly the leak this function exists to close.
	// If the legacy DB is reachable at all, its rows are load-bearing.
	if common.LegacyDB == nil {
		return 0, 0, nil
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return 0, 0, nil
	}

	// Collect every legacy id for this email. LQA has no unique constraint
	// on email, so a duplicate row would otherwise survive and revive the
	// account on its own.
	// Scan into an explicit struct slice rather than []int64: gorm's
	// primitive-slice Scan is version-dependent, and this file's other
	// legacy queries already use the tagged-struct form.
	var rows []struct {
		ID int64 `gorm:"column:id"`
	}
	if err := common.LegacyDB.Raw(
		`SELECT id FROM tbl_user WHERE email = ?`, email).Scan(&rows).Error; err != nil {
		return 0, 0, err
	}
	if len(rows) == 0 {
		return 0, 0, nil
	}
	ids := make([]int64, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}

	err = common.LegacyDB.Transaction(func(tx *gorm.DB) error {
		r := tx.Exec(`DELETE FROM tbl_rm_personal_access_token WHERE user_id IN ?`, ids)
		if r.Error != nil {
			return r.Error
		}
		tokens = r.RowsAffected

		r = tx.Exec(`DELETE FROM tbl_user WHERE id IN ?`, ids)
		if r.Error != nil {
			return r.Error
		}
		users = r.RowsAffected
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return users, tokens, nil
}
