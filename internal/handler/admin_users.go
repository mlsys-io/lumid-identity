package handler

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

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
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	EmailVerified      bool       `json:"email_verified"`
	Name               string     `json:"name,omitempty"`
	AvatarURL          string     `json:"avatar_url,omitempty"`
	Role               string     `json:"role"`
	Status             string     `json:"status"`
	InvitationCodeUsed string     `json:"invitation_code_used,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	// Derived on read only.
	ActiveTokenCount int       `json:"active_token_count"`
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
	case "user", "admin":
		db = db.Where("role = ?", role)
	case "all", "":
	default:
		fail(c, http.StatusBadRequest, 1001, "role must be user|admin|all")
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
		if v != "user" && v != "admin" {
			fail(c, http.StatusBadRequest, 1001, "role must be user|admin")
			return
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

var accessServices = []string{"lumid", "qa", "runmesh", "lumilake", "flowmesh", "xpcloud"}

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

	rows := make([]accessRow, 0, len(accessServices))
	for _, svc := range accessServices {
		rows = append(rows, computeAccess(svc, u, toks))
	}
	ok(c, "ok", gin.H{"user_id": id, "access": rows})
}

func computeAccess(svc string, u models.User, toks []models.Token) accessRow {
	if u.Status != "active" {
		return accessRow{Service: svc, Level: "none", Source: "suspended"}
	}
	if u.Role == "admin" {
		return accessRow{Service: svc, Level: "admin", Source: "role"}
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

// canGrant reports whether the calling user is allowed to mint a PAT
// with the given scope, based on their matrix row for the target service.
// Admin role can always grant anything (matches the matrix's role=admin
// → admin-everywhere rule). Global wildcards require admin role.
func canGrant(u models.User, toks []models.Token, rawScope string) bool {
	svc, lvl := parseScope(rawScope)
	if svc == "" {
		return false
	}
	if u.Role == "admin" {
		return true
	}
	if svc == "*" {
		// Non-admins can never mint global wildcards.
		return false
	}
	row := computeAccess(svc, u, toks)
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
	case "user", "admin":
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
		for _, svc := range accessServices {
			row = append(row, computeAccess(svc, u, tokensByUser[u.ID]).Level)
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
	row := models.AuditLog{
		UserID:    targetID,
		Event:     event,
		Source:    "admin-web",
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		IP:        c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	}
	if actorID != "" {
		// Encode the actor in UserAgent suffix since we don't have a
		// dedicated column; easier than a schema change. Format lets a
		// later migration pull it back out.
		row.UserAgent = fmt.Sprintf("%s | actor=%s | %s", row.UserAgent, actorID, detail)
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

	r2 := common.DB.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	n += r2.RowsAffected
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
