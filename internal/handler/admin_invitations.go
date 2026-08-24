package handler

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Admin invitation-code management. Ported from LQA's management UI;
// now lives on lum.id so a single admin pool covers the whole
// ecosystem. UI at /auth/account/admin/invitations.

// ---- middleware ----

// resolveRole returns (userID, role, ok) for a bearer token.
// Handles both JWTs (fast, no DB) and lm_pat_* / rm_pat_* tokens
// (DB lookup for the owning user's role).
func resolveRole(tok string) (userID, role string, ok bool) {
	if claims, err := common.VerifyJWT(tok); err == nil {
		return claims.Subject, claims.Role, true
	}
	if strings.HasPrefix(tok, "lm_pat_") || strings.HasPrefix(tok, "rm_pat_") {
		if row, found := lookupPAT(tok); found {
			var u models.User
			if err := common.DB.Select("id, role").Where("id = ?", row.UserID).First(&u).Error; err == nil {
				return u.ID, u.Role, true
			}
		}
	}
	return "", "", false
}

// RequireAdmin blocks callers whose credential doesn't carry role=admin.
// Accepts session JWTs (lm_session cookie or Authorization header) and
// lm_pat_* / rm_pat_* tokens whose owning account has role=admin|super_admin.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := bearerToken(c)
		if tok == "" {
			fail(c, http.StatusUnauthorized, 1003, "auth required")
			c.Abort()
			return
		}
		userID, role, ok := resolveRole(tok)
		if !ok {
			fail(c, http.StatusUnauthorized, 1003, "invalid session")
			c.Abort()
			return
		}
		if role != "admin" && role != "super_admin" {
			fail(c, http.StatusForbidden, 1005, "admin required")
			c.Abort()
			return
		}
		c.Set("admin_user_id", userID)
		c.Set("admin_user_role", role)
		c.Next()
	}
}

// RequireSuperAdmin — stricter gate than RequireAdmin. Billing and
// accounting routes use this so a regular admin (operations) can't
// touch money-moving endpoints. super_admin inherits everything
// admin can do; additional authority is scoped to this gate.
// Accepts session JWTs and lm_pat_* / rm_pat_* tokens from super_admin accounts.
func RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := bearerToken(c)
		if tok == "" {
			fail(c, http.StatusUnauthorized, 1003, "auth required")
			c.Abort()
			return
		}
		userID, role, ok := resolveRole(tok)
		if !ok {
			fail(c, http.StatusUnauthorized, 1003, "invalid session")
			c.Abort()
			return
		}
		if role != "super_admin" {
			fail(c, http.StatusForbidden, 1005, "super_admin required")
			c.Abort()
			return
		}
		c.Set("admin_user_id", userID)
		c.Next()
	}
}

// SuperAdminCheck — lightweight probe for nginx auth_request.
// Returns 200 if caller is super_admin, 401/403 otherwise (handled by the
// RequireSuperAdmin middleware on this group). nginx forwards the
// lm_session cookie so browser sessions are checked server-side.
func SuperAdminCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// AdminCheck is a no-op probe gated by RequireAdmin (admin or super_admin).
// It exists so edge nginx can auth_request against it to gate internal doc
// routes to admins; reaching here means the role check already passed.
func AdminCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---- handlers ----

type mintInviteReq struct {
	Count   int    `json:"count"`    // how many distinct codes; default 1
	MaxUses int    `json:"max_uses"` // per code; default 1 (0 = unlimited)
	Note    string `json:"note"`
	TTLDays int    `json:"ttl_days"` // 0 = no expiry
	// Space-separated scopes granted on redemption, e.g. "lumid:write".
	// One code with max_uses=20 therefore onboards a whole cohort to an
	// entitlement none of them could self-grant, without an operator ever
	// touching an individual account or holding anyone's credential.
	Scopes string `json:"scopes"`
}

type inviteRow struct {
	Code string `json:"code"`
	Note string `json:"note,omitempty"`
	// Surfaced so an operator listing codes can see WHICH grants each one
	// carries. Once a code confers entitlement rather than mere signup, "what
	// does this code do" stops being answerable from the note field.
	Scopes        string     `json:"scopes,omitempty"`
	MaxUses       int        `json:"max_uses"`
	UsesRemaining int        `json:"uses_remaining"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// POST /api/v1/admin/invitation-codes
func AdminInviteMint(c *gin.Context) {
	adminID := c.GetString("admin_user_id")
	var req mintInviteReq
	_ = c.ShouldBindJSON(&req)
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 100 {
		req.Count = 100
	}
	if req.MaxUses < 0 {
		req.MaxUses = 0
	}
	if req.MaxUses == 0 {
		req.MaxUses = 1
	}
	// Validate scopes HERE, at mint, not at redemption. A bad scope discovered
	// during redeem is discovered by the wrong person: the user has already
	// spent a seat and can do nothing about it, while the operator who made the
	// mistake never sees the error.
	for _, s := range strings.Fields(req.Scopes) {
		svc, _ := parseScope(s)
		if svc == "" {
			fail(c, http.StatusBadRequest, 1001,
				"invalid scope '"+s+"' — expected <service>:<read|write|admin>")
			return
		}
		if svc == "*" {
			// An invitation carrying a wildcard is indistinguishable from
			// handing out admin, and it would do so to every holder of the code.
			fail(c, http.StatusBadRequest, 1001, "wildcard scope is never allowed in an invitation")
			return
		}
	}

	var expAt *time.Time
	if req.TTLDays > 0 {
		t := time.Now().AddDate(0, 0, req.TTLDays)
		expAt = &t
	}

	codes := make([]inviteRow, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		raw, err := randInviteCode()
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "rng")
			return
		}
		row := &models.InvitationCode{
			Code:          raw,
			CreatedByID:   adminID,
			Note:          req.Note,
			Scopes:        strings.Join(strings.Fields(req.Scopes), " "),
			MaxUses:       req.MaxUses,
			UsesRemaining: req.MaxUses,
			ExpiresAt:     expAt,
		}
		if err := common.DB.Create(row).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
			return
		}
		codes = append(codes, inviteRow{
			Code: row.Code, Note: row.Note, Scopes: row.Scopes,
			MaxUses: row.MaxUses, UsesRemaining: row.UsesRemaining,
			ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
		})
	}
	ok(c, "minted", gin.H{"codes": codes, "total": len(codes)})
}

// GET /api/v1/admin/invitation-codes?status=active|revoked|exhausted|all
func AdminInviteList(c *gin.Context) {
	status := strings.ToLower(c.DefaultQuery("status", "active"))
	q := common.DB.Model(&models.InvitationCode{}).Order("created_at DESC")
	switch status {
	case "revoked":
		q = q.Where("revoked_at IS NOT NULL")
	case "exhausted":
		q = q.Where("uses_remaining <= 0 AND revoked_at IS NULL")
	case "active":
		q = q.Where("revoked_at IS NULL AND uses_remaining > 0 AND (expires_at IS NULL OR expires_at > NOW())")
	case "all":
		// no filter
	default:
		fail(c, http.StatusBadRequest, 1001, "status must be active|revoked|exhausted|all")
		return
	}
	var rows []models.InvitationCode
	q.Limit(500).Find(&rows)
	out := make([]inviteRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, inviteRow{
			Code: r.Code, Note: r.Note, Scopes: r.Scopes,
			MaxUses: r.MaxUses, UsesRemaining: r.UsesRemaining,
			ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
			LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt,
		})
	}
	ok(c, "ok", gin.H{"codes": out, "total": len(out)})
}

// DELETE /api/v1/admin/invitation-codes/:code
func AdminInviteRevoke(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		fail(c, http.StatusBadRequest, 1001, "code required")
		return
	}
	now := time.Now()
	res := common.DB.Model(&models.InvitationCode{}).
		Where("code = ? AND revoked_at IS NULL", code).
		Update("revoked_at", &now)
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1002, "code not found or already revoked")
		return
	}
	ok(c, "revoked", nil)
}

// ---- helpers ----

// randInviteCode — 6 bytes = 12 hex chars, matches LQA's code style.
func randInviteCode() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
