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

// RequireAdmin blocks callers whose JWT doesn't carry role=admin.
// Relies on the session cookie (lm_session) or Authorization header,
// whichever currentUserID resolves through common.VerifyJWT.
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := bearerToken(c)
		if tok == "" {
			fail(c, http.StatusUnauthorized, 1003, "auth required")
			c.Abort()
			return
		}
		claims, err := common.VerifyJWT(tok)
		if err != nil {
			fail(c, http.StatusUnauthorized, 1003, "invalid session")
			c.Abort()
			return
		}
		if claims.Role != "admin" && claims.Role != "super_admin" {
			fail(c, http.StatusForbidden, 1005, "admin required")
			c.Abort()
			return
		}
		c.Set("admin_user_id", claims.Subject)
		c.Next()
	}
}

// RequireSuperAdmin — stricter gate than RequireAdmin. Billing and
// accounting routes use this so a regular admin (operations) can't
// touch money-moving endpoints. super_admin inherits everything
// admin can do; additional authority is scoped to this gate.
func RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := bearerToken(c)
		if tok == "" {
			fail(c, http.StatusUnauthorized, 1003, "auth required")
			c.Abort()
			return
		}
		claims, err := common.VerifyJWT(tok)
		if err != nil {
			fail(c, http.StatusUnauthorized, 1003, "invalid session")
			c.Abort()
			return
		}
		if claims.Role != "super_admin" {
			fail(c, http.StatusForbidden, 1005, "super_admin required")
			c.Abort()
			return
		}
		c.Set("admin_user_id", claims.Subject)
		c.Next()
	}
}

// ---- handlers ----

type mintInviteReq struct {
	Count     int    `json:"count"`      // how many distinct codes; default 1
	MaxUses   int    `json:"max_uses"`   // per code; default 1 (0 = unlimited)
	Note      string `json:"note"`
	TTLDays   int    `json:"ttl_days"`   // 0 = no expiry
}

type inviteRow struct {
	Code          string     `json:"code"`
	Note          string     `json:"note,omitempty"`
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
			MaxUses:       req.MaxUses,
			UsesRemaining: req.MaxUses,
			ExpiresAt:     expAt,
		}
		if err := common.DB.Create(row).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
			return
		}
		codes = append(codes, inviteRow{
			Code: row.Code, Note: row.Note,
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
			Code: r.Code, Note: r.Note,
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
