package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /api/v1/session-bearer — returns the current session JWT to JS
// on lum.id so it can forward it as Authorization: Bearer <jwt> on
// cross-domain admin calls (runmesh.ai, etc.) where the HttpOnly
// `.lum.id` cookie cannot reach. Only exposes to the authenticated
// caller themselves — 401 when no session.
//
// This is a pragmatic bridge until every downstream app lives under
// `*.lum.id` where the session cookie flows automatically. The
// returned token is the same JWT already in lm_session; exposing it
// to JS widens the XSS blast radius marginally but is bounded by
// the session's own TTL and logout-everywhere.
func SessionBearerHandler(c *gin.Context) {
	tok := bearerToken(c)
	if tok == "" {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	claims, err := common.VerifyJWT(tok)
	if err != nil {
		fail(c, http.StatusUnauthorized, 1003, "invalid session")
		return
	}
	ok(c, "ok", gin.H{
		"token":      tok,
		"expires_at": claims.ExpiresAt.Unix(),
	})
}

// GET /api/v1/user — return the current user based on the session
// cookie. This is what every frontend calls on mount to decide
// "logged in or not". 401 means no/expired session.
func CurrentUserHandler(c *gin.Context) {
	uid, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", uid).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	ok(c, "ok", userInfoFromModel(&u))
}

type updateUserReq struct {
	// Both fields optional — only supplied ones are applied.
	Name   *string `json:"username"`
	Avatar *string `json:"avatar"`
}

// PUT /api/v1/user — edit profile (name, avatar). Avatar accepted as
// a base64 data URL for v1 (same shape the ported Runmesh / LQA UIs
// already send); swap to multipart+MinIO later if needed.
func UpdateUserHandler(c *gin.Context) {
	uid, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var req updateUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	updates := map[string]interface{}{}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" {
			fail(c, http.StatusBadRequest, 1001, "username cannot be empty")
			return
		}
		if len(n) > 255 {
			fail(c, http.StatusBadRequest, 1001, "username too long")
			return
		}
		updates["name"] = n
	}
	if req.Avatar != nil {
		// 5MB cap, generous but keeps a runaway paste out of the DB.
		if len(*req.Avatar) > 5*1024*1024 {
			fail(c, http.StatusBadRequest, 1001, "avatar exceeds 5MB")
			return
		}
		updates["avatar_url"] = *req.Avatar
	}
	if len(updates) == 0 {
		fail(c, http.StatusBadRequest, 1001, "nothing to update")
		return
	}
	if err := common.DB.Model(&models.User{}).Where("id = ?", uid).Updates(updates).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "db: "+err.Error())
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", uid).First(&u).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "reload: "+err.Error())
		return
	}
	ok(c, "updated", userInfoFromModel(&u))
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// POST /api/v1/user/password — self-service password change.
// Verifies the old password with bcrypt, hashes the new one, revokes
// every *other* session so stolen cookies don't survive a password
// rotation. The caller's own session stays valid (jti compared).
func ChangePasswordHandler(c *gin.Context) {
	uid, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var req changePasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		fail(c, http.StatusBadRequest, 1001, "old_password and new_password required")
		return
	}
	if len(req.NewPassword) < 8 {
		fail(c, http.StatusBadRequest, 1001, "new_password must be at least 8 characters")
		return
	}
	if req.OldPassword == req.NewPassword {
		fail(c, http.StatusBadRequest, 1001, "new password must differ from old")
		return
	}

	var u models.User
	if err := common.DB.Where("id = ?", uid).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	if u.PasswordHash == "" {
		// OAuth-only account — user signed up via Google, never set a
		// password. Refuse rather than silently upgrade (would expose
		// the Google-linked account to a password-based attack surface).
		fail(c, http.StatusBadRequest, 1010, "this account has no password; sign in via your OAuth provider and set one from /account/profile once supported")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)); err != nil {
		fail(c, http.StatusUnauthorized, 1004, "old password incorrect")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "hash: "+err.Error())
		return
	}

	// Don't revoke our own session — read the jti from the bearer
	// token we arrived with so we can exclude it from the sweep.
	var currentJTI string
	if tok := bearerToken(c); tok != "" {
		if claims, err := common.VerifyJWT(tok); err == nil {
			currentJTI = claims.ID
		}
	}

	now := time.Now()
	tx := common.DB.Begin()
	if err := tx.Model(&models.User{}).Where("id = ?", uid).Update("password_hash", string(newHash)).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "update pw: "+err.Error())
		return
	}
	revokeQ := tx.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", uid)
	if currentJTI != "" {
		revokeQ = revokeQ.Where("jti <> ?", currentJTI)
	}
	if err := revokeQ.Update("revoked_at", &now).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "revoke sessions: "+err.Error())
		return
	}
	tx.Commit()

	ok(c, "password changed", nil)
}

func userInfoFromModel(u *models.User) gin.H {
	return gin.H{
		"id":              u.ID,
		"email":           u.Email,
		"username":        u.Name,
		"role":            u.Role,
		"status":          u.Status,
		"avatar":          u.AvatarURL,
		"email_verified":  u.EmailVerified,
		"invitation_code": u.InvitationCodeUsed,
	}
}
