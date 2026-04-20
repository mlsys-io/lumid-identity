package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// GET /api/v1/session-bearer — mints a short-lived, scope-constrained
// JWT for same-origin JS on lum.id to forward as Authorization:
// Bearer on cross-domain admin calls (runmesh.ai, etc.) where the
// HttpOnly `.lum.id` session cookie cannot reach.
//
// Security shape (improvement over returning the raw session JWT):
//   - TTL: 10 minutes (vs session's 24h) — limits XSS blast radius
//   - audience: "runmesh" (vs session's "lumid-ecosystem") — prevents
//     replay as a general lum.id session
//   - scope: "runmesh:admin" for admins, empty otherwise — principle
//     of least privilege
//   - jti NOT persisted in `sessions` — a stolen bearer can't be
//     turned into an audit artifact or revoked; instead the short
//     TTL *is* the revocation.
//
// Non-admin callers still get a 200 but with an empty scope so the
// frontend can rely on "200 means authenticated, inspect the scope".
// Admins get "runmesh:admin". This endpoint is authed via the HttpOnly
// session cookie that same-origin JS cannot read — the bearer lives
// on the JS side only as a *copy* of permissions, not the session itself.
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

	var u models.User
	if err := common.DB.Where("id = ?", claims.Subject).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	if u.Status == "suspended" {
		fail(c, http.StatusForbidden, 1006, "account suspended")
		return
	}

	scopes := []string{}
	if u.Role == "admin" {
		scopes = []string{"runmesh:admin"}
	}

	bridge, jti, exp, err := common.IssueBridgeJWT(
		u.ID, u.Email, u.Role, "runmesh", scopes, 10*time.Minute,
	)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint bridge: "+err.Error())
		return
	}

	// Still persist a session row so admin audit can see *some* trail
	// of federated access, even if the bearer itself is fire-and-forget.
	common.DB.Create(&models.Session{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		JTI:       jti,
		ClientID:  "lumid-bridge",
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
		ExpiresAt: exp,
	})

	ok(c, "ok", gin.H{
		"token":      bridge,
		"expires_at": exp.Unix(),
		"scopes":     scopes,
		"audience":   "runmesh",
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
