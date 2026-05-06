package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

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

	// Audience selection:
	//   ?audience=runmesh (default, for back-compat) → scope rules below
	//   ?audience=flowmesh → any authenticated user gets `flowmesh:ssh`
	//     (parity with the CLI: anyone with a lum.id PAT can run
	//     `flowmesh ssh`). Cost control lives in the billing layer,
	//     not here.
	requestedAud := strings.ToLower(strings.TrimSpace(c.Query("audience")))
	if requestedAud == "" {
		requestedAud = "runmesh"
	}

	var audience string
	scopes := []string{}
	switch requestedAud {
	case "runmesh":
		audience = "runmesh"
		// Scope selection for runmesh audience:
		//   ?scope=admin (or missing) → runmesh:admin if admin, else empty
		//   ?scope=user              → runmesh:user for every caller
		requestedScope := strings.ToLower(strings.TrimSpace(c.Query("scope")))
		switch requestedScope {
		case "", "admin":
			if u.Role == "admin" || u.Role == "super_admin" {
				scopes = []string{"runmesh:admin"}
			}
		case "user":
			scopes = []string{"runmesh:user"}
		default:
			fail(c, http.StatusBadRequest, 1001, "scope must be 'user' or 'admin'")
			return
		}
	case "flowmesh":
		audience = "flowmesh"
		// Narrow runtime-only scope: lets the UI submit SSH tasks + poll
		// + stream logs + open the proxy WebSocket. Not a PAT scope a
		// user can mint; session-bearer only.
		scopes = []string{"flowmesh:ssh"}
	default:
		fail(c, http.StatusBadRequest, 1001, "audience must be 'runmesh' or 'flowmesh'")
		return
	}

	bridge, jti, exp, err := common.IssueBridgeJWT(
		u.ID, u.Email, u.Role, audience, scopes, 10*time.Minute,
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
		ClientID:  "lumid-bridge-" + audience,
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
		ExpiresAt: exp,
	})

	ok(c, "ok", gin.H{
		"token":      bridge,
		"expires_at": exp.Unix(),
		"scopes":     scopes,
		"audience":   audience,
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

// ---- redeem invitation code ----
//
// Closes the gap that Google-OAuth users land here without an
// invitation_code on their first sign-in. The lumid_ui callback page
// detects empty `user_info.invitation_code` after the OAuth exchange,
// pops the InvitationCodeDialog (mirroring LQA's pattern), and POSTs
// here to claim a code.
//
// Validation is the same as register: the code must exist in
// `invitation_codes`, not be revoked, not be expired, and have
// `uses_remaining > 0` (or `max_uses == 0` = unlimited). On success
// the user's `invitation_code_used` is filled in atomically with the
// uses_remaining decrement so a concurrent claim of the last seat
// can't double-spend.

type redeemInviteReq struct {
	InvitationCode string `json:"invitation_code"`
}

func RedeemInvitationCodeHandler(c *gin.Context) {
	uid, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	var req redeemInviteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid request body")
		return
	}
	code := strings.TrimSpace(req.InvitationCode)
	if code == "" {
		fail(c, http.StatusBadRequest, 1001, "invitation_code required")
		return
	}

	tx := common.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	var u models.User
	if err := tx.Where("id = ?", uid).First(&u).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	if u.Status == "suspended" {
		tx.Rollback()
		fail(c, http.StatusForbidden, 1006, "account suspended")
		return
	}
	if u.InvitationCodeUsed != "" {
		// Idempotent: a user who already redeemed should not be punished
		// for retrying (e.g. dialog reopened, race with another tab).
		// 409 with a clear message lets the UI close the dialog and
		// move on without another DB write.
		tx.Rollback()
		fail(c, http.StatusConflict, 1009, "invitation code already redeemed")
		return
	}

	var inv models.InvitationCode
	if err := tx.Where("code = ?", code).First(&inv).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusBadRequest, 1007, "invitation code invalid")
		return
	}
	if inv.RevokedAt != nil {
		tx.Rollback()
		fail(c, http.StatusBadRequest, 1007, "invitation code revoked")
		return
	}
	if inv.ExpiresAt != nil && inv.ExpiresAt.Before(time.Now()) {
		tx.Rollback()
		fail(c, http.StatusBadRequest, 1007, "invitation code expired")
		return
	}
	// max_uses == 0 means unlimited; otherwise we need uses_remaining > 0.
	if inv.MaxUses != 0 && inv.UsesRemaining <= 0 {
		tx.Rollback()
		fail(c, http.StatusBadRequest, 1007, "invitation code exhausted")
		return
	}

	now := time.Now()
	updates := map[string]any{"last_used_at": &now}
	if inv.MaxUses != 0 {
		// Decrement only when the code is bounded; unlimited stays at 0.
		// gorm.Expr keeps it server-side so concurrent claims don't race
		// on a stale read.
		res := tx.Model(&models.InvitationCode{}).
			Where("code = ? AND uses_remaining > 0", code).
			Updates(map[string]any{
				"uses_remaining": gorm.Expr("uses_remaining - 1"),
				"last_used_at":   &now,
			})
		if res.Error != nil {
			tx.Rollback()
			fail(c, http.StatusInternalServerError, 1500,
				"redeem code: "+res.Error.Error())
			return
		}
		if res.RowsAffected == 0 {
			// A concurrent claimer drained the last seat between our
			// SELECT and UPDATE.
			tx.Rollback()
			fail(c, http.StatusBadRequest, 1007, "invitation code exhausted")
			return
		}
	} else {
		if err := tx.Model(&models.InvitationCode{}).
			Where("code = ?", code).
			Updates(updates).Error; err != nil {
			tx.Rollback()
			fail(c, http.StatusInternalServerError, 1500,
				"touch code: "+err.Error())
			return
		}
	}

	if err := tx.Model(&u).
		Update("invitation_code_used", code).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500,
			"set user invitation_code: "+err.Error())
		return
	}

	if err := tx.Commit().Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "commit: "+err.Error())
		return
	}

	// Mirror LQA's response shape so the frontend dialog's
	// `onSuccess(response.token)` path stays a single contract: return
	// the current session bearer + its remaining lifetime. We don't
	// re-mint here — the existing JWT is still valid and revoking it
	// just to bump `invitation_code` would log the user out of every
	// other tab for no security benefit.
	tok := bearerToken(c)
	expiresIn := 0
	if claims, err := common.VerifyJWT(tok); err == nil && !claims.ExpiresAt.IsZero() {
		expiresIn = int(time.Until(claims.ExpiresAt.Time).Seconds())
		if expiresIn < 0 {
			expiresIn = 0
		}
	}
	ok(c, "invitation code redeemed", gin.H{
		"token":      tok,
		"expires_in": expiresIn,
	})
}
