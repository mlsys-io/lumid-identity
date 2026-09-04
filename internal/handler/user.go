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
	"lumid_identity/internal/config"
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
	//   ?audience=lqt → read-only LQT surfaces, no scopes; see the case below.
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
		// Runtime-only scopes for the GPU-rental UI: submit/cancel the SSH
		// workflow, poll tasks/results, stream logs, open the proxy
		// WebSocket. flowmesh:ssh alone failed the lumid plugin's
		// kind-level check on workflow create ("requires
		// 'flowmesh:workflows:write'") for every non-`*` user — the app
		// wasn't saying which capability it exercises (2026-06-12).
		// Session-bearer only, 10-min TTL; not PAT-mintable.
		scopes = []string{
			"flowmesh:ssh",
			"flowmesh:workflows:write",
			"flowmesh:workflows:read",
			"flowmesh:tasks:read",
			"flowmesh:results:read",
		}
	case "lqt":
		// LQT read surfaces (lum.id/lqt/inspect/*, served by its own ingress
		// straight to lqt-inspect — it never passes through the landing nginx,
		// so it is NOT covered by the $lqt_auth service-PAT injection and is
		// scoped to whoever's bearer actually arrives).
		//
		// lqt-auth already accepts exactly this: it verifies a JWKS-signed JWT
		// requiring aud="lqt" / iss="https://lum.id" (lqt-auth DEFAULT_AUD,
		// DEFAULT_ISS) before falling back to PAT introspect. The two halves
		// were built to meet and were never connected — without this case a
		// browser had no way to reach a tenant-scoped LQT read except by the
		// user pasting a raw PAT into the page, which is precisely what
		// session-bearer exists to avoid.
		//
		// No scopes: /lqt/inspect/* authorizes on the tenant the token asserts
		// (self_tenant is injected server-side from `sub` and cannot be spoofed
		// by the caller), not on a scope string. Deliberately NOT granting
		// `lqt:strategy` here — deploying a strategy is a write, it is a
		// capability tag a user mints on a PAT deliberately, and a 10-minute
		// bearer minted from a session cookie is the wrong instrument for it.
		audience = "lqt"
	default:
		fail(c, http.StatusBadRequest, 1001, "audience must be 'runmesh', 'flowmesh' or 'lqt'")
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
	// Read the jtis BEFORE the update, so we know which sessions to publish to
	// the denylist. Writing revoked_at alone changed nothing observable: the
	// auth path accepts a JWT on signature, so every one of these kept working
	// until it expired on its own.
	var doomed []models.Session
	scopeQ := tx.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", uid, now)
	if currentJTI != "" {
		scopeQ = scopeQ.Where("jti <> ?", currentJTI)
	}
	if err := scopeQ.Find(&doomed).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "read sessions: "+err.Error())
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

	// AFTER the commit — a denylist entry for a session the DB did not actually
	// revoke would lock someone out with no durable record explaining why. Each
	// key lives exactly as long as the token it kills, so the list self-trims.
	for i := range doomed {
		common.RevokeSessionJTI(c.Request.Context(), doomed[i].JTI, time.Until(doomed[i].ExpiresAt))
	}

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
	// Has this user already redeemed THIS code? That is the only replay we must
	// refuse. Enforcement is the uk_user_code unique index below — this SELECT
	// is a fast path and a nice error message, not the guarantee: two
	// concurrent redeems both pass here and one loses at the insert.
	var priorSame models.InvitationRedemption
	if err := tx.Where("user_id = ? AND code = ?", u.ID, code).
		First(&priorSame).Error; err == nil {
		tx.Rollback()
		fail(c, http.StatusConflict, 1009, "you have already redeemed this code")
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

	// A user who has already onboarded may redeem a code that GRANTS ACCESS,
	// but not a second plain signup code. Those are different objects that
	// happen to share a table: a signup code answers "may this person join",
	// which is asked once; a scoped code answers "may this person have X",
	// which is asked whenever X changes.
	//
	// Conflating them is what broke this: every one of the twenty cohort
	// accounts already had invitation_code_used set from signup, so a scoped
	// code minted for them was refused before it could grant anything — the
	// feature worked only for brand-new accounts, which is precisely the group
	// that did not need it.
	if u.InvitationCodeUsed != "" && strings.TrimSpace(inv.Scopes) == "" {
		tx.Rollback()
		fail(c, http.StatusConflict, 1009, "invitation code already redeemed")
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

	// Only the FIRST redemption sets invitation_code_used. That column means
	// "the code this account joined with", and a later access grant must not
	// rewrite the signup record — QuantArena's middleware reads it, and the
	// provenance of who invited whom would be lost.
	if u.InvitationCodeUsed == "" {
		if err := tx.Model(&u).
			Update("invitation_code_used", code).Error; err != nil {
			tx.Rollback()
			fail(c, http.StatusInternalServerError, 1500,
				"set user invitation_code: "+err.Error())
			return
		}
	}

	// The per-(user, code) record. Its unique index — not the SELECT at the top
	// — is what actually stops a replay: without it one user could drain a
	// 20-seat code alone, because uses_remaining decrements per redeem, not per
	// person. A duplicate key here is a concurrent double-submit, which is a
	// 409, not a 500.
	if err := tx.Create(&models.InvitationRedemption{
		ID: uuid.NewString(), UserID: u.ID, Code: code,
		Scopes: strings.TrimSpace(inv.Scopes),
	}).Error; err != nil {
		tx.Rollback()
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			fail(c, http.StatusConflict, 1009, "you have already redeemed this code")
			return
		}
		fail(c, http.StatusInternalServerError, 1500, "record redemption: "+err.Error())
		return
	}

	// Apply the code's scopes as durable access grants.
	//
	// These ride the SAME transaction as the uses_remaining decrement above,
	// and that is the whole reason this block sits here rather than after the
	// commit. A code that consumed a seat but failed to apply its grants leaves
	// the user believing they were onboarded and the operator believing the
	// seat was spent — with nothing to distinguish that from a code that simply
	// granted nothing, and no way for the user to redeem it again.
	//
	// This is what lets an operator hand out an entitlement a user cannot
	// self-grant (`lumid:write`) without any credential passing through the
	// operator's hands: they issue a claim, the user redeems it, and then mints
	// their own PAT through the ordinary flow. Nothing about PAT minting
	// changes — canGrant simply starts passing, because the grant row exists.
	for _, raw := range strings.Fields(inv.Scopes) {
		svc, lvl := parseScope(raw)
		if svc == "" || svc == "*" {
			// Validated at mint time. A malformed value that reached the DB
			// anyway must not fail somebody's redeem — skip it rather than
			// punish the user for an operator's typo.
			continue
		}
		var existing models.UserAccessGrant
		err := tx.Where("user_id = ? AND service = ?", u.ID, svc).First(&existing).Error
		if err == nil {
			// Redeeming a second code must not collide on the uk_user_svc
			// unique index — and must never DOWNGRADE an existing grant. A
			// read-level invitation landing on someone who already has write
			// would otherwise quietly take access away.
			if levelRank(lvl) > levelRank(existing.Level) {
				if e := tx.Model(&existing).Updates(map[string]any{
					"level": lvl, "granted_by": "invite:" + code,
				}).Error; e != nil {
					tx.Rollback()
					fail(c, http.StatusInternalServerError, 1500, "apply grant: "+e.Error())
					return
				}
			}
		} else if e := tx.Create(&models.UserAccessGrant{
			ID: uuid.NewString(), UserID: u.ID, Service: svc,
			Level: lvl, GrantedBy: "invite:" + code,
		}).Error; e != nil {
			tx.Rollback()
			fail(c, http.StatusInternalServerError, 1500, "apply grant: "+e.Error())
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "commit: "+err.Error())
		return
	}

	// Mirror the redeemed code to LQA's tbl_user.invitation_code.
	// QA's InvitationCodeRequiredMiddleware (middleware.go:421) reads
	// that column directly and 403s gated routes (/strategies,
	// /backtesting-tasks, /history-databases, /universes, …) when
	// empty. Without this mirror, OAuth users redeem successfully on
	// lum.id but every QA dashboard panel toasts "Please add an
	// invitation code to access this feature" until the next signup.
	if config.G.Legacy.Enabled && common.LegacyDB != nil {
		common.LegacyDB.Exec(
			`UPDATE tbl_user SET invitation_code = ?, update_time = UNIX_TIMESTAMP() WHERE email = ?`,
			code, u.Email,
		)
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
