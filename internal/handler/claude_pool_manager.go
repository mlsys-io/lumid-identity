package handler

// Delegated pool-account management.
//
// Two powers that are otherwise estate-wide and admin/super_admin — pausing a
// pooled Claude account, and resetting a user's usage clock — handed to a
// named member of ONE pool, over ONLY that pool's accounts and members.
//
// Why these live outside the /admin tree: a delegate is an ordinary user, so
// RequireAdmin would refuse them. The gate here is the (pool, user) grant
// itself, checked per request against the resource being touched, which is
// strictly narrower than any role could express.
//
// Visibility is a CONSEQUENCE of the same check, never a substitute for it.
// MeClaudePoolManage returns an empty roster to a non-manager so the UI can
// hide the section, and every write independently re-derives the caller's
// managed pools — hiding a control that still answers is theatre.

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// managedPools returns the pool ids this user may administer. Empty for
// everyone who has not been explicitly granted, INCLUDING admins and
// super_admins: this is a delegation mechanism, not a role. A super_admin who
// wants these powers already has the estate-wide /admin endpoints.
func managedPools(userSub string) []string {
	if userSub == "" {
		return nil
	}
	var ids []string
	common.DB.Model(&models.ClaudePoolMember{}).
		Where("user_sub = ? AND is_manager = ?", userSub, true).
		Pluck("pool_id", &ids)
	return ids
}

func managesPool(userSub, poolID string) bool {
	if userSub == "" || poolID == "" {
		return false
	}
	var n int64
	common.DB.Model(&models.ClaudePoolMember{}).
		Where("user_sub = ? AND pool_id = ? AND is_manager = ?", userSub, poolID, true).
		Count(&n)
	return n > 0
}

// MeClaudePoolManage — what, if anything, this caller may manage.
//
// GET /api/v1/me/claude-pool/manage
func MeClaudePoolManage(c *gin.Context) {
	uid, okUser := currentUserID(c)
	if !okUser {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	pools := managedPools(uid)
	// 200 with an empty roster, not 403: "you manage nothing" is a legitimate
	// answer to a question every session asks on load, and a 403 would make
	// ordinary users look like failures in the logs.
	if len(pools) == 0 {
		ok(c, "ok", gin.H{"pools": []any{}, "accounts": []any{}, "members": []any{}})
		return
	}

	var poolRows []models.ClaudePool
	common.DB.Where("id IN ?", pools).Find(&poolRows)

	type acct struct {
		Email         string     `json:"email"`
		PoolID        string     `json:"pool_id"`
		Label         string     `json:"label,omitempty"`
		DrainingSince *time.Time `json:"draining_since,omitempty"`
		DrainReason   string     `json:"drain_reason,omitempty"`
		Revoked       bool       `json:"revoked,omitempty"`
	}
	var tokens []models.ClaudeQuotaToken
	common.DB.Where("pool_id IN ?", pools).Find(&tokens)
	accounts := make([]acct, 0, len(tokens))
	for _, t := range tokens {
		accounts = append(accounts, acct{
			Email: t.Email, PoolID: t.PoolID, Label: t.Label,
			DrainingSince: t.DrainingSince, DrainReason: t.DrainReason,
			Revoked: t.RevokedAt != nil,
		})
	}

	type member struct {
		UserSub string `json:"user_sub"`
		Email   string `json:"email"`
		PoolID  string `json:"pool_id"`
	}
	var members []member
	common.DB.Raw(`SELECT m.user_sub, COALESCE(u.email, m.user_sub) AS email, m.pool_id
	               FROM   claude_pool_members m
	               LEFT JOIN users u ON u.id = m.user_sub
	               WHERE  m.pool_id IN ?
	               ORDER  BY email`, pools).Scan(&members)

	ok(c, "ok", gin.H{"pools": poolRows, "accounts": accounts, "members": members})
}

// MeClaudePoolAccountDrain pauses/resumes ONE account, and only if it belongs
// to a pool the caller manages.
//
// POST /api/v1/me/claude-pool/accounts/:email/drain  {draining, reason?}
func MeClaudePoolAccountDrain(c *gin.Context) {
	uid, okUser := currentUserID(c)
	if !okUser {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(c.Param("email")))
	var body struct {
		// Pointer for the same reason AdminClaudeAccountDrain uses one: a
		// mis-serialised field must not silently un-pause an account.
		Draining *bool  `json:"draining"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Draining == nil {
		fail(c, http.StatusBadRequest, 1400, "draining (true|false) required")
		return
	}

	var row models.ClaudeQuotaToken
	if common.DB.Where("email = ?", email).First(&row).Error != nil {
		// Deliberately the same 404 a manager gets for an account in someone
		// else's pool (below): the existence of accounts outside your pool is
		// not yours to learn by probing this endpoint.
		fail(c, http.StatusNotFound, 1404, "no such pooled account in a pool you manage")
		return
	}
	if !managesPool(uid, poolIDOrDefault(row.PoolID)) {
		fail(c, http.StatusNotFound, 1404, "no such pooled account in a pool you manage")
		return
	}

	updates := map[string]interface{}{"draining_since": nil, "drain_reason": ""}
	if *body.Draining {
		// Refuse to pause the pool's last un-paused, usable account. The
		// estate-wide admin endpoint makes the same refusal; a delegate must
		// not be able to take their own pool offline by accident.
		var usable int64
		common.DB.Model(&models.ClaudeQuotaToken{}).
			Where("pool_id = ? AND email <> ? AND draining_since IS NULL AND revoked_at IS NULL AND deleted_at IS NULL",
				row.PoolID, row.Email).Count(&usable)
		if usable == 0 {
			fail(c, http.StatusConflict, 1409,
				"refusing to pause the last usable account in this pool — it would take the pool offline")
			return
		}
		now := time.Now().UTC()
		updates["draining_since"] = &now
		updates["drain_reason"] = strings.TrimSpace(body.Reason)
	}
	if err := common.DB.Model(&row).Updates(updates).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "update account: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"email": row.Email, "pool_id": row.PoolID, "draining": *body.Draining})
}

// MeClaudePoolResetWindow resets the usage clock for ONE member of a pool the
// caller manages.
//
// Deliberately NOT offering the admin endpoint's no-argument "reset everyone"
// form: estate-wide is exactly what a delegate must not have, and an omitted
// field defaulting to "all users everywhere" is the worst possible shape for
// that mistake.
//
// POST /api/v1/me/claude-pool/reset-window  {user_sub|email, window?}
func MeClaudePoolResetWindow(c *gin.Context) {
	uid, okUser := currentUserID(c)
	if !okUser {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var body struct {
		UserSub string `json:"user_sub"`
		Email   string `json:"email"`
		Window  string `json:"window"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	target := strings.TrimSpace(body.UserSub)
	if target == "" && strings.TrimSpace(body.Email) != "" {
		var u models.User
		if common.DB.Where("email = ?", strings.TrimSpace(body.Email)).First(&u).Error != nil {
			fail(c, http.StatusNotFound, 1404, "no such member in a pool you manage")
			return
		}
		target = u.ID
	}
	if target == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub or email required — a delegate cannot reset every user")
		return
	}

	// The target must be a member of a pool THIS caller manages. Checked as one
	// query over both sides so a manager of pool A cannot reset a member of
	// pool B by naming them.
	pools := managedPools(uid)
	if len(pools) == 0 {
		fail(c, http.StatusForbidden, 1403, "you do not manage any Claude pool")
		return
	}
	var shared int64
	common.DB.Model(&models.ClaudePoolMember{}).
		Where("user_sub = ? AND pool_id IN ?", target, pools).Count(&shared)
	if shared == 0 {
		fail(c, http.StatusNotFound, 1404, "no such member in a pool you manage")
		return
	}

	updates, label, err := poolResetColumns(body.Window, time.Now().UTC())
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	res := common.DB.Model(&models.ClaudePoolWindow{}).Where("user_sub = ?", target).Updates(updates)
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "reset: "+res.Error.Error())
		return
	}
	ok(c, "ok", gin.H{"user_sub": target, "window": label, "rows": res.RowsAffected})
}

// AdminClaudePoolSetManager grants/revokes the delegation. super_admin only —
// see ClaudePoolMember.IsManager.
//
// POST /api/v1/admin/claude-pools/:id/members/:user_sub/manager  {is_manager}
func AdminClaudePoolSetManager(c *gin.Context) {
	id := strings.ToLower(strings.TrimSpace(c.Param("id")))
	userSub := strings.TrimSpace(c.Param("user_sub"))
	var body struct {
		IsManager *bool `json:"is_manager"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.IsManager == nil {
		fail(c, http.StatusBadRequest, 1400, "is_manager (true|false) required")
		return
	}
	var m models.ClaudePoolMember
	if common.DB.Where("pool_id = ? AND user_sub = ?", id, userSub).First(&m).Error != nil {
		// Management is a property OF a membership: you cannot manage a pool
		// you are not in, so there is no row to hang the grant on.
		fail(c, http.StatusNotFound, 1404, "not a member of this pool — add them first")
		return
	}
	if err := common.DB.Model(&m).Update("is_manager", *body.IsManager).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "set manager: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"pool_id": id, "user_sub": userSub, "is_manager": *body.IsManager})
}
