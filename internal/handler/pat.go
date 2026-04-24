package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// PAT handlers. Called by the lum.id/account/tokens UI via the
// session cookie. Tokens returned only at mint time — we hash before
// storage and never surface cleartext again.

type patMintReq struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	TTLDays   int      `json:"ttl_days"` // 0 = no expiry
}

type patMintResp struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`    // cleartext, once only
	Prefix    string    `json:"prefix"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// JSON shape matches the lumid_auth_ui PATInfo TS interface verbatim.
// Timestamps are emitted as unix seconds (0 when absent) so the frontend
// can do plain `t > 0` checks without date parsing. `status` is always
// "active" here because the list query filters out revoked rows;
// AuditDialog sees revoked ones through a separate endpoint.
type patListItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TokenPrefix string   `json:"token_prefix"`
	Scopes      []string `json:"scopes"`
	Status      string   `json:"status"`
	LastUsedAt  int64    `json:"last_used_at"`
	ExpiresAt   int64    `json:"expires_at"`
	RevokedAt   int64    `json:"revoked_at"`
	CreateTime  int64    `json:"create_time"`
	Source      string   `json:"source"`
}

func PATMintHandler(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var req patMintReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if len(req.Scopes) == 0 {
		fail(c, http.StatusBadRequest, 1001, "scopes required")
		return
	}
	// Gate against the user's effective matrix row. Prevents non-admins
	// from minting a `*`-scope PAT (which would light up as admin on
	// every service via computeAccess). Admins pass through; users get
	// each requested scope checked against their current level.
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	var existing []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", userID).
		Find(&existing)
	for _, s := range req.Scopes {
		if !canGrant(u, existing, s) {
			fail(c, http.StatusForbidden, 1005, "scope not grantable: "+s)
			return
		}
	}
	if req.Name == "" {
		req.Name = "lm_pat " + time.Now().Format("2006-01-02 15:04")
	}

	// 32 bytes of entropy → 64 hex chars, prefixed lm_pat_live_.
	raw, err := randHex(32)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rng")
		return
	}
	cleartext := "lm_pat_live_" + raw
	sum := sha256.Sum256([]byte(cleartext))
	hash := hex.EncodeToString(sum[:])

	var expAt *time.Time
	if req.TTLDays > 0 {
		t := time.Now().AddDate(0, 0, req.TTLDays)
		expAt = &t
	}

	row := &models.Token{
		ID:        uuid.NewString(),
		UserID:    userID,
		Prefix:    "lm_pat_",
		Hash:      hash,
		HashAlg:   "sha256", // argon2id is Phase 8; plain sha256 is good enough + cheap to verify
		Name:      req.Name,
		Scopes:    strings.Join(req.Scopes, " "),
		ExpiresAt: expAt,
		Source:    "native",
	}
	if err := common.DB.Create(row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
		return
	}
	ok_(c, "minted", patMintResp{
		ID: row.ID, Token: cleartext, Prefix: "lm_pat_live_",
		Name: row.Name, Scopes: req.Scopes, ExpiresAt: expAt,
	})
}

func PATListHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var rows []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("created_at DESC").Find(&rows)
	out := make([]patListItem, 0, len(rows))
	for _, r := range rows {
		var lastUsed, expires int64
		if r.LastUsedAt != nil {
			lastUsed = r.LastUsedAt.Unix()
		}
		if r.ExpiresAt != nil {
			expires = r.ExpiresAt.Unix()
		}
		out = append(out, patListItem{
			ID:          r.ID,
			Name:        r.Name,
			TokenPrefix: r.Prefix,
			Scopes:      strings.Fields(r.Scopes),
			Status:      "active", // revoked rows filtered by the WHERE above
			LastUsedAt:  lastUsed,
			ExpiresAt:   expires,
			CreateTime:  r.CreatedAt.Unix(),
			Source:      r.Source,
		})
	}
	ok_(c, "ok", gin.H{"tokens": out, "total": len(out)})
}

func PATRevokeHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	id := c.Param("id")
	now := time.Now()
	res := common.DB.Model(&models.Token{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Update("revoked_at", &now)
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1002, "token not found")
		return
	}
	ok_(c, "revoked", nil)
}

// PATRotateHandler revokes an existing PAT and mints a replacement with
// the same name + scopes + TTL (computed from the remaining lifespan of
// the original, if it had one). Returns the new cleartext once. The
// caller is responsible for swapping it into their keyring / env.
func PATRotateHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	id := c.Param("id")

	// Atomic handoff: revoke old + mint new in one transaction so the
	// caller either gets both records or neither.
	var newToken string
	var newRow models.Token
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		var old models.Token
		if err := tx.Where("id = ? AND user_id = ? AND revoked_at IS NULL",
			id, userID).First(&old).Error; err != nil {
			return err
		}
		now := time.Now()
		if err := tx.Model(&old).Update("revoked_at", &now).Error; err != nil {
			return err
		}
		raw, err := randHex(32)
		if err != nil {
			return err
		}
		cleartext := "lm_pat_live_" + raw
		sum := sha256.Sum256([]byte(cleartext))
		hash := hex.EncodeToString(sum[:])
		var expAt *time.Time
		if old.ExpiresAt != nil {
			// Preserve the original remaining lifespan (not absolute deadline).
			t := time.Now().Add(time.Until(*old.ExpiresAt))
			expAt = &t
		}
		newRow = models.Token{
			ID:        uuid.NewString(),
			UserID:    userID,
			Prefix:    "lm_pat_",
			Hash:      hash,
			HashAlg:   "sha256",
			Name:      old.Name,
			Scopes:    old.Scopes,
			ExpiresAt: expAt,
			Source:    "native",
		}
		if err := tx.Create(&newRow).Error; err != nil {
			return err
		}
		newToken = cleartext
		return nil
	})
	if err != nil {
		fail(c, http.StatusNotFound, 1002,
			"token not found or already revoked")
		return
	}
	scopes := strings.Fields(newRow.Scopes)
	ok_(c, "rotated", patMintResp{
		ID: newRow.ID, Token: newToken, Prefix: "lm_pat_live_",
		Name: newRow.Name, Scopes: scopes, ExpiresAt: newRow.ExpiresAt,
	})
}

// currentUserID resolves the session cookie, Bearer JWT, or lm_pat_*
// PAT to a user id. Returns (id, true) on success.
//
// Accepting PATs here (not just JWTs) is what makes the unified-auth
// claim work for callers like lumid /api/v1/user: a power-user with
// only a PAT must still be able to read their own profile the same
// way a session-cookie caller can.
func currentUserID(c *gin.Context) (string, bool) {
	tok := bearerToken(c)
	if tok == "" {
		return "", false
	}
	// JWT path first — fast, no DB hit.
	if claims, err := common.VerifyJWT(tok); err == nil {
		return claims.Subject, true
	}
	// PAT path — same tokens.hash lookup used by introspectNative.
	if strings.HasPrefix(tok, "lm_pat_") {
		sum := sha256.Sum256([]byte(tok))
		hash := hex.EncodeToString(sum[:])
		var row models.Token
		if err := common.DB.Where("hash = ?", hash).First(&row).Error; err == nil {
			if row.RevokedAt == nil &&
				(row.ExpiresAt == nil || row.ExpiresAt.After(time.Now())) {
				return row.UserID, true
			}
		}
	}
	return "", false
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ok_ — same shape as the helper in helpers.go. Named with trailing
// underscore because `ok` is a frequent local var in this file.
func ok_(c *gin.Context, msg string, data any) { ok(c, msg, data) }

// GrantableScopesHandler — GET /api/v1/identity/grantable-scopes.
// Tells the caller which scopes they can mint a PAT with, so the UI
// can render an accurate picker instead of letting the user request
// scopes the backend will 403. Shape mirrors the admin matrix so the
// PAT mint dialog and the admin users access view can share widgets.
//
// Response:
//   {
//     "role":        "user" | "admin",
//     "services":    [ "lumid", "qa", "runmesh", ... ],
//     "matrix":      { "lumid": "read", "qa": "write", ... },
//     "can_wildcard": bool   // true iff the global `*` scope is grantable
//   }
func GrantableScopesHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "user not found")
		return
	}
	var toks []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())", userID).
		Find(&toks)

	grants := loadAccessGrants(userID)
	matrix := make(map[string]string, len(accessServices))
	for _, svc := range accessServices {
		matrix[svc] = computeAccess(svc, u, toks, grants).Level
	}
	ok(c, "ok", gin.H{
		"role":         u.Role,
		"services":     accessServices,
		"matrix":       matrix,
		"can_wildcard": u.Role == "admin" || u.Role == "super_admin",
	})
}
