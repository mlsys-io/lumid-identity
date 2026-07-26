package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// PAT handlers. Called by the lum.id/account/tokens UI via the
// session cookie. Tokens returned only at mint time — we hash before
// storage and never surface cleartext again.

const (
	patMaxNameLen  = 128
	patMaxScopes   = 20
	patMaxScopeLen = 2048 // chars, total scope string
	patMaxTTLDays  = 3650 // 10 years

	// Per-user PAT mint/rotate limit: 10 per hour.
	patMintHourlyLimit = 10
	patMintWindowS     = 3600

	// argon2id KDF parameters for new native tokens.
	argon2Time    = 2
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	argon2SaltLen = 16

	// Fixed cleartext prefix for native PATs.
	patCleartextPrefix = "lm_pat_live_"
)

type patMintReq struct {
	Name    string   `json:"name"`
	Scopes  []string `json:"scopes"`
	TTLDays int      `json:"ttl_days"` // 0 = no expiry
}

type patMintResp struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"` // cleartext, once only
	Prefix    string     `json:"prefix"`
	Name      string     `json:"name"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// JSON shape matches the lumid_auth_ui PATInfo TS interface verbatim.
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

// ── argon2id helpers ─────────────────────────────────────────────────────────

// argon2idHash computes an argon2id hash with a fresh random salt.
// Stored format: base64RawStd(salt) + ":" + base64RawStd(hash).
func argon2idHash(cleartext string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h := argon2.IDKey([]byte(cleartext), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return base64.RawStdEncoding.EncodeToString(salt) + ":" + base64.RawStdEncoding.EncodeToString(h), nil
}

// argon2idVerify verifies a cleartext token against an argon2id encoded hash.
func argon2idVerify(cleartext, encoded string) bool {
	parts := strings.SplitN(encoded, ":", 2)
	if len(parts) != 2 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[0])
	expected, err2 := base64.RawStdEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(salt) < 8 {
		return false
	}
	h := argon2.IDKey([]byte(cleartext), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return subtle.ConstantTimeCompare(h, expected) == 1
}

// patLookupKey extracts the 16-char lookup key from a cleartext native PAT
// (the first 16 hex chars of the random part). Used to narrow the DB query
// for argon2id tokens, which can't use WHERE hash = ? (non-deterministic).
func patLookupKey(cleartext string) string {
	if !strings.HasPrefix(cleartext, patCleartextPrefix) {
		return ""
	}
	raw := cleartext[len(patCleartextPrefix):]
	if len(raw) < 16 {
		return ""
	}
	return raw[:16]
}

// ── PAT lookup ───────────────────────────────────────────────────────────────

// findPATRow resolves a cleartext token to its DB row without filtering by
// revocation/expiry — the caller checks those to give accurate error messages.
// Tries argon2id path (new tokens) via lookup_key, then falls back to SHA-256
// (legacy sha256 tokens from before the argon2id migration).
func findPATRow(tok string) (*models.Token, bool) {
	// argon2id path: narrow by lookup_key, then verify hash.
	if lk := patLookupKey(tok); lk != "" {
		var rows []models.Token
		common.DB.Where("lookup_key = ? AND hash_alg = ?", lk, "argon2id").Find(&rows)
		for i := range rows {
			if argon2idVerify(tok, rows[i].Hash) {
				return &rows[i], true
			}
		}
	}
	// SHA-256 fallback for legacy lm_pat_* / rm_pat_* tokens.
	sum := sha256.Sum256([]byte(tok))
	hash := hex.EncodeToString(sum[:])
	var row models.Token
	if err := common.DB.Where("hash = ? AND hash_alg = ?", hash, "sha256").First(&row).Error; err == nil {
		return &row, true
	}
	return nil, false
}

// lookupPAT resolves a token to an active (not revoked, not expired) DB row.
func lookupPAT(tok string) (*models.Token, bool) {
	row, ok := findPATRow(tok)
	if !ok {
		return nil, false
	}
	if row.RevokedAt != nil {
		return nil, false
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now()) {
		return nil, false
	}
	return row, true
}

// ── rate limiting ────────────────────────────────────────────────────────────

// checkPATMintRate enforces 10 PAT mints/rotates per user per hour via Redis.
// Fails open when Redis is unavailable.
func checkPATMintRate(ctx context.Context, userID string) bool {
	if common.Redis == nil {
		return true
	}
	key := "rl:pat:mint:" + userID
	n, err := common.Redis.Incr(ctx, key).Result()
	if err != nil {
		return true
	}
	if n == 1 {
		_ = common.Redis.Expire(ctx, key, time.Duration(patMintWindowS)*time.Second).Err()
	}
	return n <= int64(patMintHourlyLimit)
}

// ── handlers ─────────────────────────────────────────────────────────────────

func PATMintHandler(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	if !callerHasLumidWrite(c) {
		fail(c, http.StatusForbidden, 1005, "PAT scope insufficient: lumid:write required to mint tokens")
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
	if len(req.Name) > patMaxNameLen {
		fail(c, http.StatusBadRequest, 1001, "name too long (max 128 chars)")
		return
	}
	if len(req.Scopes) > patMaxScopes {
		fail(c, http.StatusBadRequest, 1001, "too many scopes (max 20)")
		return
	}
	scopeStr := strings.Join(req.Scopes, " ")
	if len(scopeStr) > patMaxScopeLen {
		fail(c, http.StatusBadRequest, 1001, "scopes string too long")
		return
	}
	if req.TTLDays > patMaxTTLDays {
		fail(c, http.StatusBadRequest, 1001, "ttl_days too large (max 3650)")
		return
	}
	if !checkPATMintRate(c.Request.Context(), userID) {
		fail(c, http.StatusTooManyRequests, 1429, "too many tokens minted; try again later")
		return
	}

	// Gate against the user's effective matrix row.
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

	var expAt *time.Time
	if req.TTLDays > 0 {
		t := time.Now().AddDate(0, 0, req.TTLDays)
		expAt = &t
	}
	cleartext, row, err := mintPATForUser(userID, req.Name, req.Scopes, expAt, "native")
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	ok_(c, "minted", patMintResp{
		ID: row.ID, Token: cleartext, Prefix: patCleartextPrefix,
		Name: row.Name, Scopes: req.Scopes, ExpiresAt: expAt,
	})
}

// mintPATForUser is the entropy→hash→persist core of PAT creation, shared
// by PATMintHandler (user-facing, validated + canGrant-gated + rate-limited)
// and claudeSandboxPAT (internal auto-mint, source="claude_sandbox").
// Returns the cleartext (surfaced exactly once) and the stored row.
func mintPATForUser(userID, name string, scopes []string, expiresAt *time.Time, source string) (string, *models.Token, error) {
	// 32 bytes of entropy → 64 hex chars, prefixed lm_pat_live_.
	raw, err := randHex(32)
	if err != nil {
		return "", nil, fmt.Errorf("rng")
	}
	cleartext := patCleartextPrefix + raw
	argonHash, err := argon2idHash(cleartext)
	if err != nil {
		return "", nil, fmt.Errorf("hash")
	}
	row := &models.Token{
		ID:        uuid.NewString(),
		UserID:    userID,
		Prefix:    patCleartextPrefix,
		LookupKey: patLookupKey(cleartext),
		Hash:      argonHash,
		HashAlg:   "argon2id",
		Name:      name,
		Scopes:    strings.Join(scopes, " "),
		ExpiresAt: expiresAt,
		Source:    source,
	}
	if err := common.DB.Create(row).Error; err != nil {
		return "", nil, fmt.Errorf("persist: %s", err.Error())
	}
	return cleartext, row, nil
}

func PATListHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}

	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			limit = n
		}
	}
	if o := c.Query("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	// Auto-minted claude-sandbox PATs are internal plumbing — hidden from
	// the user's token list (revoking one is harmless, identity re-mints,
	// but surfacing them just confuses people).
	var total int64
	common.DB.Model(&models.Token{}).
		Where("user_id = ? AND revoked_at IS NULL AND source != ?", userID, claudeSandboxSource).Count(&total)

	var rows []models.Token
	common.DB.Where("user_id = ? AND revoked_at IS NULL AND source != ?", userID, claudeSandboxSource).
		Order("created_at DESC").Limit(limit).Offset(offset).Find(&rows)

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
			Status:      "active",
			LastUsedAt:  lastUsed,
			ExpiresAt:   expires,
			CreateTime:  r.CreatedAt.Unix(),
			Source:      r.Source,
		})
	}
	ok_(c, "ok", gin.H{"tokens": out, "total": total, "limit": limit, "offset": offset})
}

func PATRevokeHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	if !callerHasLumidWrite(c) {
		fail(c, http.StatusForbidden, 1005, "PAT scope insufficient: lumid:write required to revoke tokens")
		return
	}
	id := c.Param("id")

	var existing models.Token
	if err := common.DB.Where("id = ? AND user_id = ?", id, userID).First(&existing).Error; err != nil {
		fail(c, http.StatusNotFound, 1002, "token not found")
		return
	}
	if existing.RevokedAt != nil {
		fail(c, http.StatusConflict, 1006, "token already revoked")
		return
	}
	common.DB.Model(&existing).Update("revoked_at", gorm.Expr("NOW()"))
	// The revoked row may be this user's cached claude-sandbox PAT — drop
	// the cache entry so new turns re-mint instead of shipping a dead token.
	invalidateSandboxPATCache(userID)
	ok_(c, "revoked", nil)
}

// PATRotateHandler revokes an existing PAT and mints a replacement with
// the same name + scopes + TTL (computed from the remaining lifespan of
// the original, if it had one). Returns the new cleartext once.
func PATRotateHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	if !callerHasLumidWrite(c) {
		fail(c, http.StatusForbidden, 1005, "PAT scope insufficient: lumid:write required to rotate tokens")
		return
	}
	if !checkPATMintRate(c.Request.Context(), userID) {
		fail(c, http.StatusTooManyRequests, 1429, "too many tokens rotated; try again later")
		return
	}
	id := c.Param("id")

	var newToken string
	var newRow models.Token
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		var old models.Token
		if err := tx.Where("id = ? AND user_id = ? AND revoked_at IS NULL",
			id, userID).First(&old).Error; err != nil {
			return err
		}
		if err := tx.Model(&old).Update("revoked_at", gorm.Expr("NOW()")).Error; err != nil {
			return err
		}
		raw, err := randHex(32)
		if err != nil {
			return err
		}
		cleartext := patCleartextPrefix + raw
		argonHash, err := argon2idHash(cleartext)
		if err != nil {
			return err
		}
		lk := patLookupKey(cleartext)

		var expAt *time.Time
		if old.ExpiresAt != nil {
			remaining := time.Until(*old.ExpiresAt)
			if remaining > 0 {
				t := time.Now().Add(remaining)
				expAt = &t
			}
		}
		newRow = models.Token{
			ID:        uuid.NewString(),
			UserID:    userID,
			Prefix:    patCleartextPrefix,
			LookupKey: lk,
			Hash:      argonHash,
			HashAlg:   "argon2id",
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
		fail(c, http.StatusNotFound, 1002, "token not found or already revoked")
		return
	}
	// Rotate revokes the old row — same cache concern as PATRevokeHandler.
	invalidateSandboxPATCache(userID)
	scopes := strings.Fields(newRow.Scopes)
	ok_(c, "rotated", patMintResp{
		ID: newRow.ID, Token: newToken, Prefix: patCleartextPrefix,
		Name: newRow.Name, Scopes: scopes, ExpiresAt: newRow.ExpiresAt,
	})
}

// callerHasLumidWrite returns true when the request is authenticated via a
// session JWT (unrestricted) or via a PAT whose scopes include lumid:write,
// lumid:admin, lumid:*, or the global wildcard *.
func callerHasLumidWrite(c *gin.Context) bool {
	tok := bearerToken(c)
	if !strings.HasPrefix(tok, "lm_pat_") {
		return true // session JWT — not PAT-gated
	}
	row, ok := lookupPAT(tok)
	if !ok {
		return false
	}
	for _, s := range strings.Fields(row.Scopes) {
		if s == "*" || s == "lumid:write" || s == "lumid:admin" || s == "lumid:*" {
			return true
		}
	}
	return false
}

// currentUserID resolves the session cookie, Bearer JWT, or lm_pat_*
// PAT to a user id. Returns (id, true) on success.
func currentUserID(c *gin.Context) (string, bool) {
	tok := bearerToken(c)
	if tok == "" {
		return "", false
	}
	// JWT path — fast, no DB hit.
	if claims, err := common.VerifyJWT(tok); err == nil {
		return claims.Subject, true
	}
	// PAT path (lm_pat_* and rm_pat_*).
	if strings.HasPrefix(tok, "lm_pat_") || strings.HasPrefix(tok, "rm_pat_") {
		if row, ok := lookupPAT(tok); ok {
			return row.UserID, true
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

// ok_ — same shape as the helper in helpers.go.
func ok_(c *gin.Context, msg string, data any) { ok(c, msg, data) }

// GrantableScopesHandler — GET /api/v1/identity/grantable-scopes.
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
