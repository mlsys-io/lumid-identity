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

type patListItem struct {
	ID         string     `json:"id"`
	Prefix     string     `json:"prefix"`
	Name       string     `json:"name"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Source     string     `json:"source"`
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
		out = append(out, patListItem{
			ID: r.ID, Prefix: r.Prefix, Name: r.Name,
			Scopes: strings.Fields(r.Scopes), CreatedAt: r.CreatedAt,
			LastUsedAt: r.LastUsedAt, ExpiresAt: r.ExpiresAt, Source: r.Source,
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

// currentUserID resolves the session cookie or Bearer JWT to a user id.
// Returns (id, true) on success.
func currentUserID(c *gin.Context) (string, bool) {
	tok := bearerToken(c)
	if tok == "" {
		return "", false
	}
	claims, err := common.VerifyJWT(tok)
	if err != nil {
		return "", false
	}
	return claims.Subject, true
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
