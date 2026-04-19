package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
)

// IntrospectResponse follows RFC 7662 with lum.id-specific extras.
// Anyone calling introspect gets the same shape regardless of which
// token prefix went in — this is the whole point of consolidating
// auth on lum.id.
type IntrospectResponse struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub,omitempty"`        // canonical user id
	Username  string   `json:"username,omitempty"`
	Email     string   `json:"email,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Scope     string   `json:"scope,omitempty"`      // space-separated, RFC 7662 shape
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"` // pat | jwt
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Source    string   `json:"source,omitempty"`     // native | legacy-lqa | legacy-runmesh
	Reason    string   `json:"reason,omitempty"`     // why active=false
}

// Introspect — POST /oauth/introspect (form or JSON body).
//
// During shadow phase (config.Legacy.Enabled=true) we read LQA's
// tbl_rm_personal_access_token directly so the response is
// byte-for-byte a mirror of LQA's /api/v1/identity/introspect —
// that's the acceptance gate for Phase 1.
func Introspect(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		// accept raw body too, for curl ergonomics
		if c.Request.ContentLength > 0 {
			b, _ := c.GetRawData()
			token = strings.TrimSpace(string(b))
			if strings.HasPrefix(token, "token=") {
				token = strings.TrimPrefix(token, "token=")
			}
		}
	}
	token = strings.TrimSpace(token)

	if token == "" {
		c.JSON(http.StatusOK, IntrospectResponse{Active: false, Reason: "no token"})
		return
	}

	// Fast path for legacy prefixes during shadow.
	if config.G.Legacy.Enabled && strings.HasPrefix(token, "rm_pat_") {
		if resp := introspectLegacyLQA(token); resp != nil {
			c.JSON(http.StatusOK, resp)
			return
		}
	}

	// Native lm_* tokens (Phase 3 onward)
	if strings.HasPrefix(token, "lm_") {
		if resp := introspectNative(token); resp != nil {
			c.JSON(http.StatusOK, resp)
			return
		}
	}

	// JWT (lm_session cookies, Bearer Authorization headers)
	if strings.Count(token, ".") == 2 {
		if resp := introspectJWT(token); resp != nil {
			c.JSON(http.StatusOK, resp)
			return
		}
	}

	c.JSON(http.StatusOK, IntrospectResponse{Active: false, Reason: "unknown token"})
}

// introspectLegacyLQA mirrors the shape of LQA's IdentityLogic.Introspect.
// We read the same tbl_rm_personal_access_token rows, so if the row
// exists, is not revoked, and is not expired, active=true. Scopes are
// stored space-separated in LQA too — just pass them through unchanged
// so downstream consumers don't have to learn a new vocabulary until
// Phase 8.
func introspectLegacyLQA(token string) *IntrospectResponse {
	if common.LegacyDB == nil {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	// LQA schema: tbl_rm_personal_access_token has columns
	// user_id, token_hash, scopes, expires_at, revoked_at, name.
	// We query by raw SQL to avoid importing LQA's GORM models.
	var row struct {
		UserID    int64   `gorm:"column:user_id"`
		Scopes    string  `gorm:"column:scopes"`
		ExpiresAt *int64  `gorm:"column:expires_at"`
		RevokedAt *int64  `gorm:"column:revoked_at"`
		Name      string  `gorm:"column:name"`
	}
	err := common.LegacyDB.Raw(`
		SELECT user_id, scopes, expires_at, revoked_at, name
		FROM tbl_rm_personal_access_token
		WHERE token_hash = ?
		LIMIT 1`, hash).Scan(&row).Error
	if err != nil || row.UserID == 0 {
		return &IntrospectResponse{Active: false, Reason: "no such token"}
	}
	now := time.Now().Unix()
	if row.RevokedAt != nil && *row.RevokedAt > 0 {
		return &IntrospectResponse{Active: false, Reason: "revoked"}
	}
	if row.ExpiresAt != nil && *row.ExpiresAt > 0 && *row.ExpiresAt < now {
		return &IntrospectResponse{Active: false, Reason: "expired"}
	}

	// Pull the LQA user so downstream gets a useful sub + email.
	var u struct {
		ID       int64  `gorm:"column:id"`
		Email    string `gorm:"column:email"`
		Username string `gorm:"column:username"`
	}
	common.LegacyDB.Raw(`SELECT id, email, username FROM tbl_user WHERE id = ? LIMIT 1`, row.UserID).Scan(&u)

	// LQA stores scopes comma-separated; Runmesh stores space-separated.
	// Accept either and normalize so downstream consumers see a clean array.
	raw := strings.ReplaceAll(row.Scopes, ",", " ")
	scopeList := strings.Fields(raw)
	var exp int64
	if row.ExpiresAt != nil {
		exp = *row.ExpiresAt
	}
	return &IntrospectResponse{
		Active:    true,
		Sub:       itoa(row.UserID),
		Email:     u.Email,
		Username:  u.Username,
		Scopes:    scopeList,
		Scope:     strings.Join(scopeList, " "),
		TokenType: "pat",
		Exp:       exp,
		Source:    "legacy-lqa",
	}
}

// introspectNative — native lm_* token lookup. Stubbed until Phase 3.
func introspectNative(token string) *IntrospectResponse {
	return nil
}

// introspectJWT — verify against our signing keys. Stubbed until JWT
// issuance lands (Phase 2 login flow).
func introspectJWT(token string) *IntrospectResponse {
	return nil
}

func itoa(i int64) string {
	// small helper, avoids importing strconv for a single call site
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
