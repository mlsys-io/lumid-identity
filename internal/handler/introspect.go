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
	// Role from the user record — "user" or "admin". Downstream
	// services (Runmesh admin UI via lum.id, etc.) read this to
	// decide whether a lum.id-issued token is allowed to hit admin
	// endpoints without an extra permission map of their own.
	Role      string   `json:"role,omitempty"`
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
//
// Response envelope: when the route is the legacy LQA-compatible
// alias `/api/v1/identity/introspect`, we wrap in LQA's
// `{ret_code,message,data}` so Runmesh's existing mapLqaResponse
// stays happy. The OIDC-standard `/oauth/introspect` stays flat
// per RFC 7662.
func Introspect(c *gin.Context) {
	token := extractIntrospectToken(c)

	if token == "" {
		writeIntrospect(c, IntrospectResponse{Active: false, Reason: "no token"})
		return
	}

	// Phase 8 metric: record which prefixes are still seen in the
	// wild so we can time the sunset of legacy rm_pat_*/rmk_*/flm-*.
	// Written async — introspect is on the hot path for every
	// downstream service + must not block on a DB insert.
	go recordIntrospectAudit(c.ClientIP(), c.GetHeader("User-Agent"), token)

	// Fast path for legacy prefixes during shadow.
	if config.G.Legacy.Enabled && strings.HasPrefix(token, "rm_pat_") {
		if resp := introspectLegacyLQA(token); resp != nil {
			writeIntrospect(c, *resp)
			return
		}
	}

	// Native lm_* tokens (Phase 3 onward)
	if strings.HasPrefix(token, "lm_") {
		if resp := introspectNative(token); resp != nil {
			writeIntrospect(c, *resp)
			return
		}
	}

	// JWT (lm_session cookies, Bearer Authorization headers)
	if strings.Count(token, ".") == 2 {
		if resp := introspectJWT(token); resp != nil {
			writeIntrospect(c, *resp)
			return
		}
	}

	writeIntrospect(c, IntrospectResponse{Active: false, Reason: "unknown token"})
}

// extractIntrospectToken pulls the token out of form body, JSON body,
// or Authorization header — whichever the caller used. Runmesh sends
// JSON `{"token": "..."}` via WebClient; curl tends to use form;
// OAuth2 clients may use either per the RFC 7662 spec.
func extractIntrospectToken(c *gin.Context) string {
	if t := strings.TrimSpace(c.PostForm("token")); t != "" {
		return t
	}
	// Try JSON body.
	ct := c.ContentType()
	if strings.Contains(ct, "application/json") {
		var body struct {
			Token string `json:"token"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			if t := strings.TrimSpace(body.Token); t != "" {
				return t
			}
		}
	}
	// Final fallback: raw body (handles `token=xxx` without proper
	// Content-Type header, which some hand-rolled curl scripts send).
	if c.Request.ContentLength > 0 {
		b, _ := c.GetRawData()
		raw := strings.TrimSpace(string(b))
		if strings.HasPrefix(raw, "token=") {
			return strings.TrimPrefix(raw, "token=")
		}
		// Accept a bare JWT in the body too.
		return raw
	}
	// Authorization header: Bearer <token>.
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// writeIntrospect picks the envelope shape per route. /oauth/introspect
// stays flat (RFC 7662 + OIDC-compatible); the LQA-compatible alias
// at /api/v1/identity/introspect wraps in `{ret_code,message,data}`
// because downstream Runmesh code reads `envelope.data`.
func writeIntrospect(c *gin.Context, resp IntrospectResponse) {
	if strings.HasPrefix(c.FullPath(), "/api/v1/identity/") {
		ok(c, "operation.success", resp)
		return
	}
	c.JSON(http.StatusOK, resp)
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

	// Pull the LQA user so downstream gets a useful sub + email + role.
	var u struct {
		ID       int64  `gorm:"column:id"`
		Email    string `gorm:"column:email"`
		Username string `gorm:"column:username"`
		Role     string `gorm:"column:role"`
	}
	common.LegacyDB.Raw(`SELECT id, email, username, role FROM tbl_user WHERE id = ? LIMIT 1`, row.UserID).Scan(&u)

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
		Role:      u.Role,
		Scopes:    scopeList,
		Scope:     strings.Join(scopeList, " "),
		TokenType: "pat",
		Exp:       exp,
		Source:    "legacy-lqa",
	}
}

// introspectNative — native lm_* token lookup against lumid_identity.tokens.
// Bumps last_used_at on hit so the dashboard can show stale tokens.
func introspectNative(token string) *IntrospectResponse {
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var row struct {
		ID        string
		UserID    string
		Prefix    string
		Scopes    string
		ExpiresAt *time.Time
		RevokedAt *time.Time
	}
	err := common.DB.Raw(`
		SELECT id, user_id, prefix, scopes, expires_at, revoked_at
		FROM tokens WHERE hash = ? LIMIT 1`, hash).Scan(&row).Error
	if err != nil || row.ID == "" {
		return &IntrospectResponse{Active: false, Reason: "no such token"}
	}
	now := time.Now()
	if row.RevokedAt != nil {
		return &IntrospectResponse{Active: false, Reason: "revoked"}
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
		return &IntrospectResponse{Active: false, Reason: "expired"}
	}
	// async last_used_at bump; don't block the reply
	go common.DB.Exec(`UPDATE tokens SET last_used_at = ? WHERE id = ?`, now, row.ID)

	// Enrich with email/name for downstream ergonomics.
	var u struct {
		Email string
		Name  string
		Role  string
	}
	common.DB.Raw(`SELECT email, name, role FROM users WHERE id = ? LIMIT 1`, row.UserID).Scan(&u)

	scopes := strings.Fields(row.Scopes)
	var exp int64
	if row.ExpiresAt != nil {
		exp = row.ExpiresAt.Unix()
	}
	return &IntrospectResponse{
		Active:    true,
		Sub:       row.UserID,
		Email:     u.Email,
		Username:  u.Name,
		Role:      u.Role,
		Scopes:    scopes,
		Scope:     strings.Join(scopes, " "),
		TokenType: "pat",
		Exp:       exp,
		Source:    "native",
	}
}

// introspectJWT — verify the signature against our JWKS + check
// the session isn't revoked. Used when downstream services bounce
// the bearer cookie through introspect instead of verifying locally.
func introspectJWT(token string) *IntrospectResponse {
	claims, err := common.VerifyJWT(token)
	if err != nil {
		return &IntrospectResponse{Active: false, Reason: "jwt verify: " + err.Error()}
	}
	// Session revocation: one row per jti. Logout flips revoked_at.
	// We treat "no such session" as expired (the JWT verified fine
	// but the server has no record — could be post-restart before the
	// session table was migrated; let it through to avoid lockout).
	var sess struct {
		ID        string     `gorm:"column:id"`
		RevokedAt *time.Time `gorm:"column:revoked_at"`
	}
	common.DB.Raw(`SELECT id, revoked_at FROM sessions WHERE jti = ? LIMIT 1`, claims.ID).Scan(&sess)
	if sess.ID != "" && sess.RevokedAt != nil {
		return &IntrospectResponse{Active: false, Reason: "session revoked"}
	}
	scopes := strings.Fields(claims.Scopes)
	return &IntrospectResponse{
		Active:    true,
		Sub:       claims.Subject,
		Email:     claims.Email,
		Role:      claims.Role,
		Scopes:    scopes,
		Scope:     claims.Scopes,
		TokenType: "jwt",
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Source:    "native",
	}
}

// recordIntrospectAudit writes one row per /oauth/introspect hit so
// the deprecation dashboard can see which legacy prefixes are still
// in play. Token body is never logged — only its prefix.
func recordIntrospectAudit(ip, ua, token string) {
	prefix := "unknown"
	switch {
	case strings.HasPrefix(token, "lm_pat_"):
		prefix = "lm_pat"
	case strings.HasPrefix(token, "rm_pat_"):
		prefix = "rm_pat-legacy"
	case strings.HasPrefix(token, "rmk_"):
		prefix = "rmk-legacy"
	case strings.HasPrefix(token, "flm-"):
		prefix = "flm-legacy"
	case strings.Count(token, ".") == 2:
		prefix = "jwt"
	}
	common.DB.Exec(
		`INSERT INTO audit_log (event, source, path, detail, ip, user_agent)
		 VALUES ('introspect', ?, '/oauth/introspect', ?, ?, ?)`,
		prefix, `{"prefix":"`+prefix+`"}`, ip, ua,
	)
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
