package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// OIDC authorization_code flow with PKCE. Target consumer today:
// oauth2-proxy sidecar in front of Umami. Future consumers (any
// service that wants an SSO experience on lum.id) use the same flow.

// ---------- /oauth/authorize ----------

func OAuthAuthorizeHandler(c *gin.Context) {
	// Pull the full set of OIDC params. We enforce PKCE always
	// (S256) — no confidential-only flows shipped.
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if responseType != "code" {
		renderAuthorizeError(c, redirectURI, state, "unsupported_response_type",
			"only response_type=code is supported")
		return
	}
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		renderAuthorizeError(c, redirectURI, state, "invalid_request",
			"PKCE required: code_challenge + code_challenge_method=S256")
		return
	}

	// Look up the client; validate redirect_uri is on its allowlist.
	var client models.OAuthClient
	if err := common.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		c.HTML(http.StatusBadRequest, "", []byte("unknown client_id"))
		c.String(http.StatusBadRequest, "unknown client_id")
		return
	}
	if !redirectURIAllowed(client.RedirectURIs, redirectURI) {
		c.String(http.StatusBadRequest, "redirect_uri not allowlisted for client")
		return
	}

	// Who is the user? Check lm_session cookie.
	tok := bearerToken(c)
	if tok == "" {
		bounceToLogin(c)
		return
	}
	claims, err := common.VerifyJWT(tok)
	if err != nil {
		bounceToLogin(c)
		return
	}

	// Mint the short-lived authorization code.
	code, err := randHex(32)
	if err != nil {
		c.String(http.StatusInternalServerError, "rng: "+err.Error())
		return
	}
	if err := common.DB.Create(&models.OAuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              claims.Subject,
		RedirectURI:         redirectURI,
		Scopes:              scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}).Error; err != nil {
		c.String(http.StatusInternalServerError, "persist code: "+err.Error())
		return
	}

	// Redirect back to the client.
	q := url.Values{"code": {code}}
	if state != "" {
		q.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, redirectURI+sep+q.Encode())
}

func renderAuthorizeError(c *gin.Context, redirectURI, state, errCode, desc string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errCode, "error_description": desc})
		return
	}
	q := url.Values{"error": {errCode}, "error_description": {desc}}
	if state != "" {
		q.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	c.Redirect(http.StatusFound, redirectURI+sep+q.Encode())
}

func bounceToLogin(c *gin.Context) {
	returnTo := c.Request.URL.RequestURI()
	// /auth is the mount point for lumid_auth_ui. Pass the original
	// authorize URL so the user lands back here after login.
	loginURL := "/auth/login?return_to=" + url.QueryEscape(returnTo)
	c.Redirect(http.StatusFound, loginURL)
}

func redirectURIAllowed(allowlist, requested string) bool {
	if requested == "" {
		return false
	}
	for _, line := range strings.Split(allowlist, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line == requested {
			return true
		}
	}
	return false
}

// ---------- /oauth/token ----------

func OAuthTokenHandler(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	switch grantType {
	case "authorization_code":
		tokenAuthCode(c)
	case "refresh_token":
		tokenRefresh(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "want authorization_code or refresh_token",
		})
	}
}

func tokenAuthCode(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID, clientSecret := extractClientCreds(c)
	codeVerifier := c.PostForm("code_verifier")

	if code == "" || clientID == "" || codeVerifier == "" {
		tokenErr(c, "invalid_request", "code + client_id + code_verifier required")
		return
	}

	// Client auth: confidential clients verify secret; public clients
	// (is_public=true) only need PKCE.
	client, err := authenticateClient(clientID, clientSecret)
	if err != nil {
		tokenErr(c, "invalid_client", err.Error())
		return
	}

	var codeRow models.OAuthCode
	if err := common.DB.Where("code = ?", code).First(&codeRow).Error; err != nil {
		tokenErr(c, "invalid_grant", "unknown code")
		return
	}
	if codeRow.UsedAt != nil {
		tokenErr(c, "invalid_grant", "code already used")
		return
	}
	if time.Now().After(codeRow.ExpiresAt) {
		tokenErr(c, "invalid_grant", "code expired")
		return
	}
	if codeRow.ClientID != client.ClientID {
		tokenErr(c, "invalid_grant", "code client_id mismatch")
		return
	}
	if codeRow.RedirectURI != redirectURI {
		tokenErr(c, "invalid_grant", "redirect_uri mismatch")
		return
	}
	// PKCE verify — base64url(sha256(code_verifier)) must equal code_challenge.
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != codeRow.CodeChallenge {
		tokenErr(c, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}
	// Mark used so replay fails.
	now := time.Now()
	common.DB.Model(&models.OAuthCode{}).Where("code = ?", code).Update("used_at", &now)

	// Load the user so the access + id tokens carry the right claims.
	var u models.User
	if err := common.DB.First(&u, "id = ?", codeRow.UserID).Error; err != nil {
		tokenErr(c, "server_error", "user missing")
		return
	}
	scopes := strings.Fields(codeRow.Scopes)
	// Always include openid so id_token is served.
	if !contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	accessTok, jti, exp, err := common.IssueJWT(u.ID, u.Email, u.Role, scopes)
	if err != nil {
		tokenErr(c, "server_error", "issue access_token: "+err.Error())
		return
	}
	// Register the session for logout-everywhere.
	common.DB.Create(&models.Session{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		JTI:       jti,
		ClientID:  client.ClientID,
		ExpiresAt: exp,
	})
	// id_token — carries identity claims the OIDC relying-party needs.
	// aud MUST equal client_id per the spec; that's what
	// oauth2-proxy (and every other RP) verifies.
	idTok, _, err := common.IssueIDToken(u.ID, u.Email, u.Name, client.ClientID, u.EmailVerified)
	if err != nil {
		tokenErr(c, "server_error", "issue id_token: "+err.Error())
		return
	}
	refreshTok, _ := randHex(32)
	// Refresh-token persistence is scoped out of Phase 6 — oauth2-proxy
	// handles its own session lifetime. Return the string so RFC-compliant
	// clients don't complain, but it's opaque.

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessTok,
		"id_token":      idTok,
		"refresh_token": refreshTok,
		"token_type":    "Bearer",
		"expires_in":    config.G.JWT.AccessTTLSec,
		"scope":         strings.Join(scopes, " "),
	})
}

func tokenRefresh(c *gin.Context) {
	tokenErr(c, "unsupported_grant_type", "refresh not implemented; re-auth via authorize")
}

func extractClientCreds(c *gin.Context) (string, string) {
	if id, secret, ok := c.Request.BasicAuth(); ok {
		return id, secret
	}
	return c.PostForm("client_id"), c.PostForm("client_secret")
}

func authenticateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	var cl models.OAuthClient
	if err := common.DB.Where("client_id = ?", clientID).First(&cl).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("unknown client")
		}
		return nil, err
	}
	if cl.IsPublic {
		return &cl, nil
	}
	if cl.SecretHash == "" {
		return nil, fmt.Errorf("client secret not set")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cl.SecretHash), []byte(clientSecret)); err != nil {
		return nil, fmt.Errorf("bad client secret")
	}
	return &cl, nil
}

func tokenErr(c *gin.Context, code, desc string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": code, "error_description": desc})
}

func contains(ss []string, needle string) bool {
	for _, s := range ss {
		if s == needle {
			return true
		}
	}
	return false
}

// Compile-time assertion for the hex package; keeps goimports happy.
var _ = hex.EncodeToString

// ---------- /oauth/userinfo ----------

func OAuthUserinfoHandler(c *gin.Context) {
	// Standard Bearer auth — the OIDC access_token is our JWT.
	tok := bearerToken(c)
	if tok == "" {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return
	}
	claims, err := common.VerifyJWT(tok)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return
	}
	var u models.User
	if err := common.DB.Where("id = ?", claims.Subject).First(&u).Error; err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"sub":            u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified,
		"name":           u.Name,
		"preferred_username": u.Email,
		"picture":        u.AvatarURL,
	})
}

// ---------- helpers ----------

func randHexBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
