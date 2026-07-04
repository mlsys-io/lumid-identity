package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

// Google scopes the personal-agent xpio app needs on top of the
// existing sign-in scopes (openid email profile).
const (
	gmailScope    = "https://www.googleapis.com/auth/gmail.modify"
	calendarScope = "https://www.googleapis.com/auth/calendar"
)

// connectRedirectURL derives the public URL Google should redirect to
// after consent. Built from the same origin as the existing sign-in
// callback (“cfg.RedirectURI“, e.g. “https://lum.id/auth/callback“)
// — we keep just the scheme+host and append our backend path. That
// origin must already be on the OAuth client's "Authorized redirect
// URIs" list (one-time admin step in Google Cloud Console).
func connectRedirectURL(loginRedirect string) string {
	loginRedirect = strings.TrimRight(loginRedirect, "/")
	if loginRedirect == "" {
		loginRedirect = "https://lum.id/auth/callback"
	}
	if u, err := url.Parse(loginRedirect); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/api/v1/oauth/google/connect/callback"
	}
	return "https://lum.id/api/v1/oauth/google/connect/callback"
}

// POST /api/v1/oauth/google/connect/init — session-bearer-gated.
// Returns the URL the browser should redirect to so the user can
// approve Gmail + Calendar scopes. The lum.id "Connect Gmail +
// Calendar" button on /dashboard/account/connect/google calls this
// and then window.location-assigns the returned authorize_url.
func GoogleConnectInit(c *gin.Context) {
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

	cfg := config.G.OAuth.Google
	if cfg.ClientID == "" {
		fail(c, http.StatusServiceUnavailable, 1500,
			"GOOGLE_CLIENT_ID unset on lumid-identity")
		return
	}
	connectRedirect := connectRedirectURL(cfg.RedirectURI)

	// Optional return_to — where to send the browser after consent. Validate
	// server-side and pack it into `state` alongside the sub so it survives
	// the Google round-trip (Google only echoes `state`).
	var body struct {
		ReturnTo string `json:"return_to"`
	}
	_ = c.ShouldBindJSON(&body) // body is optional
	rt := ""
	if isSafeReturnPath(body.ReturnTo) {
		rt = body.ReturnTo
	}

	q := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {connectRedirect},
		"response_type": {"code"},
		"scope": {strings.Join([]string{
			"openid", "email", "profile", gmailScope, calendarScope,
		}, " ")},
		"access_type":            {"offline"},
		"prompt":                 {"consent"},
		"include_granted_scopes": {"true"},
		"state":                  {encodeConnectState(claims.Subject, rt)},
	}

	ok(c, "connect init", gin.H{
		"authorize_url": "https://accounts.google.com/o/oauth2/v2/auth?" + q.Encode(),
		"redirect_uri":  connectRedirect,
		"scopes":        []string{gmailScope, calendarScope},
	})
}

// GET /api/v1/oauth/google/connect/callback — Google bounces here with
// ?code=...&state=<user-sub>. We exchange + persist the refresh-token
// encrypted, then redirect the browser back to /dashboard/account/connect
// so the user sees "✓ Connected".
func GoogleConnectCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")
	errParam := c.Query("error")
	// Decode {sub, return_to} from state up front so every redirect can carry
	// the (server-validated) return_to back to the launching page.
	sub, rt := decodeConnectState(state)
	if !isSafeReturnPath(rt) {
		rt = ""
	}
	redir := func(status, detail string) {
		u := "/dashboard/account/connect/google?google_status=" + url.QueryEscape(status)
		if detail != "" {
			u += "&detail=" + url.QueryEscape(detail)
		}
		if rt != "" {
			u += "&return_to=" + url.QueryEscape(rt)
		}
		c.Redirect(http.StatusSeeOther, u)
	}

	if errParam != "" {
		redir("denied", errParam)
		return
	}
	if code == "" || state == "" {
		redir("invalid", "")
		return
	}

	var u models.User
	if err := common.DB.Where("id = ?", sub).First(&u).Error; err != nil {
		redir("unknown_user", "")
		return
	}

	cfg := config.G.OAuth.Google
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		redir("server_misconfigured", "")
		return
	}
	connectRedirect := connectRedirectURL(cfg.RedirectURI)

	tok, err := exchangeGoogleCode(c.Request.Context(), code, connectRedirect,
		cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		redir("exchange_failed", "")
		return
	}
	if tok.RefreshToken == "" {
		// Google omits refresh_token on subsequent consents unless
		// prompt=consent forces re-issue (which we set above). If we
		// still get nothing, the user already had a grant and reused
		// it — in that case keep the existing row.
		redir("already_connected", "")
		return
	}

	enc, err := common.EncryptGrant(tok.RefreshToken)
	if err != nil {
		redir("encrypt_failed", "")
		return
	}

	now := time.Now().UTC()
	grant := models.GoogleGrant{
		UserSub:               u.ID,
		RefreshTokenEncrypted: enc,
		Scopes:                strings.Join([]string{gmailScope, calendarScope}, " "),
		ClientID:              cfg.ClientID,
		GrantedAt:             now,
	}
	common.DB.Save(&grant)

	redir("connected", "")
}

// GET /api/v1/identity/google-token — bearer-gated (accepts JWT
// session OR “lm_pat_*“ PAT; both resolve via currentUserID()).
// Returns the user's stored refresh-token + client-id so the
// personal-agent CLI can mint access-tokens locally.
func GoogleTokenFetch(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	var grant models.GoogleGrant
	err := common.DB.Where("user_sub = ?", userID).First(&grant).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusNotFound, 1404,
			"no google grant — click Connect Gmail + Calendar at /dashboard/account/connect")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	if grant.RevokedAt != nil {
		fail(c, http.StatusGone, 1410, "google grant revoked; reconnect to mint a new one")
		return
	}

	rt, err := common.DecryptGrant(grant.RefreshTokenEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}

	now := time.Now().UTC()
	common.DB.Model(&grant).Update("last_used_at", now)

	scopes := strings.Fields(grant.Scopes)
	c.JSON(http.StatusOK, gin.H{
		"refresh_token": rt,
		"client_id":     grant.ClientID,
		"scopes":        scopes,
		"granted_at":    grant.GrantedAt.Format(time.RFC3339),
	})
}

// GET /api/v1/identity/google-grants — session-bearer-gated.
// Returns grant metadata (scopes, granted_at, last_used_at, revoked_at)
// for the current user — but NOT the refresh-token. Used by the
// dashboard tokens page to render "connected/disconnected" state
// without exposing the actual credential to the browser. The token
// itself is only fetched once, by the CLI setup verb, via
// /api/v1/identity/google-token (which requires the same session
// bearer but ships the secret).
func GoogleGrantsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	var grant models.GoogleGrant
	err := common.DB.Where("user_sub = ?", userID).First(&grant).Error
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"google": nil},
		})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}

	scopes := strings.Fields(grant.Scopes)
	state := "connected"
	if grant.RevokedAt != nil {
		state = "revoked"
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"google": gin.H{
				"state":        state,
				"scopes":       scopes,
				"client_id":    grant.ClientID,
				"granted_at":   grant.GrantedAt.Format(time.RFC3339),
				"last_used_at": optionalTime(grant.LastUsedAt),
				"revoked_at":   optionalTime(grant.RevokedAt),
			},
		},
	})
}

func optionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}

// POST /api/v1/identity/google-access-token — bearer-gated.
// Server-mediated token refresh. The client never sees the OAuth
// client_secret (which lumid keeps as a deployment env var); the CLI
// posts here, the server uses the user's stored refresh-token + the
// shared client credentials to mint a fresh access-token, and ships
// the access-token back. Caller caches it client-side until expiry.
//
// Request body: empty (the user_sub comes from the bearer; the
// refresh-token is already on the server). Response:
//
//	{"access_token": "ya29...", "expires_in": 3599, "token_type": "Bearer",
//	 "scopes": ["...gmail.modify", "...calendar"]}
//
// Errors:
//
//	401 — no bearer
//	404 — no grant for this user
//	410 — grant revoked
//	502 — Google rejected the refresh (token revoked at Google's end,
//	       rate-limit, etc); body carries Google's error verbatim.
func GoogleAccessToken(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	body, status, err := mintGoogleAccessTokenRaw(c.Request.Context(), userID)
	if err != nil {
		fail(c, status, 1500, err.Error())
		return
	}
	c.Data(status, "application/json", body)
}

// mintGoogleAccessTokenRaw is the in-process helper behind both the
// HTTP handler above and the me_agent Gmail/Calendar tools. Returns
// Google's verbatim token payload as JSON bytes alongside the HTTP
// status code we'd surface to a caller (200 on success, 404/410/etc.
// on grant-lookup failures, 502 on Google's end). Useful so the
// agent-tool helpers don't have to make a self-HTTP-call.
func mintGoogleAccessTokenRaw(ctx context.Context, userID string) ([]byte, int, error) {
	var grant models.GoogleGrant
	err := common.DB.Where("user_sub = ?", userID).First(&grant).Error
	if err == gorm.ErrRecordNotFound {
		return nil, http.StatusNotFound, fmt.Errorf("no google grant — connect at /dashboard/account/connect/google")
	}
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("lookup: %w", err)
	}
	if grant.RevokedAt != nil {
		return nil, http.StatusGone, fmt.Errorf("google grant revoked; reconnect to mint a new one")
	}

	rt, err := common.DecryptGrant(grant.RefreshTokenEncrypted)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("decrypt: %w", err)
	}

	cfg := config.G.OAuth.Google
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("GOOGLE_CLIENT_ID/SECRET unset on lumid-identity")
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://oauth2.googleapis.com/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, fmt.Errorf("google: %w", err)
	}
	defer resp.Body.Close()
	body, _ := readAll(resp.Body)
	if resp.StatusCode != 200 {
		return body, http.StatusBadGateway, fmt.Errorf("google %d", resp.StatusCode)
	}
	now := time.Now().UTC()
	common.DB.Model(&grant).Update("last_used_at", now)
	return body, http.StatusOK, nil
}

// mintGoogleAccessToken is a convenience wrapper for me_agent tools —
// returns just the access_token string. Errors propagate cleanly so
// the tool can surface them.
func mintGoogleAccessToken(ctx context.Context, userID string) (string, error) {
	body, _, err := mintGoogleAccessTokenRaw(ctx, userID)
	if err != nil {
		return "", err
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse token: %w", err)
	}
	if payload.AccessToken == "" {
		return "", fmt.Errorf("token: empty access_token in google response")
	}
	return payload.AccessToken, nil
}

// readAll reads an http.Response.Body without pulling in extra deps.
func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return buf, nil
			}
			return buf, err
		}
	}
}

// DELETE /api/v1/identity/google-token — bearer-gated.
// Marks the grant as revoked. Subsequent /google-token GETs return 410
// until the user re-consents via /dashboard/account/connect.
func GoogleTokenRevoke(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	now := time.Now().UTC()
	res := common.DB.Model(&models.GoogleGrant{}).
		Where("user_sub = ?", userID).
		Update("revoked_at", now)
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "no grant to revoke")
		return
	}
	ok(c, "revoked", gin.H{"revoked_at": now.Format(time.RFC3339)})
}
