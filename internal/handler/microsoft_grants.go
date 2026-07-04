package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Microsoft Graph OAuth — Shape 3 (centralized auth, distributed runtime).
//
// Uses Microsoft's pre-registered Graph PowerShell SDK public client_id
// (14d82eec-...), a Microsoft-verified app present in every Azure AD
// tenant by default. Users grant per-user delegated consent without
// IT involvement; this is the path that survives corporate tenant
// policies blocking custom Azure app registration AND SAS-token HTTP
// triggers in Power Automate.
//
// The flow is device-code:
//   1. POST /api/v1/oauth/microsoft/connect/init — backend asks
//      Microsoft for a device_code; returns user_code + verification
//      URL to the UI. Pending state stored in microsoft_grant_pendings.
//   2. User opens the URL, completes corporate auth + consent.
//   3. UI polls POST /api/v1/oauth/microsoft/connect/poll until ok.
//      Backend exchanges the device_code; refresh_token persists in
//      microsoft_grants (AES-256-GCM at rest, same crypto as
//      google_grants).
//   4. Runtime callers (daemon, skills) POST /api/v1/identity/
//      microsoft-access-token with their PAT/JWT bearer. The server
//      mints a fresh access-token from the stored refresh + the
//      shared client_id and returns it. Tokens never leave the
//      server-side decrypted memory except as the response body.

const (
	msPublicClientID = "14d82eec-204b-4c2f-b7e8-296a70dab67e" // Microsoft Graph PowerShell SDK
	msAuthority      = "https://login.microsoftonline.com/common"
	msDeviceCodeURL  = msAuthority + "/oauth2/v2.0/devicecode"
	msTokenURL       = msAuthority + "/oauth2/v2.0/token"
	msGraphMe        = "https://graph.microsoft.com/v1.0/me"

	// offline_access asks Microsoft for a refresh-token. The
	// .default scope flavor wouldn't return one for a public client.
	msScopes = "offline_access Mail.ReadWrite Mail.Send Calendars.ReadWrite User.Read"
)

// ── Init (start device-code) ──────────────────────────────────────

// POST /api/v1/oauth/microsoft/connect/init
//
// Body: none (auth via bearer).
// Returns: {user_code, verification_uri, interval_seconds, expires_at,
//
//	message}. The UI shows user_code + URL to the user, then
//	polls /connect/poll until success.
func MicrosoftConnectInit(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	form := url.Values{
		"client_id": {msPublicClientID},
		"scope":     {msScopes},
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", msDeviceCodeURL,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "Microsoft devicecode: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		fail(c, http.StatusBadGateway, 1502,
			fmt.Sprintf("Microsoft devicecode %d: %s", resp.StatusCode, truncateBytes(body, 300)))
		return
	}

	var dc msDeviceCodeResp
	if err := json.Unmarshal(body, &dc); err != nil {
		fail(c, http.StatusBadGateway, 1502, "parse devicecode: "+err.Error())
		return
	}
	expiresAt := time.Now().UTC().Add(time.Duration(dc.ExpiresIn) * time.Second)
	if dc.Interval == 0 {
		dc.Interval = 5
	}

	// Upsert the pending row — a re-init while a flow is in flight
	// just replaces the stale device_code.
	pending := models.MicrosoftGrantPending{
		UserSub:         userID,
		DeviceCode:      dc.DeviceCode,
		UserCode:        dc.UserCode,
		VerificationURI: dc.VerificationURI,
		Interval:        dc.Interval,
		ExpiresAt:       expiresAt,
		StartedAt:       time.Now().UTC(),
	}
	if err := common.DB.Save(&pending).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist pending: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"user_code":        dc.UserCode,
			"verification_uri": dc.VerificationURI,
			"interval_seconds": dc.Interval,
			"expires_at":       expiresAt,
			"message":          dc.Message,
		},
	})
}

// ── Poll (complete device-code) ───────────────────────────────────

// POST /api/v1/oauth/microsoft/connect/poll
//
// Body: none. Reads the user's pending device_code, polls Microsoft
// once. Returns:
//
//	{ status: "pending" }     — keep polling
//	{ status: "connected" }   — refresh-token stored
//	{ status: "expired"  }    — flow timed out; re-run /init
//	{ status: "denied" }      — user declined consent
//	{ status: "error", error: "..." }
//
// The UI calls this every `interval_seconds` from the /init response
// (Microsoft typically returns 5). We don't poll on a server-side
// loop because we want the user to be able to abandon the flow
// without burning resources.
func MicrosoftConnectPoll(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	var pending models.MicrosoftGrantPending
	err := common.DB.Where("user_sub = ?", userID).First(&pending).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusBadRequest, 1404,
			"no pending Microsoft connect flow — call /init first")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	if time.Now().UTC().After(pending.ExpiresAt) {
		_ = common.DB.Delete(&pending).Error
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"status": "expired"},
		})
		return
	}

	tok, errResp, err := exchangeMicrosoftDeviceCode(c.Request.Context(), pending.DeviceCode)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, err.Error())
		return
	}
	if errResp != nil {
		// Microsoft returns 400 with structured errors during normal polling.
		switch errResp.Error {
		case "authorization_pending":
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"status": "pending"},
			})
			return
		case "authorization_declined":
			_ = common.DB.Delete(&pending).Error
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"status": "denied"},
			})
			return
		case "expired_token", "code_expired":
			_ = common.DB.Delete(&pending).Error
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"status": "expired"},
			})
			return
		case "slow_down":
			// Microsoft asks us to back off. Same UX as pending; UI
			// just keeps polling at the interval it already has.
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"status": "pending", "slow_down": true},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"status": "error",
				"error":  fmt.Sprintf("%s: %s", errResp.Error, errResp.ErrorDescription),
			},
		})
		return
	}

	// Success — store the grant. We also fetch /me to capture the
	// userPrincipalName + displayName for the status card.
	upn, dn := "", ""
	if me, err := fetchMicrosoftMe(c.Request.Context(), tok.AccessToken); err == nil {
		upn = me.UserPrincipalName
		if upn == "" {
			upn = me.Mail
		}
		dn = me.DisplayName
	}

	enc, err := common.EncryptGrant(tok.RefreshToken)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
		return
	}
	now := time.Now().UTC()
	grant := models.MicrosoftGrant{
		UserSub:               userID,
		RefreshTokenEncrypted: enc,
		Scopes:                tok.Scope,
		ClientID:              msPublicClientID,
		HomeAccountID:         "", // MSAL would set this; raw OAuth doesn't return it
		UserPrincipalName:     upn,
		DisplayName:           dn,
		GrantedAt:             now,
	}
	if err := common.DB.Save(&grant).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist grant: "+err.Error())
		return
	}
	_ = common.DB.Delete(&pending).Error

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"status":              "connected",
			"user_principal_name": upn,
			"display_name":        dn,
			"scopes":              tok.Scope,
			"granted_at":          now,
		},
	})
}

// ── Status + revoke ────────────────────────────────────────────────

// GET /api/v1/identity/microsoft-grants — status card.
// Mirrors GoogleGrantsList. Returns nothing about the refresh-token.
func MicrosoftGrantsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var g models.MicrosoftGrant
	err := common.DB.Where("user_sub = ?", userID).First(&g).Error
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"state": "not_connected"},
		})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	state := "connected"
	if g.RevokedAt != nil {
		state = "revoked"
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"state":               state,
			"user_principal_name": g.UserPrincipalName,
			"display_name":        g.DisplayName,
			"scopes":              g.Scopes,
			"granted_at":          g.GrantedAt,
			"last_used_at":        g.LastUsedAt,
			"revoked_at":          g.RevokedAt,
		},
	})
}

// DELETE /api/v1/identity/microsoft-token — revoke locally.
// We don't call Microsoft's revocation endpoint (which requires a
// client_secret we don't have for the public client); deleting the
// row makes the refresh-token unusable on our side, which is
// sufficient. The user can also revoke from
// myaccount.microsoft.com/orgapps if they want belt-and-braces.
func MicrosoftTokenRevoke(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	if err := common.DB.Where("user_sub = ?", userID).
		Delete(&models.MicrosoftGrant{}).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "revoked"})
}

// ── Access-token mint (runtime callers) ───────────────────────────

// POST /api/v1/identity/microsoft-access-token — mirror of
// GoogleAccessToken. Daemons / skills / chat tools POST with their
// PAT/JWT bearer; we mint a fresh access-token from the stored
// refresh + the public client_id and return it.
//
// Body (optional): {"scope": "..."} to override the default scope
// set. Most callers pass nothing and accept the default.
func MicrosoftAccessToken(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		Scope string `json:"scope"`
	}
	_ = c.ShouldBindJSON(&body)
	scope := body.Scope
	if scope == "" {
		scope = msScopes
	}

	var g models.MicrosoftGrant
	err := common.DB.Where("user_sub = ?", userID).First(&g).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusBadRequest, 1404,
			"no Microsoft grant — connect at /dashboard/account/connect/microsoft")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	if g.RevokedAt != nil {
		fail(c, http.StatusBadRequest, 1410, "grant revoked")
		return
	}

	refresh, err := common.DecryptGrant(g.RefreshTokenEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}

	tok, errResp, err := refreshMicrosoftToken(c.Request.Context(), refresh, scope)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, err.Error())
		return
	}
	if errResp != nil {
		// Common: invalid_grant (refresh-token expired / revoked by tenant).
		// User needs to reconnect.
		if errResp.Error == "invalid_grant" {
			fail(c, http.StatusBadRequest, 1401,
				"Microsoft refresh token invalid — reconnect: "+errResp.ErrorDescription)
			return
		}
		fail(c, http.StatusBadGateway, 1502,
			fmt.Sprintf("Microsoft token: %s: %s", errResp.Error, errResp.ErrorDescription))
		return
	}

	// Microsoft sometimes rotates the refresh-token; persist if so.
	if tok.RefreshToken != "" && tok.RefreshToken != refresh {
		enc, err := common.EncryptGrant(tok.RefreshToken)
		if err == nil {
			_ = common.DB.Model(&models.MicrosoftGrant{}).
				Where("user_sub = ?", userID).
				Updates(map[string]any{"refresh_token_encrypted": enc}).Error
		}
	}
	now := time.Now().UTC()
	_ = common.DB.Model(&models.MicrosoftGrant{}).
		Where("user_sub = ?", userID).
		Updates(map[string]any{"last_used_at": &now}).Error

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"access_token": tok.AccessToken,
			"expires_in":   tok.ExpiresIn,
			"scope":        tok.Scope,
			"token_type":   tok.TokenType,
		},
	})
}

// ── Microsoft OAuth wire types ────────────────────────────────────

type msDeviceCodeResp struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type msTokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type msTokenErr struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type msMeResp struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	DisplayName       string `json:"displayName"`
}

// exchangeMicrosoftDeviceCode polls Microsoft's token endpoint once
// with the device_code. Returns (success, errResp, transport_err)
// where errResp is non-nil for normal polling outcomes
// (authorization_pending, etc.) and transport_err for actual
// failures (network down).
func exchangeMicrosoftDeviceCode(ctx context.Context, deviceCode string) (*msTokenResp, *msTokenErr, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {msPublicClientID},
		"device_code": {deviceCode},
	}
	return doMicrosoftTokenCall(ctx, form)
}

// refreshMicrosoftToken exchanges a stored refresh-token for a fresh
// access (+ optionally rotated refresh) token.
func refreshMicrosoftToken(ctx context.Context, refresh, scope string) (*msTokenResp, *msTokenErr, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {msPublicClientID},
		"refresh_token": {refresh},
		"scope":         {scope},
	}
	return doMicrosoftTokenCall(ctx, form)
}

func doMicrosoftTokenCall(ctx context.Context, form url.Values) (*msTokenResp, *msTokenErr, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", msTokenURL,
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("microsoft token transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var er msTokenErr
		if err := json.Unmarshal(body, &er); err != nil || er.Error == "" {
			return nil, nil, fmt.Errorf("microsoft token %d: %s",
				resp.StatusCode, truncateBytes(body, 300))
		}
		return nil, &er, nil
	}
	var t msTokenResp
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, nil, fmt.Errorf("microsoft token parse: %w", err)
	}
	return &t, nil, nil
}

func fetchMicrosoftMe(ctx context.Context, accessToken string) (*msMeResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", msGraphMe, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("graph /me %d: %s", resp.StatusCode, truncateBytes(body, 200))
	}
	var me msMeResp
	if err := json.Unmarshal(body, &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// truncateBytes clips a byte slice for inclusion in an error message
// without writing arbitrarily large bodies to the user. Separate from
// the string-based truncate() in me_today.go.
func truncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
