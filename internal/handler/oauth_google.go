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
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

// Google 3rd-party sign-in. The frontend at lum.id/auth/login
// redirects the browser to accounts.google.com with client_id +
// redirect_uri=https://lum.id/auth/callback. Google bounces back with
// ?code=...&state=...; the /auth/callback page POSTs that payload
// here. We exchange + resolve the Google profile, upsert the user in
// lumid_identity.users + tbl_user (dual-write during shadow), and
// issue a session cookie on .lum.id.
//
// For this to work in a browser:
//   1. GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET env must be set on
//      lumid-identity (via compose env).
//   2. https://lum.id/auth/callback must be on the Google OAuth
//      client's "Authorized redirect URIs" — external action.

type googleLoginReq struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	RedirectURI string `json:"redirect_uri"` // optional; sanity check
}

type googleTokenResp struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type googleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// POST /api/v1/oauth/google/login — exchange code + sign user in.
func GoogleLoginHandler(c *gin.Context) {
	var req googleLoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if req.Code == "" {
		fail(c, http.StatusBadRequest, 1001, "code required")
		return
	}

	cfg := config.G.OAuth.Google
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		fail(c, http.StatusServiceUnavailable, 1500,
			"Google OAuth not configured on lumid-identity (GOOGLE_CLIENT_ID/SECRET env)")
		return
	}
	redirectURI := cfg.RedirectURI
	if redirectURI == "" {
		redirectURI = "https://lum.id/auth/callback"
	}

	// Step 1 — exchange code for tokens.
	tok, err := exchangeGoogleCode(c.Request.Context(), req.Code, redirectURI, cfg.ClientID, cfg.ClientSecret)
	if err != nil {
		fail(c, http.StatusBadRequest, 1401, "google exchange: "+err.Error())
		return
	}
	// Step 2 — fetch userinfo.
	info, err := fetchGoogleUserInfo(c.Request.Context(), tok.AccessToken)
	if err != nil {
		fail(c, http.StatusBadRequest, 1402, "google userinfo: "+err.Error())
		return
	}
	if info.Email == "" {
		fail(c, http.StatusBadRequest, 1403, "google profile missing email")
		return
	}

	email := strings.ToLower(info.Email)

	// Step 3 — upsert user.
	var u models.User
	err = common.DB.Where("email = ?", email).First(&u).Error
	if err == gorm.ErrRecordNotFound {
		u = models.User{
			ID:            uuid.NewString(),
			Email:         email,
			EmailVerified: info.VerifiedEmail,
			Name:          info.Name,
			AvatarURL:     info.Picture,
			Role:          "user",
			Status:        "active",
			PasswordHash:  "", // OAuth-only — user can add a password later
		}
		if cerr := common.DB.Create(&u).Error; cerr != nil {
			fail(c, http.StatusInternalServerError, 1500, "create user: "+cerr.Error())
			return
		}
		// Mirror to LQA so lumid.market pages keep recognising the user
		// during the shadow window. Best-effort — we don't block login.
		if config.G.Legacy.Enabled && common.LegacyDB != nil {
			common.LegacyDB.Exec(`
				INSERT IGNORE INTO tbl_user (email, username, password_hash, role, status, avatar, create_time, update_time)
				VALUES (?, ?, '', 'user', 'active', ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())
			`, email, info.Name, info.Picture)
		}
	} else if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "user lookup: "+err.Error())
		return
	}

	// Step 4 — link Google identity if not already.
	var existing models.Identity
	linkErr := common.DB.Where("provider = ? AND provider_sub = ?", "google", info.ID).First(&existing).Error
	if linkErr == gorm.ErrRecordNotFound {
		common.DB.Create(&models.Identity{UserID: u.ID, Provider: "google", ProviderSub: info.ID})
	}

	// Step 5 — issue session.
	scopes := []string{"lumid:profile:read"}
	if u.Role == "admin" {
		scopes = []string{"*"}
	}
	sessionTok, jti, exp, err := common.IssueJWT(u.ID, u.Email, u.Role, scopes)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "sign jwt: "+err.Error())
		return
	}
	common.DB.Create(&models.Session{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		JTI:       jti,
		ClientID:  "lumid-web",
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
		ExpiresAt: exp,
	})
	setSessionCookie(c, sessionTok, exp)

	ok(c, "login ok", loginResp{
		Token:     sessionTok,
		ExpiresAt: exp,
		User: userOut{
			ID:    u.ID,
			Email: u.Email,
			Name:  u.Name,
			Role:  u.Role,
		},
	})
}

func exchangeGoogleCode(ctx context.Context, code, redirectURI, clientID, clientSecret string) (*googleTokenResp, error) {
	form := url.Values{
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://oauth2.googleapis.com/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var out googleTokenResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func fetchGoogleUserInfo(ctx context.Context, accessToken string) (*googleUserInfo, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://www.googleapis.com/oauth2/v2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var out googleUserInfo
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
