package handler

// /api/v1/me/apps/:app/secrets/claude-verify — verify a pasted Claude
// credential against the live Anthropic API, and (only if it authenticates)
// store it encrypted as an app_secret. Backs the Studio "Connect Claude"
// pop-out login window: the browser can't complete Anthropic's OAuth
// (no third-party client), so the user runs `claude setup-token` (or grabs an
// API key), pastes the result here, and we prove it works before saving —
// which is exactly what would otherwise fail silently at cycle time.
//
// Auth verdict (a minimal /v1/messages call):
//   200/400/429 -> authenticated (valid; 400=bad body but keyed, 429=rate-limited)
//   401/403     -> invalid credential
// Token shape decides the auth header:
//   sk-ant-oat*  -> Authorization: Bearer + anthropic-beta: oauth-2025-04-20  (subscription)
//   otherwise    -> x-api-key                                                  (API key)

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const claudeDefaultKey = common.ClaudeOAuthSecretKey

type claudeVerifyBody struct {
	Value string `json:"value" binding:"required"`
	Key   string `json:"key"`  // optional; defaults to CLAUDE_CODE_OAUTH_TOKEN (or ANTHROPIC_API_KEY)
	Save  *bool  `json:"save"` // optional; default true — store when valid
}

// verifyAnthropic makes a minimal live call and returns (valid, httpStatus, reason).
func verifyAnthropic(token string) (bool, int, string) {
	reqBody := []byte(`{"model":"claude-sonnet-4-5-20250929","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(reqBody))
	if err != nil {
		return false, 0, "request build failed"
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	if strings.HasPrefix(token, "sk-ant-oat") {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	} else {
		req.Header.Set("x-api-key", token)
	}
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return false, 0, "network error reaching api.anthropic.com: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	switch {
	case resp.StatusCode == 200 || resp.StatusCode == 400 || resp.StatusCode == 429:
		// Authenticated (400 = keyed but bad body; 429 = keyed but rate-limited).
		return true, resp.StatusCode, "authenticated"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return false, resp.StatusCode, "invalid or unauthorized credential"
	default:
		// Surface upstream error text (truncated) for other statuses.
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		msg := e.Error.Message
		if msg == "" {
			msg = "unexpected status"
		}
		return false, resp.StatusCode, msg
	}
}

// MeSecretClaudeVerify — POST /api/v1/me/apps/:app/secrets/claude-verify
func MeSecretClaudeVerify(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	var body claudeVerifyBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	token := strings.TrimSpace(body.Value)
	if token == "" {
		fail(c, http.StatusBadRequest, 1400, "value required")
		return
	}
	key := body.Key
	if key == "" {
		key = claudeDefaultKey
	}
	if !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid secret key")
		return
	}

	valid, status, reason := verifyAnthropic(token)
	stored := false
	if valid && (body.Save == nil || *body.Save) {
		enc, err := common.EncryptGrant(token)
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
			return
		}
		now := time.Now().UTC()
		sec := models.AppSecret{
			UserSub: userID, AppSlug: app, Key: key,
			ValueEncrypted: enc, CreatedAt: now, UpdatedAt: now,
		}
		if err := common.DB.Save(&sec).Error; err != nil {
			fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
			return
		}
		stored = true
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "verified",
		"data": gin.H{
			"app": app, "key": key,
			"valid": valid, "stored": stored,
			"upstream_status": status, "reason": reason,
		},
	})
}
