package handler

// Claude Code quota status — super_admin view across all org accounts.
//
// GET /api/v1/admin/claude-quota  (RequireSuperAdmin)
//
// Reads every row in claude_quota_tokens (admin-managed, email-keyed),
// decrypts each token, and calls api.anthropic.com/v1/messages with a
// 1-token probe to read the unified rate-limit headers:
//   anthropic-ratelimit-unified-5h-utilization  (0-1 float)
//   anthropic-ratelimit-unified-7d-utilization
//   anthropic-ratelimit-unified-5h-reset         (Unix seconds)
//   anthropic-ratelimit-unified-7d-reset
//   anthropic-ratelimit-unified-5h-status        (allowed | throttled | exceeded)
//   anthropic-ratelimit-unified-7d-status
//
// Results are cached in claude_quota_snapshots; stale (>5 min) snapshots
// trigger a fresh probe. api.anthropic.com is not Cloudflare-gated, so this
// works from K8s pods.
//
// DELETE /api/v1/admin/claude-token/:email  (RequireSuperAdmin)
// Removes a Claude token and its snapshots for the given email.

// POST /api/v1/internal/claude-quota/report  (RequireBridge)
// Legacy bridge path — kept for any external push reporter.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	claudeOAuthTokenURL = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthClientID = "https://claude.ai/oauth/claude-code-client-metadata"
)

// tryRefreshToken attempts to exchange a stored refresh token for a new access
// token. On success it updates the DB row and returns the new access token.
func tryRefreshToken(row *models.ClaudeQuotaToken) (string, error) {
	if row.RefreshTokenEncrypted == "" {
		return "", fmt.Errorf("no refresh token stored")
	}
	refreshTok, err := common.DecryptGrant(row.RefreshTokenEncrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt refresh token: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshTok,
		"client_id":     claudeOAuthClientID,
	})
	req, err := http.NewRequest(http.MethodPost, claudeOAuthTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	cl := &http.Client{Timeout: quotaFetchTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("token refresh network error: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &errResp)
		if errResp.Error != "" {
			return "", fmt.Errorf("token refresh failed: %s — %s", errResp.Error, errResp.Desc)
		}
		return "", fmt.Errorf("token refresh HTTP %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("token refresh: invalid response body")
	}

	// Persist updated access token (and new refresh token if rotated).
	newEnc, err := common.EncryptGrant(tok.AccessToken)
	if err != nil {
		return tok.AccessToken, fmt.Errorf("encrypt new token: %w", err)
	}
	updates := map[string]interface{}{"value_encrypted": newEnc}
	if tok.RefreshToken != "" && tok.RefreshToken != refreshTok {
		newRefEnc, _ := common.EncryptGrant(tok.RefreshToken)
		if newRefEnc != "" {
			updates["refresh_token_encrypted"] = newRefEnc
		}
	}
	common.DB.Model(row).Updates(updates)
	return tok.AccessToken, nil
}

const (
	quotaCacheTTL     = 5 * time.Minute
	quotaFetchTimeout = 20 * time.Second
	// Minimal probe model — cheapest, fastest; we only need the response headers.
	quotaProbeModel = "claude-haiku-4-5-20251001"
)

// fetchClaudeUsage calls api.anthropic.com/v1/messages with a 1-token probe
// and reads the unified rate-limit response headers. Works from any server
// (no Cloudflare on api.anthropic.com). Returns a partially-filled snapshot
// (Email + Ts are set by the caller).
func fetchClaudeUsage(token string) (*models.ClaudeQuotaSnapshot, error) {
	probeBody := []byte(`{"model":"` + quotaProbeModel + `","max_tokens":1,"messages":[{"role":"user","content":"quota"}]}`)
	req, err := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(probeBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	cl := &http.Client{Timeout: quotaFetchTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api.anthropic.com unreachable: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("token invalid or unauthorized (HTTP %d)", resp.StatusCode)
	}
	// 200=ok, 429=rate-limited (headers still present), 400=keyed but bad body — all usable.
	if resp.StatusCode != 200 && resp.StatusCode != 429 && resp.StatusCode != 400 {
		return nil, fmt.Errorf("unexpected HTTP %d from Anthropic API", resp.StatusCode)
	}

	h := resp.Header
	get := func(k string) string { return h.Get(k) }

	snap := &models.ClaudeQuotaSnapshot{}

	if u, err := strconv.ParseFloat(get("anthropic-ratelimit-unified-5h-utilization"), 64); err == nil {
		snap.FiveHourPct = u * 100
	}
	if u, err := strconv.ParseFloat(get("anthropic-ratelimit-unified-7d-utilization"), 64); err == nil {
		snap.SevenDayPct = u * 100
	}
	if ts, err := strconv.ParseInt(get("anthropic-ratelimit-unified-5h-reset"), 10, 64); err == nil {
		snap.FiveHourReset = time.Unix(ts, 0)
	}
	if ts, err := strconv.ParseInt(get("anthropic-ratelimit-unified-7d-reset"), 10, 64); err == nil {
		snap.SevenDayReset = time.Unix(ts, 0)
	}

	fiveStatus := get("anthropic-ratelimit-unified-5h-status")
	sevenStatus := get("anthropic-ratelimit-unified-7d-status")

	switch {
	case fiveStatus == "exceeded" || sevenStatus == "exceeded":
		snap.Severity = "critical"
	case fiveStatus == "throttled" || sevenStatus == "throttled" ||
		snap.FiveHourPct >= 85 || snap.SevenDayPct >= 85:
		snap.Severity = "warning"
	default:
		snap.Severity = "normal"
	}

	// Build a limits array in the shape the UI expects so the badge row renders.
	type limitEntry struct {
		Kind     string `json:"kind"`
		Percent  int    `json:"percent"`
		IsActive bool   `json:"is_active"`
		Severity string `json:"severity"`
		ResetsAt string `json:"resets_at"`
	}
	limits := []limitEntry{
		{
			Kind:     "five_hour",
			Percent:  int(snap.FiveHourPct),
			IsActive: true,
			Severity: severityFromStatus(fiveStatus, snap.FiveHourPct),
			ResetsAt: snap.FiveHourReset.Format(time.RFC3339),
		},
		{
			Kind:     "seven_day",
			Percent:  int(snap.SevenDayPct),
			IsActive: true,
			Severity: severityFromStatus(sevenStatus, snap.SevenDayPct),
			ResetsAt: snap.SevenDayReset.Format(time.RFC3339),
		},
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"limits": limits,
		"meta": map[string]string{
			"five_hour_status":         fiveStatus,
			"seven_day_status":         sevenStatus,
			"representative_claim":     get("anthropic-ratelimit-unified-representative-claim"),
			"fallback_percentage":      get("anthropic-ratelimit-unified-fallback-percentage"),
			"source":                   "anthropic_api_headers",
		},
	})
	snap.Raw = string(raw)
	return snap, nil
}

func severityFromStatus(status string, pct float64) string {
	switch status {
	case "exceeded":
		return "critical"
	case "throttled":
		return "warning"
	}
	if pct >= 85 {
		return "warning"
	}
	return "normal"
}

// refreshSnapshot fetches live quota and upserts a ClaudeQuotaSnapshot row.
// If the probe returns 401 and the row has a refresh token, it auto-refreshes
// the access token and retries once.
func refreshSnapshot(row *models.ClaudeQuotaToken, token string) (*models.ClaudeQuotaSnapshot, error) {
	snap, err := fetchClaudeUsage(token)
	if err != nil {
		// On auth failure, try to refresh if we have a refresh token.
		if strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "HTTP 403") {
			newTok, refreshErr := tryRefreshToken(row)
			if refreshErr != nil {
				return nil, fmt.Errorf("%w (refresh also failed: %s)", err, refreshErr.Error())
			}
			snap, err = fetchClaudeUsage(newTok)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	snap.Email = row.Email
	if err := common.DB.Create(snap).Error; err != nil {
		return nil, fmt.Errorf("save snapshot: %w", err)
	}
	return snap, nil
}

type quotaResult struct {
	Email         string          `json:"email"`
	Ts            time.Time       `json:"ts"`
	FiveHourPct   float64         `json:"five_hour_pct"`
	SevenDayPct   float64         `json:"seven_day_pct"`
	FiveHourReset time.Time       `json:"five_hour_reset"`
	SevenDayReset time.Time       `json:"seven_day_reset"`
	Severity      string          `json:"severity"`
	Stale         bool            `json:"stale"`
	Error         string          `json:"error,omitempty"`
	Limits        json.RawMessage `json:"limits,omitempty"`
}

func fillFromSnap(res *quotaResult, snap *models.ClaudeQuotaSnapshot) {
	res.Ts = snap.Ts
	res.FiveHourPct = snap.FiveHourPct
	res.SevenDayPct = snap.SevenDayPct
	res.FiveHourReset = snap.FiveHourReset
	res.SevenDayReset = snap.SevenDayReset
	res.Severity = snap.Severity
	if snap.Raw != "" {
		var raw map[string]json.RawMessage
		if json.Unmarshal([]byte(snap.Raw), &raw) == nil {
			res.Limits = raw["limits"]
		}
	}
}

// GET /api/v1/admin/claude-quota  (RequireSuperAdmin)
func AdminClaudeQuota(c *gin.Context) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Order("updated_at DESC").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query tokens: "+err.Error())
		return
	}

	results := make([]quotaResult, len(rows))
	var wg sync.WaitGroup
	for i, row := range rows {
		wg.Add(1)
		go func(i int, row models.ClaudeQuotaToken) {
			defer wg.Done()
			res := quotaResult{Email: row.Email}

			var snap models.ClaudeQuotaSnapshot
			snapErr := common.DB.
				Where("email = ?", row.Email).
				Order("ts DESC").
				First(&snap).Error
			cacheHit := snapErr == nil && time.Since(snap.Ts) < quotaCacheTTL

			if cacheHit {
				fillFromSnap(&res, &snap)
				results[i] = res
				return
			}

			token, err := common.DecryptGrant(row.ValueEncrypted)
			if err != nil {
				res.Error = "decrypt: " + err.Error()
				res.Stale = true
				if snapErr == nil {
					fillFromSnap(&res, &snap)
				}
				results[i] = res
				return
			}
			fresh, err := refreshSnapshot(&row, token)
			if err != nil {
				res.Stale = true
				res.Error = err.Error()
				if snapErr == nil {
					fillFromSnap(&res, &snap)
				}
				results[i] = res
				return
			}
			fillFromSnap(&res, fresh)
			results[i] = res
		}(i, row)
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"accounts": results,
			"count":    len(rows),
		},
	})
}

// POST /api/v1/admin/claude-token  (RequireAdmin)
func AdminClaudeTokenAdd(c *gin.Context) {
	var body struct {
		Email        string `json:"email"         binding:"required"`
		Token        string `json:"token"         binding:"required"`
		RefreshToken string `json:"refresh_token"` // optional; enables auto-refresh on 401
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	token := strings.TrimSpace(body.Token)
	email := strings.TrimSpace(strings.ToLower(body.Email))
	refreshTok := strings.TrimSpace(body.RefreshToken)

	// Verify against Anthropic before storing.
	valid, status, reason := verifyAnthropic(token)
	if !valid {
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "invalid",
			"data": gin.H{
				"email": email, "valid": false, "stored": false,
				"upstream_status": status, "reason": reason,
			},
		})
		return
	}

	// Encrypt and upsert into claude_quota_tokens (email is PK).
	enc, err := common.EncryptGrant(token)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
		return
	}
	row := models.ClaudeQuotaToken{Email: email, ValueEncrypted: enc}
	if refreshTok != "" {
		refEnc, err := common.EncryptGrant(refreshTok)
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "encrypt refresh: "+err.Error())
			return
		}
		row.RefreshTokenEncrypted = refEnc
	}
	if err := common.DB.Save(&row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"email": email, "valid": true, "stored": true,
			"has_refresh_token": refreshTok != "",
			"upstream_status":   status, "reason": reason,
		},
	})
}

// AdminClaudeTokenDelete removes a tracked Claude token (and its snapshots) by email.
// DELETE /api/v1/admin/claude-token/:email  (RequireSuperAdmin)
func AdminClaudeTokenDelete(c *gin.Context) {
	email := strings.TrimSpace(strings.ToLower(c.Param("email")))
	if email == "" {
		fail(c, http.StatusBadRequest, 1400, "email required")
		return
	}
	if err := common.DB.Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete token: "+err.Error())
		return
	}
	// Best-effort cleanup of historical snapshots.
	common.DB.Where("email = ?", email).Delete(&models.ClaudeQuotaSnapshot{})
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok"})
}

// reportBody is the wire shape for the legacy bridge path.
type claudeQuotaReportBody struct {
	Email         string  `json:"email"          binding:"required"`
	FiveHourPct   float64 `json:"five_hour_pct"`
	SevenDayPct   float64 `json:"seven_day_pct"`
	FiveHourReset string  `json:"five_hour_reset"`
	SevenDayReset string  `json:"seven_day_reset"`
	Severity      string  `json:"severity"`
	Raw           string  `json:"raw"`
}

// POST /api/v1/internal/claude-quota/report  (RequireBridge)
func InternalClaudeQuotaReport(c *gin.Context) {
	var body claudeQuotaReportBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Severity == "" {
		body.Severity = "normal"
	}
	snap := models.ClaudeQuotaSnapshot{
		Email:       body.Email,
		FiveHourPct: body.FiveHourPct,
		SevenDayPct: body.SevenDayPct,
		Severity:    body.Severity,
		Raw:         body.Raw,
	}
	if t, err := time.Parse(time.RFC3339, body.FiveHourReset); err == nil {
		snap.FiveHourReset = t
	}
	if t, err := time.Parse(time.RFC3339, body.SevenDayReset); err == nil {
		snap.SevenDayReset = t
	}
	if err := common.DB.Create(&snap).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "insert snapshot: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok"})
}
