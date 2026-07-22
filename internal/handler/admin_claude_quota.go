package handler

// Claude Code quota status — super_admin view across all org accounts.
//
// GET /api/v1/admin/claude-quota  (RequireSuperAdmin)
//
// Reads every app_secrets row whose key matches CLAUDE_CODE_OAUTH_TOKEN
// (or ANTHROPIC_API_KEY for sk-ant-api03 keys — they don't have quota),
// decrypts the token, and calls https://claude.ai/api/oauth/usage for
// each. Results are cached in claude_quota_snapshots; the endpoint
// returns fresh data when the newest snapshot for an account is >5 min
// old, otherwise returns cached.
//
// POST /api/v1/internal/claude-quota/report  (RequireBridge)
// Legacy bridge path — kept for any external cron. Upserts a snapshot
// directly without fetching from claude.ai.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	claudeUsageURL    = "https://claude.ai/api/oauth/usage"
	quotaCacheTTL     = 5 * time.Minute
	quotaFetchTimeout = 10 * time.Second
)

// fetchClaudeUsage calls the claude.ai usage endpoint with the given
// OAuth token and returns the raw JSON body.
func fetchClaudeUsage(token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, claudeUsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	cl := &http.Client{Timeout: quotaFetchTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claude.ai returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

type claudeUsagePayload struct {
	FiveHour *struct {
		Utilization float64 `json:"utilization"`
		ResetsAt    string  `json:"resets_at"`
	} `json:"five_hour"`
	SevenDay *struct {
		Utilization float64 `json:"utilization"`
		ResetsAt    string  `json:"resets_at"`
	} `json:"seven_day"`
	Limits []struct {
		Severity string `json:"severity"`
		IsActive bool   `json:"is_active"`
		ResetsAt string `json:"resets_at"`
		Percent  int    `json:"percent"`
		Kind     string `json:"kind"`
	} `json:"limits"`
}

func parseSeverity(p *claudeUsagePayload) string {
	for _, l := range p.Limits {
		if l.Severity == "critical" {
			return "critical"
		}
	}
	for _, l := range p.Limits {
		if l.Severity == "warning" {
			return "warning"
		}
	}
	return "normal"
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

// refreshSnapshot fetches live quota for a token+email pair and upserts
// a ClaudeQuotaSnapshot row. Returns the fresh snapshot or an error.
func refreshSnapshot(email, token string) (*models.ClaudeQuotaSnapshot, error) {
	raw, err := fetchClaudeUsage(token)
	if err != nil {
		return nil, err
	}
	var p claudeUsagePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse usage: %w", err)
	}
	snap := models.ClaudeQuotaSnapshot{
		Email:    email,
		Severity: parseSeverity(&p),
		Raw:      string(raw),
	}
	if p.FiveHour != nil {
		snap.FiveHourPct = p.FiveHour.Utilization
		snap.FiveHourReset = parseTime(p.FiveHour.ResetsAt)
	}
	if p.SevenDay != nil {
		snap.SevenDayPct = p.SevenDay.Utilization
		snap.SevenDayReset = parseTime(p.SevenDay.ResetsAt)
	}
	if err := common.DB.Create(&snap).Error; err != nil {
		return nil, fmt.Errorf("save snapshot: %w", err)
	}
	return &snap, nil
}

// GET /api/v1/admin/claude-quota  (RequireSuperAdmin)
func AdminClaudeQuota(c *gin.Context) {
	// 1. Find all entries in claude_quota_tokens (admin-managed, email-keyed).
	//    This table is written exclusively by AdminClaudeTokenAdd and is
	//    intentionally separate from app_secrets so lumid-only users who
	//    connect via Studio settings don't pollute the org-wide quota view.
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Order("updated_at DESC").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query tokens: "+err.Error())
		return
	}

	// 2. For each user, return cached snapshot if fresh; otherwise refresh.
	type result struct {
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

	results := make([]result, len(rows))
	var wg sync.WaitGroup
	for i, row := range rows {
		wg.Add(1)
		go func(i int, row models.ClaudeQuotaToken) {
			defer wg.Done()
			res := result{Email: row.Email}

			// Check for a recent cached snapshot.
			var snap models.ClaudeQuotaSnapshot
			cacheHit := common.DB.
				Where("email = ?", row.Email).
				Order("ts DESC").
				First(&snap).Error == nil &&
				time.Since(snap.Ts) < quotaCacheTTL

			if cacheHit {
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
				results[i] = res
				return
			}

			// Decrypt token and fetch fresh.
			token, err := common.DecryptGrant(row.ValueEncrypted)
			if err != nil {
				res.Error = "decrypt: " + err.Error()
				res.Stale = true
				results[i] = res
				return
			}
			fresh, err := refreshSnapshot(row.Email, token)
			if err != nil {
				// Return stale cached data if available, with error annotation.
				res.Stale = true
				res.Error = err.Error()
				if cacheHit {
					res.Ts = snap.Ts
					res.FiveHourPct = snap.FiveHourPct
					res.SevenDayPct = snap.SevenDayPct
					res.Severity = snap.Severity
				}
				results[i] = res
				return
			}
			res.Ts = fresh.Ts
			res.FiveHourPct = fresh.FiveHourPct
			res.SevenDayPct = fresh.SevenDayPct
			res.FiveHourReset = fresh.FiveHourReset
			res.SevenDayReset = fresh.SevenDayReset
			res.Severity = fresh.Severity
			if fresh.Raw != "" {
				var raw map[string]json.RawMessage
				if json.Unmarshal([]byte(fresh.Raw), &raw) == nil {
					res.Limits = raw["limits"]
				}
			}
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

// POST /api/v1/admin/claude-token  (RequireSuperAdmin)
//
// Stores a Claude OAuth token for any email — no lumid account required.
// Uses the claude_quota_tokens table (email-keyed) so org members who
// have a Claude Code subscription but no lumid account can be tracked,
// and lumid-only users don't bleed into the org quota view.
func AdminClaudeTokenAdd(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required"`
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	token := strings.TrimSpace(body.Token)
	email := strings.TrimSpace(strings.ToLower(body.Email))

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
	if err := common.DB.Save(&row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"email": email, "valid": true, "stored": true,
			"upstream_status": status, "reason": reason,
		},
	})
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
