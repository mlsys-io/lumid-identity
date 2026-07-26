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
	"crypto/sha256"
	base64Stdlib "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	claudeOAuthTokenURL = "https://platform.claude.com/v1/oauth/token"
	// UUID-format client_id expected by platform.claude.com/v1/oauth/token.
	// The metadata document URL (https://claude.ai/oauth/claude-code-client-metadata)
	// is used for initial authorization but NOT for token refresh — the endpoint
	// validates the client_id as a UUID and rejects URLs with "Invalid request format".
	claudeOAuthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	// Scopes required by Claude Code — must be present in the refresh body.
	claudeOAuthScopes = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
)

// refreshMutexes serialises token refresh per email. Anthropic rotates the
// refresh token on every exchange, so two concurrent refreshes with the same
// refresh token (e.g. a dashboard probe racing a pool lease) would invalidate
// one side's rotated credentials.
var refreshMutexes sync.Map // email -> *sync.Mutex

func refreshMutex(email string) *sync.Mutex {
	m, _ := refreshMutexes.LoadOrStore(email, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// withEmailLock runs fn while holding a MySQL named lock scoped to the email.
// The in-process refreshMutex only serialises within ONE pod; identity runs
// 2 replicas, and two pods exchanging the same (single-use, rotated-on-every-
// exchange) refresh token concurrently trips Anthropic's rotation-reuse
// detection, which revokes the whole token family. GET_LOCK is session-scoped,
// so acquire/callback/release are pinned to one pooled connection.
func withEmailLock(email string, fn func() error) error {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	name := "cqr:" + fmt.Sprintf("%x", sum)[:32] // MySQL lock names cap at 64 chars
	return common.DB.Connection(func(tx *gorm.DB) error {
		var got int
		if err := tx.Raw("SELECT GET_LOCK(?, 20)", name).Scan(&got).Error; err != nil {
			return fmt.Errorf("acquire refresh lock: %w", err)
		}
		if got != 1 {
			return fmt.Errorf("refresh lock busy for %s", email)
		}
		defer tx.Exec("DO RELEASE_LOCK(?)", name)
		return fn()
	})
}

// tryRefreshToken attempts to exchange a stored refresh token for a new access
// token. On success it updates the DB row and returns the new access token.
// Serialised per email in-process AND across replicas (withEmailLock); if
// another refresher rotated within the last 30s the already-rotated access
// token is returned without a second exchange. Rows quarantined by a prior
// invalid_grant are never re-presented to Anthropic — re-add clears them.
func tryRefreshToken(row *models.ClaudeQuotaToken) (string, error) {
	mu := refreshMutex(row.Email)
	mu.Lock()
	defer mu.Unlock()

	var tok string
	err := withEmailLock(row.Email, func() error {
		var innerErr error
		tok, innerErr = refreshTokenLocked(row)
		return innerErr
	})
	return tok, err
}

func refreshTokenLocked(row *models.ClaudeQuotaToken) (string, error) {
	// Re-read: another refresher (this pod or the other replica) may have
	// rotated while we waited on the locks.
	var fresh models.ClaudeQuotaToken
	if err := common.DB.Where("email = ?", row.Email).First(&fresh).Error; err == nil {
		if time.Since(fresh.UpdatedAt) < 30*time.Second && fresh.ValueEncrypted != row.ValueEncrypted && fresh.RevokedAt == nil {
			if tok, err := common.DecryptGrant(fresh.ValueEncrypted); err == nil {
				*row = fresh
				return tok, nil
			}
		}
		*row = fresh
	}

	if row.RevokedAt != nil {
		return "", fmt.Errorf("token family revoked (%s) — re-add the account with a fresh `claude auth login`", row.RevokeReason)
	}
	if row.RefreshTokenEncrypted == "" {
		return "", fmt.Errorf("no refresh token stored")
	}
	refreshTok, err := common.DecryptGrant(row.RefreshTokenEncrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt refresh token: %w", err)
	}

	// Anthropic's token endpoint accepts JSON (not form-encoded).
	// Must include client_id (UUID, not metadata URL) and scope.
	bodyMap := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshTok,
		"client_id":     claudeOAuthClientID,
		"scope":         claudeOAuthScopes,
	}
	bodyJSON, _ := json.Marshal(bodyMap)
	req, err := http.NewRequest(http.MethodPost, claudeOAuthTokenURL, bytes.NewReader(bodyJSON))
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
		if errResp.Error == "invalid_grant" {
			// The family is gone (typically rotation-reuse detection after the
			// owner's own Claude Code refreshed a shared credential copy).
			// Quarantine the row so no path re-presents the revoked token.
			reason := strings.TrimSpace(errResp.Error + " — " + errResp.Desc)
			now := time.Now()
			common.DB.Model(row).Updates(map[string]interface{}{
				"revoked_at":    now,
				"revoke_reason": reason,
			})
			row.RevokedAt = &now
			row.RevokeReason = reason
			log.Printf("claude-refresh: %s: QUARANTINED (%s) — re-add with a fresh `claude auth login` required", row.Email, reason)
			return "", fmt.Errorf("token refresh failed: %s (account quarantined — re-add required)", reason)
		}
		if errResp.Error != "" {
			return "", fmt.Errorf("token refresh failed: %s — %s", errResp.Error, errResp.Desc)
		}
		return "", fmt.Errorf("token refresh HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
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
	updates := map[string]interface{}{
		"value_encrypted": newEnc,
		// A successful exchange proves the family is alive — clear any stale
		// quarantine (e.g. a row re-added out-of-band).
		"revoked_at":    nil,
		"revoke_reason": "",
	}
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
			"five_hour_status":     fiveStatus,
			"seven_day_status":     sevenStatus,
			"representative_claim": get("anthropic-ratelimit-unified-representative-claim"),
			"fallback_percentage":  get("anthropic-ratelimit-unified-fallback-percentage"),
			"source":               "anthropic_api_headers",
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
	// Quarantine state — the token family was revoked (invalid_grant);
	// the account needs a re-add with a fresh `claude auth login`.
	Revoked      bool   `json:"revoked,omitempty"`
	RevokeReason string `json:"revoke_reason,omitempty"`
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

			// Quarantined family: don't probe (the access token died with the
			// refresh token) — report the state and the fix explicitly.
			if row.RevokedAt != nil {
				res.Revoked = true
				res.RevokeReason = row.RevokeReason
				res.Stale = true
				res.Error = "token family revoked — re-add with a fresh `claude auth login`"
				if snapErr == nil {
					fillFromSnap(&res, &snap)
				}
				results[i] = res
				return
			}

			// A snapshot whose 5h/7d reset moment has already passed reports a
			// PRE-reset utilization that Anthropic has since rolled toward 0.
			// Serving it is what produced the "100% ↺now" that looked stuck:
			// the reset clock says "now" while the cached % is still the old
			// high value. Treat a passed-reset snapshot as a miss so we re-probe
			// the true post-reset number (the fresh snapshot gets a future
			// reset and caches normally again).
			now := time.Now()
			resetPassed := (!snap.FiveHourReset.IsZero() && now.After(snap.FiveHourReset)) ||
				(!snap.SevenDayReset.IsZero() && now.After(snap.SevenDayReset))
			cacheHit := snapErr == nil && time.Since(snap.Ts) < quotaCacheTTL && !resetPassed

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
	// Upsert: INSERT ... ON DUPLICATE KEY UPDATE only the token columns.
	// DB.Save() with a string PK includes created_at=zero in the UPDATE clause
	// which MySQL strict mode rejects with Error 1292. Explicit DoUpdates avoids it.
	// A re-add is the recovery path for a revoked family — clear the quarantine.
	if err := common.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.AssignmentColumns([]string{"value_encrypted", "refresh_token_encrypted", "updated_at", "revoked_at", "revoke_reason"}),
	}).Create(&row).Error; err != nil {
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

// InternalClaudeTokenLease hands the claude-proxy service the healthiest
// pooled account's decrypted access token.
//
// POST /api/v1/internal/claude-token/lease  (RequireBridge)
// Body (all optional): {"prefer_email": "...", "exclude": ["...", ...]}
//
// Selection: prefer_email if usable, else lowest 5h utilization among accounts
// whose latest snapshot isn't critical (5h exceeded). Accounts with a stale
// (>5 min) or missing snapshot are probed via refreshSnapshot — which also
// auto-refreshes an expired access token. Unusable accounts are skipped.
func InternalClaudeTokenLease(c *gin.Context) {
	var body struct {
		PreferEmail string   `json:"prefer_email"`
		Exclude     []string `json:"exclude"`
	}
	_ = c.ShouldBindJSON(&body) // empty body is fine

	excluded := map[string]bool{}
	for _, e := range body.Exclude {
		excluded[strings.ToLower(strings.TrimSpace(e))] = true
	}
	prefer := strings.ToLower(strings.TrimSpace(body.PreferEmail))

	var rows []models.ClaudeQuotaToken
	if err := common.DB.Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query tokens: "+err.Error())
		return
	}

	type cand struct {
		row  models.ClaudeQuotaToken
		snap *models.ClaudeQuotaSnapshot
	}
	var cands []cand
	for _, row := range rows {
		if excluded[row.Email] {
			continue
		}
		// Quarantined family — its access token dies with the refresh token,
		// so it can't serve proxy traffic. Skip until re-added.
		if row.RevokedAt != nil {
			continue
		}
		var snap models.ClaudeQuotaSnapshot
		var sp *models.ClaudeQuotaSnapshot
		if common.DB.Where("email = ?", row.Email).Order("ts DESC").First(&snap).Error == nil {
			sp = &snap
		}
		// Skip accounts that are known-exceeded on a fresh snapshot; a stale
		// critical snapshot falls through to a re-probe below.
		if sp != nil && sp.Severity == "critical" && time.Since(sp.Ts) < quotaCacheTTL {
			continue
		}
		cands = append(cands, cand{row, sp})
	}

	// Order (ascending key, lowest picked first): "use it or lose it".
	//   1. prefer_email — explicit stickiness (the proxy also caches leases
	//      per-user for prompt-cache locality; honor a real match).
	//   2. Among accounts that still HAVE 5h headroom, prefer the one whose 5h
	//      window resets SOONEST. Its remaining allocation is wiped at the reset
	//      regardless, so draining near-due accounts first maximizes total pool
	//      throughput; accounts with distant resets are "savings" left for later.
	//   3. Near-exhausted accounts (5h or 7d ≥ ceiling) go to the back — they'd
	//      429 almost immediately and just churn the retry loop.
	//   4. No snapshot → probe last.
	// The key packs these into disjoint numeric bands so the ordering is total.
	const nearExhaustCeiling = 92.0
	sortKey := func(cd cand) float64 {
		if cd.row.Email == prefer {
			return -1
		}
		if cd.snap == nil {
			return 4e9 // probe cost — behind everything with a snapshot
		}
		s := cd.snap
		// Band 3: near-exhausted on either window — last resort, ordered by how
		// spent they are (least-spent first) so we still pick the best of a bad lot.
		if s.FiveHourPct >= nearExhaustCeiling || s.SevenDayPct >= nearExhaustCeiling {
			worst := s.FiveHourPct
			if s.SevenDayPct > worst {
				worst = s.SevenDayPct
			}
			return 3e9 + worst
		}
		// Band 2 (primary): has 5h headroom → prefer soonest 5h reset. Key =
		// seconds until the 5h window resets (due-now → 0 → highest priority).
		if !s.FiveHourReset.IsZero() {
			secs := time.Until(s.FiveHourReset).Seconds()
			if secs < 0 {
				secs = 0
			}
			return secs // 0 .. ~18000 (5h) — all below the 3e9 band
		}
		// Band ~2.5: healthy but no reset timestamp — fall back to most-headroom-
		// first, kept ahead of near-exhausted (band 3) but behind timed accounts.
		return 2e9 + s.FiveHourPct
	}
	for i := 1; i < len(cands); i++ {
		for j := i; j > 0 && sortKey(cands[j]) < sortKey(cands[j-1]); j-- {
			cands[j], cands[j-1] = cands[j-1], cands[j]
		}
	}

	for _, cd := range cands {
		row := cd.row
		token, err := common.DecryptGrant(row.ValueEncrypted)
		if err != nil {
			continue
		}
		snap := cd.snap
		if snap == nil || time.Since(snap.Ts) >= quotaCacheTTL {
			fresh, err := refreshSnapshot(&row, token)
			if err != nil {
				continue // dead token with no working refresh — skip
			}
			snap = fresh
			if snap.Severity == "critical" {
				continue
			}
			// refreshSnapshot may have rotated the access token — re-read.
			var r2 models.ClaudeQuotaToken
			if common.DB.Where("email = ?", row.Email).First(&r2).Error == nil {
				if t2, err := common.DecryptGrant(r2.ValueEncrypted); err == nil {
					token = t2
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"email":         row.Email,
				"access_token":  token,
				"five_hour_pct": snap.FiveHourPct,
				"seven_day_pct": snap.SevenDayPct,
				"severity":      snap.Severity,
			},
		})
		return
	}

	fail(c, http.StatusServiceUnavailable, 1503, "no pooled account with available quota")
}

// AdminClaudeUserUsage lists per-user pool consumption over the rolling
// 5h/7d windows — the per-PAT/user counterpart of the account quota table.
//
// GET /api/v1/admin/claude-user-usage  (RequireAdmin)
func AdminClaudeUserUsage(c *gin.Context) {
	now := time.Now().UTC()
	rows := []struct {
		UserSub   string
		Email     string
		Win       string
		Tokens    int
		CostCents int
		Reqs      int
		LastTs    time.Time
	}{}
	err := common.DB.Raw(`
		SELECT ue.user_sub                                        AS user_sub,
		       COALESCE(u.email, ue.user_sub)                     AS email,
		       CASE WHEN ue.ts >= ? THEN '5h' ELSE '7d' END       AS win,
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens), 0) AS tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents,
		       COUNT(*)                                           AS reqs,
		       MAX(ue.ts)                                         AS last_ts
		FROM   usage_events ue
		LEFT JOIN users u ON u.id = ue.user_sub
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= ?
		GROUP  BY ue.user_sub, u.email, win`,
		now.Add(-5*time.Hour), now.Add(-7*24*time.Hour)).Scan(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query usage: "+err.Error())
		return
	}

	// Per-model breakdown over the 7d window.
	modelRows := []struct {
		UserSub   string
		Model     string
		Tokens    int
		CostCents int
	}{}
	common.DB.Raw(`
		SELECT ue.user_sub                                        AS user_sub,
		       COALESCE(ue.model, '')                             AS model,
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens), 0) AS tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= ?
		GROUP  BY ue.user_sub, ue.model`,
		now.Add(-7*24*time.Hour)).Scan(&modelRows)

	// Also find users who hold a claude:proxy (or wildcard) PAT used recently
	// — they show even if chargeUser failed (0/0 token rows).
	var patHolders []struct {
		UserSub    string
		Email      string
		LastUsedAt time.Time
	}
	common.DB.Raw(`
		SELECT t.user_id AS user_sub, u.email,
		       MAX(t.last_used_at) AS last_used_at
		FROM   tokens t
		JOIN   users u ON u.id = t.user_id
		WHERE  t.revoked_at IS NULL
		  AND  t.last_used_at >= ?
		  AND (t.scopes = '*'
		       OR t.scopes = 'claude:proxy'
		       OR t.scopes LIKE 'claude:proxy %'
		       OR t.scopes LIKE '% claude:proxy'
		       OR t.scopes LIKE '% claude:proxy %')
		GROUP  BY t.user_id, u.email`,
		now.Add(-7*24*time.Hour)).Scan(&patHolders)

	cap5, cap7 := common.ClaudePoolLimits()
	// Third query: oldest event per user per window — used to compute reset times.
	// five_hour_reset = min_ts_5h + 5h  (when the oldest 5h event ages out)
	// seven_day_reset = min_ts_7d + 7d  (when the oldest 7d event ages out)
	oldestRows := []struct {
		UserSub  string
		Win      string
		OldestTs time.Time
	}{}
	common.DB.Raw(`
		SELECT ue.user_sub                                        AS user_sub,
		       CASE WHEN ue.ts >= ? THEN '5h' ELSE '7d' END       AS win,
		       MIN(ue.ts)                                         AS oldest_ts
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= ?
		GROUP  BY ue.user_sub, win`,
		now.Add(-5*time.Hour), now.Add(-7*24*time.Hour)).Scan(&oldestRows)

	type modelUsage struct {
		Tokens    int `json:"tokens_7d"`
		CostCents int `json:"cost_cents_7d"`
	}
	type userUsage struct {
		Email         string                `json:"email"`
		FiveHour      int                   `json:"five_hour_tokens"`
		SevenDay      int                   `json:"seven_day_tokens"`
		FiveHourPct   float64               `json:"five_hour_pct"`
		SevenDayPct   float64               `json:"seven_day_pct"`
		CostCents7d   int                   `json:"cost_cents_7d"`
		Requests      int                   `json:"requests_7d"`
		LastTs        time.Time             `json:"last_ts"`
		FiveHourReset time.Time             `json:"five_hour_reset"`
		SevenDayReset time.Time             `json:"seven_day_reset"`
		Models        map[string]modelUsage `json:"models"`
	}
	byUser := map[string]*userUsage{}
	for _, r := range rows {
		u, ok := byUser[r.UserSub]
		if !ok {
			u = &userUsage{Email: r.Email, Models: map[string]modelUsage{}}
			byUser[r.UserSub] = u
		}
		if r.Win == "5h" {
			u.FiveHour += r.Tokens
		}
		u.SevenDay += r.Tokens       // 5h bucket is inside the 7d window
		u.CostCents7d += r.CostCents // accumulate cost from both buckets (7d total)
		u.Requests += r.Reqs
		if r.LastTs.After(u.LastTs) {
			u.LastTs = r.LastTs
		}
	}
	// Attach per-user reset times from oldest-event query.
	for _, or_ := range oldestRows {
		u, ok := byUser[or_.UserSub]
		if !ok {
			continue
		}
		switch or_.Win {
		case "5h":
			u.FiveHourReset = or_.OldestTs.Add(5 * time.Hour)
		case "7d":
			u.SevenDayReset = or_.OldestTs.Add(7 * 24 * time.Hour)
		}
	}
	// Attach per-model breakdown.
	for _, mr := range modelRows {
		u, ok := byUser[mr.UserSub]
		if !ok {
			continue
		}
		m := u.Models[mr.Model]
		m.Tokens += mr.Tokens
		m.CostCents += mr.CostCents
		u.Models[mr.Model] = m
	}
	// Merge PAT holders who haven't charged tokens yet.
	for _, ph := range patHolders {
		if _, ok := byUser[ph.UserSub]; !ok {
			byUser[ph.UserSub] = &userUsage{
				Email:  ph.Email,
				LastTs: ph.LastUsedAt,
				Models: map[string]modelUsage{},
			}
		}
	}
	users := make([]userUsage, 0, len(byUser))
	for _, u := range byUser {
		u.FiveHourPct = float64(u.FiveHour) / float64(cap5) * 100
		u.SevenDayPct = float64(u.SevenDay) / float64(cap7) * 100
		users = append(users, *u)
	}
	// Highest 5h pressure first.
	for i := 1; i < len(users); i++ {
		for j := i; j > 0 && users[j].FiveHourPct > users[j-1].FiveHourPct; j-- {
			users[j], users[j-1] = users[j-1], users[j]
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"users":            users,
			"five_hour_tokens": cap5,
			"seven_day_tokens": cap7,
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

// ── proactive token refresh loop ───────────────────────────────────────────
//
// Claude OAuth access tokens expire in ~1 hour. StartTokenRefreshLoop starts
// a background goroutine that wakes every 12 hours and proactively exchanges
// every stored refresh token for a fresh access+refresh token pair, keeping
// the pool perpetually valid without any manual intervention.
//
// Only rows with a stored RefreshTokenEncrypted are processed; rows with only
// an access token are left alone (they must be re-added manually when they
// expire). Requests are staggered by 2 s to avoid simultaneous Anthropic hits.

// tokenRefreshInterval is how often the proactive loop sweeps all accounts.
// Claude OAuth access tokens expire in roughly 1 hour; 45 minutes ensures they
// are refreshed before expiry even if the proxy hasn't been used recently.
const tokenRefreshInterval = 45 * time.Minute

func StartTokenRefreshLoop() {
	go func() {
		// Small initial delay so the DB is ready and startup noise settles.
		time.Sleep(3 * time.Minute)
		for {
			proactiveRefreshAll()
			time.Sleep(tokenRefreshInterval)
		}
	}()
}

// jwtExpiry extracts the exp claim from a JWT without verifying the signature.
// Returns zero time on any parse error.
func jwtExpiry(rawToken string) time.Time {
	// sk-ant-oat01-<header>.<payload>.<sig> — strip vendor prefix.
	tok := rawToken
	if idx := strings.Index(rawToken, "eyJ"); idx != -1 {
		tok = rawToken[idx:]
	}
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) < 2 {
		return time.Time{}
	}
	payload, err := base64DecodeJWT(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

func base64DecodeJWT(s string) ([]byte, error) {
	// JWT uses base64url without padding; add padding back.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	// Replace url-safe chars.
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64Stdlib.StdEncoding.DecodeString(s)
}

func proactiveRefreshAll() {
	// Single-sweeper election across replicas: GET_LOCK with 0 timeout —
	// if the other pod is mid-sweep, skip this tick entirely. Every sweep
	// rotates every refresh token, so duplicate sweeps double the rotation
	// rate and widen the crash window where a rotated-but-unpersisted token
	// loses the family.
	_ = common.DB.Connection(func(tx *gorm.DB) error {
		var got int
		if err := tx.Raw("SELECT GET_LOCK('cqr:sweep', 0)").Scan(&got).Error; err != nil || got != 1 {
			log.Printf("token-refresh-loop: another replica is sweeping — skipping this tick")
			return nil
		}
		defer tx.Exec("DO RELEASE_LOCK('cqr:sweep')")
		sweepAllTokens()
		return nil
	})
}

func sweepAllTokens() {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.
		Where("refresh_token_encrypted != '' AND revoked_at IS NULL").
		Find(&rows).Error; err != nil {
		log.Printf("token-refresh-loop: db query failed: %v", err)
		return
	}
	var quarantined int64
	common.DB.Model(&models.ClaudeQuotaToken{}).Where("revoked_at IS NOT NULL").Count(&quarantined)
	if quarantined > 0 {
		log.Printf("token-refresh-loop: %d quarantined account(s) awaiting re-add", quarantined)
	}
	if len(rows) == 0 {
		return
	}
	for _, row := range rows {
		// Damping: if any refresher (a lease, a dashboard probe, the other
		// replica's earlier sweep) rotated this row recently, leave it alone —
		// each rotation is a fresh chance to lose the family.
		if time.Since(row.UpdatedAt) < tokenRefreshInterval/2 {
			continue
		}
		tok, err := common.DecryptGrant(row.ValueEncrypted)
		if err != nil {
			log.Printf("token-refresh-loop: %s: decrypt err: %v — skipping", row.Email, err)
			continue
		}
		// Only refresh if the token expires within 2 × the sweep interval
		// (i.e. within ~90 min). Tokens still valid for longer are left alone.
		if exp := jwtExpiry(tok); !exp.IsZero() && time.Until(exp) > 2*tokenRefreshInterval {
			log.Printf("token-refresh-loop: %s: exp in %v — skipping", row.Email, time.Until(exp).Round(time.Minute))
			continue
		}
		if _, err := tryRefreshToken(&row); err != nil {
			log.Printf("token-refresh-loop: %s: FAILED: %v", row.Email, err)
		} else {
			log.Printf("token-refresh-loop: %s: ok", row.Email)
		}
		time.Sleep(2 * time.Second)
	}
}
