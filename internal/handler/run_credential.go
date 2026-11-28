package handler

// Per-run REFRESH credential — what a tenant cycle holds INSTEAD of the bridge
// secret.
//
// Until this existed the scheduler launched every tenant cycle with its own
// env, LUMID_IDENTITY_BRIDGE_SECRET included, and tenant app code runs inside
// that cycle process. Any app could therefore call POST
// /internal/mint-user-token and mint a lum.id token for ANY user. The cycle only
// needed the secret for two things: re-minting its own 15-min bearer, and
// self-reporting its run. This file gives it a credential that can do those two
// things for ONE user and nothing else.
//
//	POST /api/v1/internal/run-credential   (X-Bridge-Secret — the DAEMON calls it)
//	     {sub, app?, loop?, intent_id?, ttl_seconds?}
//	  -> {refresh_token, refresh_expires_at, credential_id, token, expires_at}
//	POST /api/v1/run-credential/refresh    (the credential as Bearer, or {refresh_token})
//	  -> {token, expires_at, refresh_expires_at}   lum.id bearer for THAT sub only
//	POST /api/v1/run-credential/revoke     (the credential itself; idempotent)
//
// The same credential authenticates the run-reporting /internal routes a cycle
// calls (RequireBridgeOrRunCredential below). Each of those handlers calls
// allowRunWrite / allowRunAppWrite with the user_sub (and app) it is about to
// write, which refuses any other user — and any other app when the credential
// is app-bound. The bridge-secret path through those routes is unchanged.
//
// What it is NOT: a PAT, a session, or a general bearer. `lm_runref_` does not
// start with `lm_pat_`, so introspect, currentUserID and every consumer that
// classifies by shape refuse it. Stored hashed (SHA-256 of 256 random bits),
// 6 h by default, 12 h at most; a suspended or deleted user gets nothing from
// it, checked on every use rather than at mint time only.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	runCredPrefix     = "lm_runref_"
	runCredDefaultTTL = 6 * time.Hour
	runCredMaxTTL     = 12 * time.Hour
	runCredMinTTL     = time.Minute
	// Same shape mint-user-token hands a run today: aud lumid-ecosystem, 15 min.
	runBearerTTL      = 15 * time.Minute
	runBearerAudience = "lumid-ecosystem"
	// Rows are kept a day past expiry (forensics), then purged on mint.
	runCredRetention  = 24 * time.Hour
	runCredPurgeBatch = 500
	ctxRunCredential  = "run_credential"
)

type runCredMintBody struct {
	Sub        string `json:"sub"`
	App        string `json:"app"`
	Loop       string `json:"loop"`
	IntentID   string `json:"intent_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func hashRunCredential(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func newRunCredentialSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return runCredPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// runCredError is a refusal the caller writes verbatim with fail().
type runCredError struct {
	status, code int
	msg          string
}

// loadRunUser applies the same principal gate as login and introspect
// (ownerRejection): a missing user or a suspended one gets nothing. A lookup
// that failed for another reason is an outage (503), never "user not found" —
// the scheduler parks a tenant's loops on that exact 404.
func loadRunUser(sub string) (*models.User, *runCredError) {
	var u models.User
	if err := common.DB.Where("id = ?", sub).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, &runCredError{http.StatusNotFound, 1404, "user not found"}
		}
		return nil, &runCredError{http.StatusServiceUnavailable, 1503, "user lookup failed: " + err.Error()}
	}
	if reason, reject := ownerRejection(false, u.Status); reject {
		return nil, &runCredError{http.StatusForbidden, 1006, reason}
	}
	return &u, nil
}

// resolveRunCredential checks a raw `lm_runref_*` value: known, unrevoked,
// unexpired, and its user still present and not suspended.
func resolveRunCredential(raw string) (*models.RunCredential, *models.User, *runCredError) {
	if !strings.HasPrefix(raw, runCredPrefix) || len(raw) <= len(runCredPrefix) {
		return nil, nil, &runCredError{http.StatusUnauthorized, 1401, "invalid run credential"}
	}
	var row models.RunCredential
	if err := common.DB.Where("token_hash = ?", hashRunCredential(raw)).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, &runCredError{http.StatusUnauthorized, 1401, "invalid run credential"}
		}
		return nil, nil, &runCredError{http.StatusServiceUnavailable, 1503, "run credential lookup failed: " + err.Error()}
	}
	if row.RevokedAt != nil {
		return nil, nil, &runCredError{http.StatusUnauthorized, 1401, "run credential revoked"}
	}
	if !time.Now().Before(row.ExpiresAt) {
		return nil, nil, &runCredError{http.StatusUnauthorized, 1401, "run credential expired"}
	}
	u, rerr := loadRunUser(row.UserID)
	if rerr != nil {
		if rerr.status == http.StatusNotFound {
			// A credential whose user is gone is simply not valid any more.
			rerr = &runCredError{http.StatusUnauthorized, 1401, "user not found"}
		}
		return nil, nil, rerr
	}
	return &row, u, nil
}

// rawRunCredential reads the credential from `Authorization: Bearer`, else
// from a JSON body {"refresh_token": "..."}. Never from a cookie.
func rawRunCredential(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	var b struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = c.ShouldBindJSON(&b)
	return strings.TrimSpace(b.RefreshToken)
}

// purgeExpiredRunCredentials drops rows a day past expiry, a bounded batch per
// mint, so the table tracks the number of runs in flight rather than every run
// ever. Best-effort: a failed purge must never fail a mint.
func purgeExpiredRunCredentials(now time.Time) {
	var ids []string
	if err := common.DB.Model(&models.RunCredential{}).
		Where("expires_at < ?", now.Add(-runCredRetention)).
		Limit(runCredPurgeBatch).Pluck("id", &ids).Error; err != nil || len(ids) == 0 {
		return
	}
	common.DB.Where("id IN ?", ids).Delete(&models.RunCredential{})
}

// InternalRunCredentialMint — POST /api/v1/internal/run-credential (X-Bridge-Secret).
// Called by the scheduler DAEMON for each tenant cycle it launches. Returns the
// refresh credential plus the run's first bearer, so one round-trip replaces
// the separate mint-user-token call.
func InternalRunCredentialMint(c *gin.Context) {
	var b runCredMintBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	b.Sub = strings.TrimSpace(b.Sub)
	if b.Sub == "" {
		fail(c, http.StatusBadRequest, 1400, "sub required")
		return
	}
	if b.App != "" && !slugRe.MatchString(b.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if len(b.Loop) > 128 {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	if b.IntentID != "" && !meIntentIDRe.MatchString(b.IntentID) {
		fail(c, http.StatusBadRequest, 1400, "invalid intent_id")
		return
	}
	u, rerr := loadRunUser(b.Sub)
	if rerr != nil {
		fail(c, rerr.status, rerr.code, rerr.msg)
		return
	}
	ttl := time.Duration(b.TTLSeconds) * time.Second
	switch {
	case ttl <= 0:
		ttl = runCredDefaultTTL
	case ttl < runCredMinTTL:
		ttl = runCredMinTTL
	case ttl > runCredMaxTTL:
		ttl = runCredMaxTTL
	}
	raw, err := newRunCredentialSecret()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint: "+err.Error())
		return
	}
	now := time.Now()
	row := models.RunCredential{
		ID:        uuid.NewString(),
		TokenHash: hashRunCredential(raw),
		UserID:    u.ID,
		App:       b.App,
		Loop:      b.Loop,
		IntentID:  b.IntentID,
		ExpiresAt: now.Add(ttl),
	}
	if err := common.DB.Create(&row).Error; err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, "store: "+err.Error())
		return
	}
	tok, _, exp, err := common.IssueBridgeJWTWithClaims(u.ID, u.Email, u.Role, runBearerAudience, nil, runBearerTTL,
		runBearerClaims(&row))
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint: "+err.Error())
		return
	}
	purgeExpiredRunCredentials(now)
	ok(c, "minted", gin.H{
		"refresh_token":      raw,
		"refresh_expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
		"credential_id":      row.ID,
		"token":              tok,
		"expires_at":         exp.UTC().Format(time.RFC3339),
	})
}

// runBearerClaims: what a run's bearer says about the run, so the LLM gateways
// it calls can attribute spend to the app (usage_events.app / run_id). The run
// id is the credential's id: one credential per run, minted by the daemon.
func runBearerClaims(row *models.RunCredential) common.RunClaims {
	return common.RunClaims{App: row.App, Loop: row.Loop, RunID: row.ID}
}

// RunCredentialRefresh — POST /api/v1/run-credential/refresh.
// Exchanges a live run credential for a fresh lum.id bearer for ITS user. There
// is no sub parameter to get wrong: the user comes from the credential row.
// The bearer never outlives the credential that minted it.
func RunCredentialRefresh(c *gin.Context) {
	row, u, rerr := resolveRunCredential(rawRunCredential(c))
	if rerr != nil {
		fail(c, rerr.status, rerr.code, rerr.msg)
		return
	}
	ttl := runBearerTTL
	if rem := time.Until(row.ExpiresAt); rem < ttl {
		ttl = rem
	}
	tok, _, exp, err := common.IssueBridgeJWTWithClaims(u.ID, u.Email, u.Role, runBearerAudience, nil, ttl,
		runBearerClaims(row))
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mint: "+err.Error())
		return
	}
	now := time.Now()
	common.DB.Model(&models.RunCredential{}).Where("id = ?", row.ID).UpdateColumn("last_used_at", now)
	ok(c, "refreshed", gin.H{
		"token":              tok,
		"expires_at":         exp.UTC().Format(time.RFC3339),
		"refresh_expires_at": row.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// RunCredentialRevoke — POST /api/v1/run-credential/revoke.
// A finished run hands its credential back, so a copy that leaked out of the
// run is dead as soon as the run is. Authenticated by the credential itself;
// revoking an already-revoked or expired one is a no-op success.
func RunCredentialRevoke(c *gin.Context) {
	raw := rawRunCredential(c)
	if !strings.HasPrefix(raw, runCredPrefix) {
		fail(c, http.StatusUnauthorized, 1401, "invalid run credential")
		return
	}
	res := common.DB.Model(&models.RunCredential{}).
		Where("token_hash = ? AND revoked_at IS NULL", hashRunCredential(raw)).
		UpdateColumn("revoked_at", time.Now())
	if res.Error != nil {
		fail(c, http.StatusServiceUnavailable, 1503, "revoke: "+res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		var n int64
		common.DB.Model(&models.RunCredential{}).Where("token_hash = ?", hashRunCredential(raw)).Count(&n)
		if n == 0 {
			fail(c, http.StatusUnauthorized, 1401, "invalid run credential")
			return
		}
	}
	ok(c, "revoked", gin.H{"revoked": true})
}

// RequireBridgeOrRunCredential gates the run-reporting /internal routes. A
// caller presenting X-Bridge-Secret, or no run credential at all, goes through
// RequireBridge exactly as before (old schedulers, the daemon, operator
// cycles). A caller presenting `Authorization: Bearer lm_runref_*` is admitted
// as THAT run; the handler then refuses any write outside the credential's
// user (allowRunWrite / allowRunAppWrite).
func RequireBridgeOrRunCredential() gin.HandlerFunc {
	bridge := RequireBridge()
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if c.GetHeader("X-Bridge-Secret") != "" || !strings.HasPrefix(h, "Bearer "+runCredPrefix) {
			bridge(c)
			return
		}
		row, _, rerr := resolveRunCredential(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
		if rerr != nil {
			fail(c, rerr.status, rerr.code, rerr.msg)
			c.Abort()
			return
		}
		c.Set(ctxRunCredential, row)
		c.Next()
	}
}

// runCredentialOf returns the run credential that authenticated this request,
// or nil for a bridge-secret caller.
func runCredentialOf(c *gin.Context) *models.RunCredential {
	v, exists := c.Get(ctxRunCredential)
	if !exists {
		return nil
	}
	row, _ := v.(*models.RunCredential)
	return row
}

// allowRunWrite is true for a bridge caller. For a run-credential caller it is
// true only when userSub is the credential's own user; otherwise it writes the
// 403 and returns false. Call it with the EXACT value the handler will use.
func allowRunWrite(c *gin.Context, userSub string) bool {
	row := runCredentialOf(c)
	if row == nil {
		return true
	}
	if userSub != row.UserID {
		fail(c, http.StatusForbidden, 1403, "run credential is bound to another user")
		return false
	}
	return true
}

// allowRunAppWrite is allowRunWrite plus the app binding: an app-bound
// credential (every one the scheduler mints) may only write for its own app,
// so one installed app's code cannot write another app's runs or drain its
// signals for the same user.
func allowRunAppWrite(c *gin.Context, userSub, app string) bool {
	if !allowRunWrite(c, userSub) {
		return false
	}
	if row := runCredentialOf(c); row != nil && row.App != "" && app != row.App {
		fail(c, http.StatusForbidden, 1403, "run credential is bound to another app")
		return false
	}
	return true
}

// runChargeAllowed narrows usage/charge for a run-credential caller to what a
// cycle itself charges: its own LLM tokens (cycle_llm) and external calls
// (external_api), never negative. cycle_start is the daemon's charge and
// claude_proxy is the proxy's; a negative count from app code would hand the
// user back budget. A bridge caller is not affected.
func runChargeAllowed(c *gin.Context, b internalChargeBody) bool {
	if runCredentialOf(c) == nil {
		return true
	}
	if b.Kind != "cycle_llm" && b.Kind != "external_api" {
		fail(c, http.StatusForbidden, 1403, "run credential may not charge kind "+b.Kind)
		return false
	}
	for _, n := range []int{b.InputTokens, b.OutputTokens, b.CacheReadTokens,
		b.CacheCreationTokens, b.CacheCreation1hTokens, b.Count, b.CostCents} {
		if n < 0 {
			fail(c, http.StatusBadRequest, 1400, "negative usage")
			return false
		}
	}
	return true
}

// computeJobOwnedByOther reports whether (site, jobID) is already owned by a
// user other than sub, by the two authoritative records callerOwnsComputeJob
// consults first (a chat-path claim, a Research Fleet row). Fails CLOSED: on a
// DB error the address is treated as someone else's and dropped. Used only for
// run-credential callers, i.e. when app code is the one reporting the address.
func computeJobOwnedByOther(sub, site, jobID string) bool {
	var claim models.MeComputeJobClaim
	err := common.DB.Where("site = ? AND job_id = ?", site, jobID).First(&claim).Error
	if err == nil {
		return claim.UserSub != sub
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}
	var fleet models.MeFleetJob
	err = common.DB.Where("site = ? AND kind = ? AND native_id = ?", site, fleetKindLL, jobID).First(&fleet).Error
	if err == nil {
		return fleet.UserSub != sub
	}
	return !errors.Is(err, gorm.ErrRecordNotFound)
}
