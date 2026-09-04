package handler

// /api/v1/me/apps/:app/secrets/* — per-(user, xpio-app, key) runtime
// credentials. The plaintext NEVER leaves the server in API responses
// — only presence (`is_set: true|false`). Plaintext is fetched
// out-of-band by the runner (CLI on the operator host, or the cloud
// scheduler) via a service-to-service introspect path (P2).
//
// AES-256-GCM via the existing IDENTITY_GRANT_KEY (same key the
// google_grants table uses).

import (
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

var secretKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// maskSecret returns a bounded, non-usable preview of a secret: a leading
// identifier prefix + a short suffix with the middle elided (e.g.
// "sk-ant-oat01-3tSM…jAAA", "lm_pat_live_2905…"). Reveals at most ~16 chars of
// long values and progressively less of short ones, so it identifies the
// credential without leaking it. ASCII-only (all our token formats are ASCII).
func maskSecret(v string) string {
	n := len(v)
	switch {
	case n == 0:
		return ""
	case n <= 6:
		return v[:1] + "…" // tiny — reveal almost nothing
	case n <= 16:
		return v[:n/3] + "…" // short — ≤ 1/3, no suffix
	default:
		return v[:12] + "…" + v[n-4:]
	}
}

type meSecretPutBody struct {
	Value string `json:"value" binding:"required"`
}

// PUT /api/v1/me/apps/:app/secrets/:key
//
// Body: {"value":"<plaintext>"}. Encrypts then upserts into app_secrets.
func MeSecretPut(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid secret key — alphanumeric+underscore, ≤64 chars")
		return
	}
	var body meSecretPutBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Value == "" {
		fail(c, http.StatusBadRequest, 1400, "value required")
		return
	}

	enc, err := common.EncryptGrant(body.Value)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
		return
	}

	now := time.Now().UTC()
	sec := models.AppSecret{
		UserSub:        userID,
		AppSlug:        app,
		Key:            key,
		ValueEncrypted: enc,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// Upsert on composite PK.
	if err := common.DB.Save(&sec).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "stored",
		"data": gin.H{
			"app":        app,
			"key":        key,
			"is_set":     true,
			"updated_at": now.Format(time.RFC3339),
		},
	})
}

// GET /api/v1/me/apps/:app/secrets — list keys present (no values).
func MeSecretsList(c *gin.Context) {
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
	var rows []models.AppSecret
	if err := common.DB.Where("user_sub = ? AND app_slug = ?", userID, app).
		Order("`key` ASC").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list: "+err.Error())
		return
	}
	keys := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		// Masked preview so the owner can confirm WHICH credential is stored
		// (e.g. sk-ant-oat01-3tSM…jAAA) without exposing the secret. Decrypt is
		// safe here: the row is the caller's own (currentUserID-scoped) and only
		// a bounded prefix+suffix is returned. Never expose the full value.
		preview := ""
		if pt, err := common.DecryptGrant(r.ValueEncrypted); err == nil {
			preview = maskSecret(pt)
		}
		keys = append(keys, gin.H{
			"key":        r.Key,
			"is_set":     true,
			"preview":    preview,
			"updated_at": r.UpdatedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "secrets": keys},
	})
}

// DELETE /api/v1/me/apps/:app/secrets/:key
func MeSecretDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) || !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or key")
		return
	}
	res := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userID, app, key).Delete(&models.AppSecret{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete: "+res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "secret not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "deleted",
		"data": gin.H{"app": app, "key": key},
	})
}

// GET /api/v1/me/apps/:app/secrets/:key/value — service-to-service ONLY.
// Returns plaintext. Gate this in P1 on a dedicated runner JWT scope.
// In P0 we leave it bearer-auth same as the rest — the runner uses
// the user's PAT.
//
// Note: this endpoint is not surfaced in the UI; only the runner calls it.
func MeSecretFetchValue(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) || !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or key")
		return
	}
	var sec models.AppSecret
	err := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userID, app, key).First(&sec).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusNotFound, 1404, "secret not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	pt, err := common.DecryptGrant(sec.ValueEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"value": pt},
	})
}

// InternalAppSecretsFetch — POST /api/v1/internal/app-secrets/fetch
// (X-Bridge-Secret). Body: {user_sub, app}. Returns the DECRYPTED
// {key: value} map of that user's secrets for the app, for the scheduler
// to inject into the cycle env. Service-to-service only — never user-facing
// (the user-facing routes only ever surface is_set, never plaintext).
func InternalAppSecretsFetch(c *gin.Context) {
	var body struct {
		UserSub string `json:"user_sub" binding:"required"`
		App     string `json:"app"      binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	// Secrets are keyed on app_slug, so a RENAMED app orphans every credential
	// its users set before the rename — the same failure appAliases was written
	// for on run rows. lqt-mailbox -> quant-research shipped at v0.7.0; anything
	// a user entered under the old slug became invisible the moment the app was
	// updated, and the cycle then fails at its own credential check as though
	// they had never set one.
	aliases := appAliases(body.App)
	var rows []models.AppSecret
	if err := common.DB.Where("user_sub = ? AND app_slug IN ?", body.UserSub, aliases).
		Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	// The CURRENT slug wins when a key exists under both, so a value set after
	// the rename is never shadowed by a stale one carrying the same key.
	out := map[string]string{}
	for _, pass := range []bool{false, true} {
		for i := range rows {
			isCurrent := rows[i].AppSlug == body.App
			if isCurrent != pass {
				continue
			}
			if rows[i].Key == lqtStrategyPATCacheKey {
				continue // machine-managed cache, not a user credential
			}
			if v, err := common.DecryptGrant(rows[i].ValueEncrypted); err == nil {
				out[rows[i].Key] = v
			}
		}
	}
	// An lqt-mailbox DEPLOY needs an `lqt:strategy`-scoped PAT, which no user
	// can be expected to paste into a credential form — and which the picker
	// cannot synthesise, because it only has the caller's login JWT. Mint one
	// here, per fetch, so it rides the SAME env-injection the config_schema
	// creds use (the picker writes these AFTER LUMID_PAT, so it wins).
	//
	// Injected only for the app that deploys, and only when the user has not
	// set the key themselves — a hand-set LQT_STRATEGY_PAT stays authoritative.
	// See lqt_strategy_pat.go for why a scoped PAT (not the login JWT, not an
	// aud=lqt session-bearer) is the only credential the consumer accepts.
	if isLQTStrategyApp(body.App) {
		// One cached token serves BOTH keys — mint/renew it at most once here.
		var cached string
		cachedOnce := func() string {
			if cached == "" {
				cached = lqtStrategyPATCached(body.UserSub)
			}
			return cached
		}
		if _, userSet := out["LQT_STRATEGY_PAT"]; !userSet {
			if tok := cachedOnce(); tok != "" {
				out["LQT_STRATEGY_PAT"] = tok
			}
		}
		// LUMID_PAT is what the app's own reads authenticate with —
		// `xpio_client._pat()` resolves LUMID_PAT then ~/.lumilake/pat, and a
		// TENANT cycle has neither: `_run_loop_cycle` deliberately pops
		// LUMID_PAT so a tenant never borrows the operator's credential, and
		// HOME is the tenant root, so the operator's mounted pat file is not
		// on its path either. Every scheduled harvest therefore died on
		// "No LUMID_PAT env var and ~/.lumilake/pat not found" — 400/day on
		// 2026-08-31, and after the scheduler stopped hiding two thirds of the
		// fleet, enough consecutive failures to SUSPEND 120 tenant loops.
		//
		// The credential that worked was the operator's, reaching Job-runner
		// cycles through `envFrom: scheduler-env` — i.e. the one path that
		// "worked" did so by handing tenant cycles the operator's PAT, exactly
		// what the in-pod scrub exists to prevent. Injecting the tenant's own
		// token fixes the failure AND closes that: app-secret values are
		// written after the scrub in-pod, and reach the Job as explicit `env`
		// entries, which outrank `envFrom`.
		//
		// SAME token as the deploy PAT, deliberately — no second credential.
		// Verified against the read surface (lumid-data-service) 2026-09-04:
		// its only scope gates are `lumilake:write` for blob writes and a
		// sync-peer credential; the read plane asks solely for a valid Lumid
		// PAT ("present a Lumid PAT as 'Authorization: Bearer <token>'").
		// Minting a second, differently-scoped token would add credential
		// sprawl and buy nothing.
		if _, userSet := out["LUMID_PAT"]; !userSet {
			if tok := cachedOnce(); tok != "" {
				out["LUMID_PAT"] = tok
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"secrets": out},
	})
}
