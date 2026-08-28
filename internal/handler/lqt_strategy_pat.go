package handler

import (
	"encoding/json"
	"fmt"
	"gorm.io/gorm/clause"
	"log"
	"strconv"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Per-user `lqt:strategy` PAT provisioning for xpio intents.
//
// WHY THIS EXISTS. The LQT mailbox consumer authorises a `strategy.deploy`
// from `payload.auth.pat`, and `lqt-auth::is_pat_shape()` accepts ONLY
// `lm_pat_live_*` / `rm_pat_live_*` — anything else is verified as a JWT and
// must carry `aud="lqt"`. The xpio app resolves its credential from
// `LQT_STRATEGY_PAT` → `LUMID_PAT` → `~/.lumilake/pat`, and under the scheduler
// the only one set is `LUMID_PAT`, which `me_intent_picker.py` assigns the
// caller's LOGIN JWT (`aud=["lumid-ecosystem"]`). So every Deploy from Studio
// ended:
//
//	mailbox_consumer.auth_denied topic=strategy.deploy
//	    reason=authentication failed: jwt_invalid
//
// two seconds after a submit that reported ok, and the row sat at
// `status=sent` forever (a reject ack carries no `strategy` echo, so the
// ingress never flips the record). Measured 2026-08-26: 0 non-admin
// registrations, ever.
//
// A `session-bearer?audience=lqt` token does NOT close this: right audience,
// but it carries no scopes, so the consumer's TOPIC_AUTHZ still refuses.
// The credential genuinely has to be a scoped PAT.
//
// WHY MINT PER CLAIM RATHER THAN STORE ONE. A PAT's cleartext is argon2id-hashed
// at rest and is unrecoverable after minting, so "reuse the user's existing one"
// is impossible without keeping a decryptable copy — i.e. standing, long-lived
// deploy credentials for every user. Instead each claim mints a fresh,
// narrowly-scoped, SHORT-LIVED token: same reasoning as `/session-bearer`, and
// it keeps per-tenant attribution, which a single shared service PAT would
// collapse (the consumer's tenant allowlist exists precisely to enforce it).
const (
	// Long enough for a queued intent to be claimed, run and retried; short
	// enough that a leaked token from a picker log is near-worthless. Intent
	// volume is low (hundreds lifetime), so mint-per-claim is not a load
	// concern; expired rows are inert.
	lqtStrategyPATTTL = 2 * time.Hour

	lqtStrategyScope = "lqt:strategy"

	// The app_secrets slug the minted deploy PAT is CACHED under. Deliberately
	// the legacy name: it is a cache key, not a display name, and one row per
	// user is correct no matter which name the app is installed as — the
	// credential is identical either way. Changing it would orphan every live
	// cached token for no gain.
	lqtStrategyApp = "lqt-mailbox"
)

// lqtStrategyApps — every app slug whose `run_loop` deploy needs the scoped PAT.
//
// THE RENAME BUG. The app was renamed `lqt-mailbox` → `quant-research` at
// v0.7.0, and the UI's row actions post `app: quant-research`. This gate still
// matched only the OLD name, so after the rename a Deploy from the Studio page
// was handed no `lqt:strategy` PAT at all — reintroducing, silently, the exact
// failure this file was written to fix.
//
// Measured on the live mailbox 2026-08-28: of 53 rejected submissions, **42
// were `no bearer credential in payload.auth.{pat,jwt}`** and 2 more
// `jwt_invalid` — 83% of all rejections were this one gate missing its app.
//
// BOTH names are matched, not just the new one: an install predating the
// rename still runs as `lqt-mailbox`, and breaking those to fix the new name
// would just move the outage.
var lqtStrategyApps = map[string]bool{
	"quant-research": true, // current name (v0.7.0+)
	"lqt-mailbox":    true, // legacy installs
}

// isLQTStrategyApp reports whether this app slug deploys strategies and so
// needs a scoped deploy PAT injected.
func isLQTStrategyApp(app string) bool {
	return lqtStrategyApps[strings.TrimSpace(app)]
}

// lqtIntentNeedsStrategyPAT reports whether this claimed intent is an
// lqt-mailbox run that will try to deploy.
//
// Deliberately narrow: minting is a side effect, so it happens only for the app
// that needs it rather than on every claim. `action` is checked too — an
// `install` never submits a strategy.
func lqtIntentNeedsStrategyPAT(action string, payload map[string]any) bool {
	if action != "run_loop" {
		return false
	}
	app, _ := payload["app"].(string)
	return isLQTStrategyApp(app)
}

// mintLQTStrategyPAT returns a fresh `lqt:strategy` PAT for userSub, or "" if
// minting fails. Best-effort BY DESIGN: a miss must not block the intent. The
// app then fails at its own credential check with a message naming the cause,
// which is strictly better than this layer swallowing the intent.
func mintLQTStrategyPAT(userSub string) string {
	pruneExpiredLQTStrategyPATs(userSub)
	exp := time.Now().Add(lqtStrategyPATTTL)
	tok, _, err := mintPATForUser(
		userSub,
		"lqt-strategy (intent, auto)",
		[]string{lqtStrategyScope},
		&exp,
		"intent",
	)
	if err != nil {
		return ""
	}
	return tok
}

// lqtStrategyPATCacheKey is where the minted deploy PAT is cached, encrypted,
// in the SAME per-user app_secrets store that delivers it. The leading "__"
// marks it as machine-managed; a user-set LQT_STRATEGY_PAT still wins.
const lqtStrategyPATCacheKey = "__lqt_strategy_pat_cache"

// Re-mint once the cached token is within this of expiry, so a cycle never
// receives a credential that dies mid-run.
const lqtStrategyPATRenewBefore = 20 * time.Minute

// lqtStrategyPATCached returns a live deploy PAT for userSub, minting a new one
// ONLY when there is no usable cached token.
//
// WHY THIS EXISTS. The first version minted on every call. `InternalAppSecretsFetch`
// runs per cycle per user, so with lqt-mailbox installed for a cohort that is a
// fresh credential every cycle: measured 2026-08-27, **451 minted, 103 in 30
// minutes, 432 live at once** — 13 per student and rising linearly with users.
// Each is a real credential that can deploy a strategy, so that is credential
// sprawl, not just table growth.
//
// A PAT's cleartext is argon2id-hashed and unrecoverable, which is why the naive
// fix ("look up the user's existing one") is impossible — so cache it the way
// the FinData SQL password is cached: AES-256-GCM via common.EncryptGrant,
// stored as "<expiry_epoch>:<token>" so the expiry travels with it and no
// introspect round-trip is needed on the hot path.
func lqtStrategyPATCached(userSub string) string {
	// Cache-miss REASON logging. The cache row is written on every mint
	// (verified: one row per user, updated_at seconds old) yet the read never
	// hits — measured 2026-08-27, 10 of 10 fetches returned distinct tokens,
	// so this misses 100% of the time and every cycle mints a live credential.
	// Which of the four gates below fails was not deducible from the outside,
	// hence the reason string: silence is what made this cost hours.
	miss := ""
	var row models.AppSecret
	if err := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userSub, lqtStrategyApp, lqtStrategyPATCacheKey).First(&row).Error; err == nil {
		if v, err := common.DecryptGrant(row.ValueEncrypted); err == nil {
			if exp, tok, ok := strings.Cut(v, ":"); ok && tok != "" {
				if unix, err := strconv.ParseInt(exp, 10, 64); err == nil {
					if time.Until(time.Unix(unix, 0)) > lqtStrategyPATRenewBefore {
						return tok
					}
					miss = fmt.Sprintf("expires too soon (in %s, need >%s)",
						time.Until(time.Unix(unix, 0)).Round(time.Second), lqtStrategyPATRenewBefore)
				} else {
					miss = "expiry not parseable: " + exp
				}
			} else {
				miss = "cached value has no <expiry>:<token> shape"
			}
		} else {
			miss = "decrypt failed: " + err.Error()
		}
	} else {
		miss = "no cache row: " + err.Error()
	}
	log.Printf("[lqt-strategy-pat] cache MISS for %s — %s (minting a new PAT)", userSub, miss)
	tok := mintLQTStrategyPAT(userSub)
	if tok == "" {
		return ""
	}
	enc, err := common.EncryptGrant(fmt.Sprintf("%d:%s", time.Now().Add(lqtStrategyPATTTL).Unix(), tok))
	if err == nil {
		// EXPLICIT UPSERT. `Save` here inserted on the FIRST mint and silently
		// failed on every one after: app_secrets has a composite primary key
		// (user_sub, app_slug, key), the duplicate-key error went into `_ =`,
		// and the row kept its original value forever. So the cached expiry
		// aged past renewal and the read could never hit again — measured
		// 2026-08-27: created_at == updated_at == 02:10 while the row was
		// "written" every cycle 10h later, and 10 of 10 fetches minted a NEW
		// live deploy PAT (99 live for one account).
		//
		// The bug was invisible precisely because the write was best-effort
		// AND silent. Keep it non-fatal — a cache write must never cost the
		// caller its credential — but say so when it fails.
		if err := common.DB.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "user_sub"}, {Name: "app_slug"}, {Name: "key"},
			},
			DoUpdates: clause.AssignmentColumns([]string{"value_encrypted", "updated_at"}),
		}).Create(&models.AppSecret{
			UserSub: userSub, AppSlug: lqtStrategyApp,
			Key: lqtStrategyPATCacheKey, ValueEncrypted: enc,
		}).Error; err != nil {
			log.Printf("[lqt-strategy-pat] cache WRITE failed for %s: %v "+
				"(next cycle will mint again)", userSub, err)
		}
	}
	return tok
}

// attachLQTStrategyPAT adds `lqt_strategy_pat` to a claimed intent's payload
// when the intent is an lqt-mailbox run_loop. The picker exports it as
// LQT_STRATEGY_PAT, which `_scoped_pat()` prefers over LUMID_PAT.
//
// The key is NOT persisted to `me_app_intents.payload` — it is merged at CLAIM
// time, exactly like `bearer`, so no deploy credential is ever stored at rest.
func attachLQTStrategyPAT(action, userSub string, p map[string]any) {
	if p == nil || !lqtIntentNeedsStrategyPAT(action, p) {
		return
	}
	if tok := lqtStrategyPATCached(userSub); tok != "" {
		p["lqt_strategy_pat"] = tok
	}
}

// pruneExpiredLQTStrategyPATs deletes this user's already-expired auto-minted
// deploy PATs. Called opportunistically on mint so the table does not accrete
// one dead row per deploy forever. Only ever touches rows this code created
// (name + source + scope all match) and only ones already past expiry, so it
// can never revoke a credential anyone is using.
func pruneExpiredLQTStrategyPATs(userSub string) {
	scopesJSON, err := json.Marshal([]string{lqtStrategyScope})
	if err != nil {
		return
	}
	_ = common.DB.
		Where("user_id = ? AND name = ? AND source = ? AND scopes = ? AND expires_at IS NOT NULL AND expires_at < ?",
			userSub, "lqt-strategy (intent, auto)", "intent", string(scopesJSON), time.Now()).
		Delete(&models.Token{}).Error
}
