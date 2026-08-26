package handler

import (
	"encoding/json"
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
	lqtStrategyApp   = "lqt-mailbox"
)

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
	return app == lqtStrategyApp
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
	if tok := mintLQTStrategyPAT(userSub); tok != "" {
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
