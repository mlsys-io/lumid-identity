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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
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

// fieldRelays maps an account Label (e.g. "denmark") to its field-box relay's
// base URL. Identity NO LONGER ROUTES ANY TRAFFIC through these — the OAuth
// refresh went direct as of 2026-08-08 (see refreshTokenLocked for why: a lost
// response on a rotating credential is destructive). The map is retained purely
// as the source of truth for whether a Label actually routes, reported by
// AdminClaudeTokenLabel's relay_configured field, so an operator learns
// immediately that a label is unwired instead of discovering it later from
// via_relay. Same env var and "label=url,label=url" shape as claude-proxy, which
// does still route Messages API traffic through them.
var fieldRelays = parseFieldRelays(os.Getenv("LUMID_CLAUDE_FIELD_RELAYS"))

func parseFieldRelays(spec string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		label, base := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		if label == "" || base == "" {
			continue
		}
		if _, err := url.Parse(base); err != nil {
			continue
		}
		out[label] = base
	}
	return out
}

// refreshFlights coalesces concurrent refreshes per email. Anthropic rotates the
// refresh token on every exchange, so two concurrent refreshes with the same
// refresh token (e.g. a dashboard probe racing a pool lease) would invalidate
// one side's rotated credentials.
//
// This REPLACES a plain per-email mutex, which serialised callers but did not
// coalesce them: N queued callers each performed their own full exchange, so a
// burst of 401s produced N rotations instead of one. That is the rate coupling
// behind the 2026-08-11 quarantines. A rotation invalidates every access token
// issued before it, so redundant rotations don't just waste an exchange — they
// invalidate the leases still being handed out, which produces more 401s, which
// queue more refreshes. Each extra rotation is also an extra draw at the
// lost-response window (see refreshTokenLocked) that permanently kills the
// family. One 401 storm could therefore rotate an account a dozen times in a
// minute and quarantine it on any one of them.
//
// With singleflight, N concurrent 401s on an account produce exactly ONE
// exchange and all N callers receive its result.
type refreshFlight struct {
	done  chan struct{}
	token string
	err   error
}

var refreshFlights sync.Map // email -> *refreshFlight

// beginRefresh returns the in-flight refresh for this email, or claims the slot.
// leader is true for the caller that must actually perform the exchange.
func beginRefresh(email string) (f *refreshFlight, leader bool) {
	mine := &refreshFlight{done: make(chan struct{})}
	if existing, loaded := refreshFlights.LoadOrStore(email, mine); loaded {
		return existing.(*refreshFlight), false
	}
	return mine, true
}

func (f *refreshFlight) finish(email, token string, err error) {
	f.token, f.err = token, err
	refreshFlights.Delete(email)
	close(f.done)
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
func tryRefreshToken(row *models.ClaudeQuotaToken, caller string) (string, error) {
	f, leader := beginRefresh(row.Email)
	if !leader {
		// A refresh for this account is already in flight. Wait for it and take
		// its result rather than starting a second, redundant rotation.
		select {
		case <-f.done:
			if f.err != nil {
				return "", f.err
			}
			// Adopt the row the leader persisted, so callers that go on to use
			// *row (the lease path re-reads, the sweep does not) see the rotated
			// credential rather than their stale copy.
			var fresh models.ClaudeQuotaToken
			if common.DB.Where("email = ?", row.Email).First(&fresh).Error == nil {
				*row = fresh
			}
			return f.token, nil
		case <-time.After(refreshExchangeTimeout + 10*time.Second):
			return "", fmt.Errorf("refresh already in flight for %s — timed out waiting", row.Email)
		}
	}

	var tok string
	err := withEmailLock(row.Email, func() error {
		var innerErr error
		tok, innerErr = refreshTokenLocked(row, caller)
		return innerErr
	})
	f.finish(row.Email, tok, err)
	return tok, err
}

// recordExchange writes the outcome of one OAuth refresh attempt onto the row.
// Every attempt is recorded, not just failures: a quarantine is only
// interpretable next to the exchange that preceded it, and on 2026-08-13 that
// context was exactly what was missing.
//
// Best-effort by construction — instrumentation must never fail a refresh, so
// errors here are swallowed and the caller's result stands.
func recordExchange(row *models.ClaudeQuotaToken, caller, outcome string, started time.Time, detail string) {
	ms := int(time.Since(started).Milliseconds())
	at := time.Now()
	common.DB.Model(row).Updates(map[string]interface{}{
		"last_exchange_at":      at,
		"last_exchange_outcome": outcome,
		"last_exchange_ms":      ms,
	})
	row.LastExchangeAt, row.LastExchangeOutcome, row.LastExchangeMs = &at, outcome, ms
	if detail = strings.TrimSpace(detail); detail != "" {
		detail = " detail=" + strconv.Quote(truncStr(detail, 200))
	}
	log.Printf("claude-refresh-exchange: account=%s caller=%s outcome=%s dur=%dms%s",
		row.Email, caller, outcome, ms, detail)
}

// markIndeterminate records an exchange whose OUTCOME UPSTREAM IS UNKNOWN — the
// request was sent (or answered 200) but we never got a usable response body.
// Anthropic rotates the family on receipt, so from this instant our stored
// refresh token may already be dead while still looking valid, and the next
// exchange is what will discover it.
//
// The marker is deliberately NOT cleared by a later success. It is an evidence
// trail, not a state machine: when a quarantine eventually lands, the question
// "did we lose a rotation earlier?" must still be answerable.
func markIndeterminate(row *models.ClaudeQuotaToken, caller string, started time.Time, reason string) {
	at := time.Now()
	common.DB.Model(row).Updates(map[string]interface{}{
		"indeterminate_at":     at,
		"indeterminate_reason": truncStr(reason, 500),
	})
	row.IndeterminateAt, row.IndeterminateReason = &at, truncStr(reason, 500)
	recordExchange(row, caller, "indeterminate", started, reason)
	log.Printf("claude-refresh: %s: INDETERMINATE caller=%s (%s) — the family may have rotated upstream; "+
		"our stored refresh token could already be superseded", row.Email, caller, truncStr(reason, 200))
}

func refreshTokenLocked(row *models.ClaudeQuotaToken, caller string) (string, error) {
	// Re-read: another refresher (this pod or the other replica) may have
	// rotated while we waited on the locks. singleflight collapses concurrent
	// callers within one pod; this is the cross-replica arm of the same idea.
	//
	// The test is "did the stored access token CHANGE since the copy I set out
	// to replace", not "was the row written recently". A wall-clock window (this
	// was 30s) silently stops collapsing exactly when collapsing matters most:
	// under a burst, callers queue behind a lock whose exchange can take up to
	// refreshExchangeTimeout, so anyone past the first couple of places in line
	// arrives after the window has closed and rotates redundantly — the deeper
	// the queue, the more redundant rotations, which is backwards. A changed
	// value is proof someone rotated for us regardless of how long we waited;
	// all we owe it is a check that what we'd hand back is actually usable.
	var fresh models.ClaudeQuotaToken
	if err := common.DB.Where("email = ?", row.Email).First(&fresh).Error; err == nil {
		if fresh.ValueEncrypted != row.ValueEncrypted && fresh.RevokedAt == nil {
			if tok, err := common.DecryptGrant(fresh.ValueEncrypted); err == nil && !tokenExpiringSoon(tok) {
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

	// The OAuth refresh ALWAYS goes DIRECT to platform.claude.com — never through
	// a field-box relay, even for a labelled account.
	//
	// This is a deliberate reversal of the original field-box design, which
	// routed both hops (Messages API + refresh) through the box so every
	// Anthropic-facing call for an account shared one origin. That reasoning
	// holds for the Messages API. It does NOT hold here, because a refresh is not
	// an idempotent read — Anthropic ROTATES the token family on receipt, and the
	// new refresh token exists only in the response body:
	//
	//   request lands -> family rotated -> response LOST (relay hang / timeout)
	//   -> we persist nothing -> next attempt presents the dead token
	//   -> invalid_grant -> family revoked -> manual `claude auth login` required
	//
	// So a lossy hop in front of a rotating credential converts transient box
	// flakiness into permanent credential loss. Observed twice on 2026-08-08:
	// yao@yao.lu (denmark) was revoked twice within hours while its box was
	// saturated and its relay timing out, whereas chicago/nyc — same code, healthy
	// relays — were never revoked.
	//
	// The trade is lopsided: refresh is a handful of calls per account per day
	// against thousands of relayed Messages API turns from the same box IP, so
	// origin consistency barely moves, while the downside is losing the account.
	// Health-gating the relay would NOT fix it — a relay healthy at check time can
	// still hang mid-request, and the window cannot be closed, only narrowed.
	//
	// fieldRelays is still consulted elsewhere (AdminClaudeTokenLabel's
	// relay_configured check); it is only the refresh ROUTING that is reverted.
	refreshURL := claudeOAuthTokenURL

	req, err := http.NewRequest(http.MethodPost, refreshURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")

	// Did the request actually reach Anthropic? This is the whole question when a
	// refresh fails without an answer. Anthropic rotates the family ON RECEIPT,
	// so a request we know was fully written but got no response leaves us
	// holding a token that may already be superseded — while looking valid. A
	// connection we never established rotates nothing and is harmless. The two
	// are indistinguishable from the error alone (both surface as some transport
	// error), so trace WroteRequest and let the wire tell us.
	var wroteRequest bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest = true },
	}))

	cl := &http.Client{Timeout: refreshExchangeTimeout}
	started := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		if wroteRequest {
			// Sent, never answered: the family's state upstream is UNKNOWN.
			markIndeterminate(row, caller, started, fmt.Sprintf("no response after send: %v", err))
			return "", fmt.Errorf("token refresh indeterminate (request sent, no response): %w", err)
		}
		recordExchange(row, caller, "unreachable", started, err.Error())
		return "", fmt.Errorf("token refresh network error: %w", err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil && resp.StatusCode == 200 {
		// A 200 we could not read is a rotation we cannot keep: Anthropic issued
		// a new family and the only copy of it was in that body.
		markIndeterminate(row, caller, started, fmt.Sprintf("200 with unreadable body: %v", readErr))
		return "", fmt.Errorf("token refresh indeterminate (200, body unreadable): %w", readErr)
	}

	if resp.StatusCode != 200 {
		var errResp struct {
			Error string `json:"error"`
			Desc  string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &errResp)
		if errResp.Error == "invalid_grant" {
			// The family is gone. Quarantine the row so no path re-presents the
			// revoked token, and classify the cause BEFORE persisting so the
			// verdict lands in revoke_reason rather than only in the log.
			//
			// The classification already existed here but lived exclusively in the
			// log line — which dies with the pod, and there has been no log
			// aggregation since the obs stack was removed. So the one fact that
			// decides what the operator must DO never survived the incident that
			// produced it. Persisting it means the verdict rides revoke_reason into
			// /internal/claude-pool/health, into the sweep's "quarantined account(s)
			// awaiting re-add" line, and into the opsagent alert — i.e. it reaches a
			// human while it still matters.
			//
			// The two causes need OPPOSITE responses, which is why guessing is
			// expensive: a second holder means someone must stop using the credential
			// (a re-add alone just gets revoked again), whereas a lost response means
			// nothing is misconfigured and a re-add is the whole fix.
			// THREE causes, not two. The original binary split treated "not a lost
			// response" as proof of a second holder, which is a non-sequitur — it
			// is only proof that WE did not lose a rotation. On 2026-08-18
			// ac9@yao.lu was quarantined with this verdict while no second holder
			// existed: its access token was refused 31 minutes into a life that a
			// sibling account minted 2 seconds earlier survived for 43, i.e. the
			// family was killed upstream mid-life. Asserting a second holder there
			// sent the operator hunting a person who was never there, so the bare
			// case now names its own ambiguity instead of guessing.
			verdict := "SECOND-HOLDER OR UPSTREAM REVOCATION: no indeterminate exchange preceded " +
				"this, so no rotation of ours was lost — but that does not distinguish another " +
				"holder rotating the family from Anthropic revoking it. Read the upstream detail " +
				"above before going looking for a holder."
			switch {
			case row.IndeterminateAt != nil:
				verdict = fmt.Sprintf("LOST-RESPONSE SUSPECTED: prior indeterminate exchange %s ago (%s) — "+
					"our own rotation may have landed without us reading the reply; no second holder implied.",
					time.Since(*row.IndeterminateAt).Round(time.Second),
					truncStr(row.IndeterminateReason, 80))
			case strings.Contains(caller, preExpiry401Marker):
				verdict = "REVOKED-UPSTREAM: the access token was refused while still INSIDE its own " +
					"JWT expiry and our last exchange completed cleanly, so nothing stale of ours was " +
					"re-presented and no rotation was lost. The family was invalidated upstream rather " +
					"than by anything this pool did. A re-add restores service but will NOT stop it " +
					"recurring — the question is what upstream objected to, not who else holds the token."
			}
			reason := truncStr(strings.TrimSpace(errResp.Error+" — "+errResp.Desc), 180) + " | " + verdict
			reason = truncStr(reason, 500)
			now := time.Now()
			common.DB.Model(row).Updates(map[string]interface{}{
				"revoked_at":    now,
				"revoke_reason": reason,
			})
			row.RevokedAt = &now
			row.RevokeReason = reason
			recordExchange(row, caller, "invalid_grant", started, reason)
			log.Printf("claude-refresh: %s: QUARANTINED caller=%s — %s; re-add with a fresh `claude auth login` required",
				row.Email, caller, reason)
			return "", fmt.Errorf("token refresh failed: %s (account quarantined — re-add required)", reason)
		}
		if errResp.Error != "" {
			recordExchange(row, caller, "error:"+errResp.Error, started, errResp.Desc)
			return "", fmt.Errorf("token refresh failed: %s — %s", errResp.Error, errResp.Desc)
		}
		recordExchange(row, caller, fmt.Sprintf("http_%d", resp.StatusCode), started,
			strings.TrimSpace(string(raw[:min(len(raw), 200)])))
		return "", fmt.Errorf("token refresh HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil || tok.AccessToken == "" {
		// Include what actually came back. The bare "invalid response body" sent
		// an operator hunting a parser bug and then the relay, when the body said
		// plainly it was HTML from the wrong endpoint. Content-Type + a snippet
		// makes a wrong-URL or throttled-upstream answer obvious on sight.
		ct := resp.Header.Get("Content-Type")
		snippet := strings.TrimSpace(string(raw[:min(len(raw), 160)]))
		// Same class as a lost response: a 200 means the family rotated, and if
		// we cannot read the new credential out of it, we no longer hold it.
		markIndeterminate(row, caller, started,
			fmt.Sprintf("200 unparseable (content-type=%q): %s", ct, snippet))
		return "", fmt.Errorf("token refresh: HTTP 200 but unparseable body (url=%s, content-type=%q): %s",
			refreshURL, ct, snippet)
	}

	// Persist updated access token (and new refresh token if rotated).
	//
	// EVERY LINE BELOW IS POST-ROTATION. Anthropic rotated the family the instant
	// it answered 200, so a failure from here on is exactly as destructive as a
	// lost response: we are holding a credential the server has already
	// superseded. Until 2026-08-18 all three failure paths here were SILENT —
	// the access-token encrypt error returned the token without persisting it,
	// the rotated refresh token's encrypt error was dropped on the floor with
	// `_`, and the UPDATE's error was never checked at all. A lost rotation was
	// therefore indistinguishable from a clean one, the row kept a bumped
	// rotated_at and kept passing probes, and the NEXT exchange took the blame —
	// with a confident "SECOND-HOLDER SUSPECTED" verdict naming a person who did
	// not exist. markIndeterminate is precisely the right marker for all three:
	// it says "the family may have moved upstream without us", and it flips the
	// eventual quarantine verdict to LOST-RESPONSE, which is the truth.
	newEnc, err := common.EncryptGrant(tok.AccessToken)
	if err != nil {
		markIndeterminate(row, caller, started,
			fmt.Sprintf("200 but the new access token could not be encrypted: %v", err))
		return "", fmt.Errorf("token refresh indeterminate (200, access token unstorable): %w", err)
	}
	now := time.Now()
	updates := map[string]interface{}{
		"value_encrypted": newEnc,
		// A successful exchange proves the family is alive — clear any stale
		// quarantine (e.g. a row re-added out-of-band).
		"revoked_at":    nil,
		"revoke_reason": "",
		// The true rotation clock the sweep damps on. See ClaudeQuotaToken.
		"rotated_at": now,
	}
	if tok.RefreshToken != "" && tok.RefreshToken != refreshTok {
		newRefEnc, encErr := common.EncryptGrant(tok.RefreshToken)
		if encErr != nil || newRefEnc == "" {
			// Storing the new ACCESS token while silently keeping the OLD refresh
			// token is the worst outcome on offer: the row looks freshly rotated
			// and probes keep succeeding for the access token's whole life, while
			// the stored refresh token is already dead upstream. The failure then
			// surfaces up to an hour later, on an unrelated caller, with every
			// local signal saying the last rotation was clean.
			if encErr == nil {
				encErr = errors.New("encrypt returned empty ciphertext")
			}
			markIndeterminate(row, caller, started,
				fmt.Sprintf("200 but the rotated refresh token could not be stored: %v", encErr))
			return "", fmt.Errorf("token refresh indeterminate (200, rotated refresh token unstorable): %w", encErr)
		}
		updates["refresh_token_encrypted"] = newRefEnc
	}
	if err := common.DB.Model(row).Updates(updates).Error; err != nil {
		markIndeterminate(row, caller, started,
			fmt.Sprintf("200 but the rotation could not be persisted: %v", err))
		return "", fmt.Errorf("token refresh indeterminate (200, persist failed): %w", err)
	}
	// Only now is the in-memory row true. ValueEncrypted especially: leaving it
	// stale made this row claim a value the DB no longer held, which is the exact
	// input the collapse guard above compares against.
	row.RotatedAt = &now
	row.ValueEncrypted = newEnc
	if enc, ok := updates["refresh_token_encrypted"].(string); ok {
		row.RefreshTokenEncrypted = enc
	}
	row.RevokedAt, row.RevokeReason = nil, ""
	recordExchange(row, caller, "ok", started, "")
	return tok.AccessToken, nil
}

const (
	quotaCacheTTL = 5 * time.Minute
	// nearExhaustCeiling is the EXHAUSTION VALVE for per-user routing: an
	// account at/above it on either window drops to the last-resort band, so a
	// heavy user pinned to one account degrades to a sibling instead of hard
	// -failing while other accounts sit idle. Availability beats pinning.
	//
	// Package-level because PLACEMENT reads it too (claude_balance.go). The two
	// must agree: an account the valve will never select must not be given
	// users, or they end up homed somewhere they can never actually egress from.
	nearExhaustCeiling = 92.0
	quotaFetchTimeout  = 20 * time.Second
	// refreshExchangeTimeout bounds the OAuth refresh POST specifically, and is
	// deliberately far more patient than quotaFetchTimeout. The two calls fail
	// asymmetrically: abandoning a quota PROBE costs one stale snapshot, while
	// abandoning a refresh mid-flight can cost the ACCOUNT — Anthropic rotates
	// the family on receipt, so a response we hang up on is a rotation we can
	// never persist, and the next attempt presents a dead token (invalid_grant
	// → quarantine → manual `claude auth login`). Waiting a slow upstream out is
	// always cheaper than that, so this is sized to outlast a slow response
	// rather than to keep the caller snappy.
	refreshExchangeTimeout = 60 * time.Second
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
	probeBodyRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// KEEP THE BODY. It is the only place Anthropic states WHY a credential
		// was refused, and an ordinary expiry, a rotated family and a policy
		// revocation are distinguishable there and nowhere else on our side.
		// Discarding it (as this did until 2026-08-18) is exactly what left the
		// ac9@yao.lu quarantine unattributable: the row recorded "HTTP 401" and
		// the sentence that would have explained it was thrown away unread.
		return nil, fmt.Errorf("token invalid or unauthorized (HTTP %d): %s",
			resp.StatusCode, truncStr(strings.TrimSpace(string(probeBodyRaw)), 300))
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

// preExpiry401Marker rides in the refresh caller string when the access token
// that triggered the refresh was refused while still inside its own JWT expiry.
// It travels as part of `caller` deliberately: caller is already threaded into
// recordExchange, the exchange log line and the quarantine verdict, so the fact
// reaches all three without a schema change or a new parameter on every hop.
const preExpiry401Marker = "pre-expiry-401"

// refreshSnapshot fetches live quota and upserts a ClaudeQuotaSnapshot row.
// If the probe returns 401 and the row has a refresh token, it auto-refreshes
// the access token and retries once.
func refreshSnapshot(row *models.ClaudeQuotaToken, token string) (*models.ClaudeQuotaSnapshot, error) {
	snap, err := fetchClaudeUsage(token)
	if err != nil {
		// On auth failure, try to refresh if we have a refresh token.
		if strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "HTTP 403") {
			// Was the token refused BEFORE it was due to expire? A token that
			// simply aged out is routine bookkeeping; one refused mid-life means
			// the family was invalidated under us, and that is the difference
			// between "re-add it" and "find out what upstream objected to". It
			// MUST be decided here: once the refresh has failed, the expiry of
			// the token that actually got the 401 is no longer recoverable.
			caller := "snapshot-probe"
			if exp := jwtExpiry(token); !exp.IsZero() && time.Now().Before(exp) {
				caller += "(" + preExpiry401Marker + ")"
				reason := fmt.Sprintf("refused with %s of its own life left (exp %s): %v",
					time.Until(exp).Round(time.Second), exp.UTC().Format(time.RFC3339), err)
				log.Printf("claude-quota: %s: access token REFUSED with %s of its own life left "+
					"(exp %s) — the family was invalidated upstream, not by expiry: %v",
					row.Email, time.Until(exp).Round(time.Second),
					exp.UTC().Format(time.RFC3339), err)
				// Persist it. Until now this fact reached only the log — and, if a
				// quarantine happened to follow, revoke_reason. A pre-expiry 401
				// whose refresh then succeeds was logged and forgotten, which is
				// the case that most needs to be seen: it means something else is
				// touching the family while the account still works.
				at := time.Now()
				common.DB.Model(row).Updates(map[string]interface{}{
					"pre_expiry_401_at":     at,
					"pre_expiry_401_reason": truncStr(reason, 500),
				})
				row.PreExpiry401At, row.PreExpiry401Reason = &at, truncStr(reason, 500)
			}
			newTok, refreshErr := tryRefreshToken(row, caller)
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
	Email string `json:"email"`
	// Label — set when this account belongs to a field box (e.g. "dublin"),
	// so /code can display and monitor it as such. Empty for every ordinary
	// pooled account.
	Label         string          `json:"label,omitempty"`
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
	// Pool-wide bench — claude-proxy saw Anthropic 401/403 this account and
	// benched it across every replica. Surfaced because a benched account still
	// reports perfectly healthy utilization headers, so without this the
	// dashboard shows a green account that is serving nobody. BenchDead means
	// the consecutive-failure threshold was reached and only a re-add clears it.
	BenchedUntil *time.Time `json:"benched_until,omitempty"`
	BenchReason  string     `json:"bench_reason,omitempty"`
	BenchDead    bool       `json:"bench_dead,omitempty"`
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
			res := quotaResult{Email: row.Email, Label: row.Label}
			// Report a standing bench alongside whatever the quota headers say —
			// the two are independent, and a benched account looks green.
			if row.BenchUntil != nil && time.Now().Before(*row.BenchUntil) {
				res.BenchedUntil = row.BenchUntil
				res.BenchReason = row.BenchReason
				res.BenchDead = row.BenchDead
			}

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
		// Label — optional field-box tag (e.g. "dublin"). Set only when this
		// account should route its Messages API + refresh traffic through
		// that box's relay (LUMID_CLAUDE_FIELD_RELAYS). Omit for a normal
		// pooled account.
		Label string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	token := strings.TrimSpace(body.Token)
	email := strings.TrimSpace(strings.ToLower(body.Email))
	refreshTok := strings.TrimSpace(body.RefreshToken)
	label := strings.TrimSpace(body.Label)

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
	row := models.ClaudeQuotaToken{Email: email, ValueEncrypted: enc, Label: label}
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
	// It is equally the documented recovery path for a pool-wide bench (the alert
	// claude-proxy prints says "re-add the account to restore it"), so clear that
	// too: `row` is freshly built, so these columns assign their zero values.
	// "label" is only included in the update set when this request actually
	// supplied one — an unrelated re-add (e.g. refresh-token rotation) with no
	// label field must not silently wipe an existing field-box tag.
	updateCols := []string{"value_encrypted", "refresh_token_encrypted", "updated_at", "revoked_at", "revoke_reason",
		"bench_until", "bench_reason", "bench_dead"}
	if label != "" {
		updateCols = append(updateCols, "label")
	}
	if err := common.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.AssignmentColumns(updateCols),
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
			"label": label,
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

// AdminClaudeTokenLabel updates ONLY a pooled account's field-box Label.
//
// PATCH /api/v1/admin/claude-token/:email  {"label": "denmark"}  (RequireSuperAdmin)
//
// Moving an account between field boxes previously meant re-adding it through
// /code, which means re-running `claude auth login` and pasting OAuth tokens —
// an absurd cost for changing one string, and one that risks rotating a
// perfectly good credential. The label is pure routing metadata; nothing about
// the token changes.
//
// An empty label is allowed and means "unlabelled": dispatch direct from the
// cluster. Callers should be aware that pointing a label at a box with no
// matching LUMID_CLAUDE_FIELD_RELAYS entry is NOT an error — claude-proxy falls
// through to direct dispatch — so the account keeps working while silently
// leaving from the wrong network. Check via_relay after any change.
func AdminClaudeTokenLabel(c *gin.Context) {
	email := strings.TrimSpace(strings.ToLower(c.Param("email")))
	if email == "" {
		fail(c, http.StatusBadRequest, 1400, "email required")
		return
	}
	var body struct {
		Label *string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Label == nil {
		fail(c, http.StatusBadRequest, 1400, `body must be {"label": "<box>"} ("" to unlabel)`)
		return
	}
	label := strings.TrimSpace(*body.Label)
	if len(label) > 64 {
		fail(c, http.StatusBadRequest, 1400, "label too long (max 64)")
		return
	}
	var row models.ClaudeQuotaToken
	if err := common.DB.Where("email = ?", email).First(&row).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "account not found: "+email)
		return
	}
	prev := row.Label
	if err := common.DB.Model(&row).Update("label", label).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "update label: "+err.Error())
		return
	}
	_, known := fieldRelays[label]
	log.Printf("claude-token label: %s %q -> %q (relay configured: %v)", email, prev, label, known || label == "")
	ok(c, "ok", gin.H{
		"email": email, "label": label, "previous": prev,
		// Surfaced so a caller can see immediately whether this label actually
		// routes, rather than discovering it later from via_relay.
		"relay_configured": known || label == "",
	})
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
// hrwScore is the rendezvous-hashing (HRW) weight for a (user, account) pair,
// uniformly distributed in [0,1) and stable for the life of both identifiers.
//
// Rendezvous rather than `index % len(accounts)` on purpose: modulo reshuffles
// EVERY user the moment an account is added or removed, which would move the
// whole org's traffic to new IPs at once — the exact "many identities changing
// origin together" signal the field-box work exists to avoid. HRW moves only
// ~1/N of users when the pool changes.
//
// It is also stateless, so claude-proxy's two replicas agree without sharing a
// round-robin counter.
func hrwScore(userSub, email string) float64 {
	h := sha256.Sum256([]byte(userSub + "\x00" + strings.ToLower(email)))
	// Top 53 bits → exactly representable as float64 in [0,1).
	return float64(binary.BigEndian.Uint64(h[:8])>>11) / float64(uint64(1)<<53)
}

// InternalClaudeAccountBench records a pool-wide cooldown for a pooled account,
// reported by claude-proxy when Anthropic returned 401/403 for it.
//
// Why this lives here rather than in the proxy: the proxy's bench is an
// in-process map, so with CLAUDE_PROXY_REPLICAS=2 only the pod that observed the
// failure stopped using the account. The sibling kept leasing it and kept
// presenting the same bad credential to Anthropic — the exact re-probing that
// claude-proxy's authFailCooldown was written to prevent, and that hardens a
// suspension rather than containing it. Identity is where every replica already
// agrees on pool state, so the bench belongs here.
//
// seconds <= 0 releases the bench, including a `dead` one — the proxy only ever
// sends seconds<=0 from one call site (main.go, ModifyResponse), gated on an
// ACTUAL non-error response from api.anthropic.com for that account
// (resp.StatusCode < 400) via noteAccountSuccess. That is unfalsifiable proof
// the credential is live: a truly dead/revoked token cannot produce a 200.
//
// This used to be a one-way ratchet ("dead bench held; re-add the account to
// restore it"), on the theory that a full 3-strike streak was strong enough
// evidence to require a human before trusting the account again. Reversed
// 2026-08-19 after it caused a real outage: ac2@nati hit a false 3-streak
// during a token-refresh race (three probes all replayed the SAME stale
// sticky-cached access token — see the leaseByKey comment in claude-proxy —
// while fresh leases on the account kept succeeding the whole time), got
// marked bench_dead at 17:02:14, and then served a real 200 thirty-six seconds
// later and hundreds more overnight. Because the dashboard had no way to ever
// un-say "dead — re-add", an operator reading it hours later, with no way to
// see the overnight successes, deleted the (perfectly healthy) account —
// collapsing the pool to one already-quota-exhausted account and taking
// lum.id/claude down. A proven-live credential must not stay flagged dead.
// Benches are still extend-only for EXTENDING (seconds>0), so a short probe
// bench from one replica can never shorten a longer one already set by the
// other — that part is unchanged.
func InternalClaudeAccountBench(c *gin.Context) {
	var body struct {
		Email   string `json:"email"`
		Seconds int    `json:"seconds"`
		Dead    bool   `json:"dead"`
		Reason  string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" {
		fail(c, http.StatusBadRequest, 1400, "email required")
		return
	}

	var row models.ClaudeQuotaToken
	if err := common.DB.Where("email = ?", email).First(&row).Error; err != nil {
		fail(c, http.StatusNotFound, 1404, "no such pooled account")
		return
	}

	if body.Seconds <= 0 {
		wasDead := row.BenchDead
		common.DB.Model(&row).Updates(map[string]interface{}{
			"bench_until": nil, "bench_reason": "", "bench_dead": false,
		})
		if wasDead {
			log.Printf("claude-pool: %s bench_dead CLEARED — proxy reported a live success, overriding the earlier dead verdict", email)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "benched": false})
		return
	}

	until := time.Now().Add(time.Duration(body.Seconds) * time.Second)
	// Extend-only: never let a 30s probe bench from one replica cut short a 6h
	// dead bench already recorded by the other.
	if row.BenchUntil != nil && row.BenchUntil.After(until) {
		until = *row.BenchUntil
	}
	reason := strings.TrimSpace(body.Reason)
	if len(reason) > 512 {
		reason = reason[:512]
	}
	updates := map[string]interface{}{"bench_until": until, "bench_reason": reason}
	if body.Dead {
		updates["bench_dead"] = true
	}
	if err := common.DB.Model(&row).Updates(updates).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist bench: "+err.Error())
		return
	}
	if body.Dead && !row.BenchDead {
		log.Printf("claude-pool: %s BENCHED pool-wide until %s (%s) — re-add the account to restore it",
			email, until.Format(time.RFC3339), reason)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "benched": true, "until": until, "dead": body.Dead || row.BenchDead})
}

func InternalClaudeTokenLease(c *gin.Context) {
	var body struct {
		PreferEmail string   `json:"prefer_email"`
		UserSub     string   `json:"user_sub"`
		Exclude     []string `json:"exclude"`
	}
	_ = c.ShouldBindJSON(&body) // empty body is fine

	excluded := map[string]bool{}
	for _, e := range body.Exclude {
		excluded[strings.ToLower(strings.TrimSpace(e))] = true
	}
	prefer := strings.ToLower(strings.TrimSpace(body.PreferEmail))

	// Keep placements current: no-op unless the table is stale (assignmentTTL)
	// AND the pool is genuinely skewed. Errors are non-fatal — a stale
	// assignment still routes correctly, it is just less well balanced.
	if err := EnsureAssignments(false); err != nil {
		log.Printf("claude assignment refresh: %v", err)
	}

	var rows []models.ClaudeQuotaToken
	if err := common.DB.Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query tokens: "+err.Error())
		return
	}

	type cand struct {
		row  models.ClaudeQuotaToken
		snap *models.ClaudeQuotaSnapshot
	}
	// Why each row was passed over. A caller that gets nothing back needs to know
	// WHICH constraint bound, because the operator response is different for each:
	// quota frees itself on a rolling window, a bench expires on a timer, but a
	// QUARANTINE is terminal until a human re-adds the account. Collapsing all
	// three into one "no account with available quota" is what let a fully
	// quarantined pool masquerade as a busy one on 2026-08-13 — every user was
	// told to retry in 5 minutes, for a day, against a pool that could never
	// recover on its own.
	var nExcluded, nQuarantined, nBenched, nExhausted int

	var cands []cand
	for _, row := range rows {
		if excluded[row.Email] {
			nExcluded++
			continue
		}
		// Quarantined family — its access token dies with the refresh token,
		// so it can't serve proxy traffic. Skip until re-added.
		if row.RevokedAt != nil {
			nQuarantined++
			continue
		}
		// Benched pool-wide after Anthropic 401/403'd it for some proxy replica.
		// Honouring it here is what makes the bench apply to every replica
		// instead of only the pod that saw the failure.
		if row.BenchUntil != nil && time.Now().Before(*row.BenchUntil) {
			nBenched++
			continue
		}
		var snap models.ClaudeQuotaSnapshot
		var sp *models.ClaudeQuotaSnapshot
		if common.DB.Where("email = ?", row.Email).Order("ts DESC").First(&snap).Error == nil {
			sp = &snap
		}
		// Skip accounts that are unusable on a fresh snapshot: severity=critical
		// OR genuinely exhausted on either window (≥98%). The window check is
		// load-bearing — an account can sit at 7d=100% with severity only
		// "warning", and leasing it wastes a request that Anthropic 429s (no
		// weekly budget), which then cascades the whole retry loop. A stale
		// snapshot falls through to the re-probe below.
		// An exhausted snapshot outlives quotaCacheTTL (see
		// exhaustedSnapshotStillTrue). Without this, a stale-but-still-true
		// exhausted row fell through to the live re-probe below, so slowing the
		// background sweep would only have relocated those probes onto the lease
		// path — inline, on a user's latency, and just as synthetic.
		if snapshotIsExhausted(sp, time.Now()) {
			nExhausted++
			continue
		}
		cands = append(cands, cand{row, sp})
	}

	// Order (ascending key, lowest picked first): "use it or lose it", driven by
	// the SCARCE window — the 7d weekly budget.
	//   1. prefer_email — explicit stickiness (the proxy also caches leases
	//      per-user for prompt-cache locality; honor a real match).
	//   2. Among usable accounts (both windows below the ceiling), prefer the one
	//      whose 7d window resets SOONEST: its unused weekly allocation is wiped
	//      at that reset and can never be reclaimed, so drain the nearest-due
	//      weekly budget first. The 5h window refreshes every few hours, so its
	//      tail-waste is negligible next to a week's budget — it's only a
	//      tiebreaker when two accounts share a 7d reset.
	//   3. Near-exhausted on EITHER window (≥ ceiling) → back: 7d-spent means no
	//      weekly budget left; 5h-spent means it 429s immediately this window
	//      (it re-enters when its 5h resets). Ordered least-spent-first.
	//   4. No snapshot → probe last.
	// The key packs these into disjoint numeric bands so the ordering is total.
	// nearExhaustCeiling is package-level (see below) so PLACEMENT can honour
	// the same threshold this valve enforces. When only the valve knew about
	// it, placement kept homing users onto an account lease-time would always
	// refuse, and those users silently egressed from someone else's box.
	// Reset-bias tuning. Only accounts below resetBiasMaxPct on the 7d window
	// are worth pulling extra users onto (above it there is little to reclaim,
	// and it would race the exhaustion valve).
	const (
		resetBiasWindowHrs = 12.0
		resetBiasMaxPct    = 70.0
	)
	sortKey := func(cd cand) float64 {
		if cd.row.Email == prefer {
			return -1
		}
		if cd.snap == nil {
			return 2e9 // probe cost — behind everything with a snapshot
		}
		s := cd.snap
		// Band 3: near-exhausted on either window — last resort, least-spent first.
		if s.FiveHourPct >= nearExhaustCeiling || s.SevenDayPct >= nearExhaustCeiling {
			worst := s.FiveHourPct
			if s.SevenDayPct > worst {
				worst = s.SevenDayPct
			}
			return 1e9 + worst
		}
		// ── Band 2 (primary): per-user HRW assignment ────────────────────────
		//
		// Each user has a stable "home" account, so one subscription is used by
		// a small, stable set of people from one field-box IP. The 2026-08-04
		// suspensions came from the opposite shape: 8 accounts each serving 4-6
		// distinct users, fully interleaved (see claude-proxy's incident doc).
		// Field boxes fixed the IP dimension; this fixes the identity fan-out.
		//
		// Requires user_sub. Without it (older claude-proxy that doesn't send
		// it yet) every user would hash identically and land on one account, so
		// fall through to the legacy soonest-7d-reset ordering instead — that
		// keeps behaviour correct during a staged rollout.
		if body.UserSub != "" {
			// BALANCED ASSIGNMENT (supersedes rendezvous hashing). The user's
			// account is a persisted, load-balanced placement — see
			// claude_balance.go. HRW is kept only as the fallback for a user with
			// no row yet, so a brand-new caller still gets a deterministic,
			// spread-out home instead of piling onto whoever sorts first.
			if want := assignedAccount(body.UserSub); want != "" {
				if cd.row.Email == want {
					return 50 // assigned home — ahead of everything but prefer_email
				}
				// Not home: still a valid fallback if home is excluded/benched,
				// but ranked behind it. HRW orders the fallbacks so the choice is
				// deterministic across replicas.
				return 200 + (1 - hrwScore(body.UserSub, cd.row.Email))
			}
			hrw := hrwScore(body.UserSub, cd.row.Email)

			// Reset bias: a 7d window that resets with budget unspent wipes
			// that budget for good. As an account nears its reset while still
			// underused, pull a GROWING DETERMINISTIC FRACTION of users onto
			// it — never all of them at once, which would itself be a mass
			// origin change. `hrw < pull` selects a pull-sized stable subset,
			// and because hrw is fixed per (user, account) the same users move
			// first every time rather than the assignment churning.
			if !s.SevenDayReset.IsZero() && s.SevenDayPct < resetBiasMaxPct {
				hrsLeft := time.Until(s.SevenDayReset).Hours()
				if hrsLeft < 0 {
					hrsLeft = 0
				}
				if hrsLeft < resetBiasWindowHrs {
					urgency := 1 - hrsLeft/resetBiasWindowHrs // →1 at reset
					unused := (resetBiasMaxPct - s.SevenDayPct) / resetBiasMaxPct
					if pull := urgency * unused; hrw < pull {
						return 0 + (1 - hrw) // urgent band, ahead of home
					}
				}
			}
			return 100 + (1 - hrw) // home band: best HRW weight wins
		}

		// Legacy ordering (no user_sub): soonest 7d reset first. Key = seconds
		// until the 7d window resets (due-now → 0 → highest priority), with the
		// 5h reset as a sub-second tiebreaker that can never override it.
		if !s.SevenDayReset.IsZero() {
			r7 := time.Until(s.SevenDayReset).Seconds()
			if r7 < 0 {
				r7 = 0
			}
			r5 := 0.0
			if !s.FiveHourReset.IsZero() {
				if v := time.Until(s.FiveHourReset).Seconds(); v > 0 {
					r5 = v
				}
			}
			return r7 + r5/1e6 // r7 ∈ [0, ~604800]; r5/1e6 ≤ 0.018 → tiebreak only
		}
		// Usable but no 7d reset timestamp — behind timed accounts, ahead of
		// near-exhausted; most-7d-headroom first.
		return 9e8 + s.SevenDayPct
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
		// Never lease a credential that is about to expire. claude-proxy now caps
		// its lease cache at the token's own expiry, so handing out a nearly-dead
		// token would give it a lease that is stale on arrival and send it back
		// here on the very next request — a lease storm in place of the 401 storm
		// this pairing exists to remove. Rotate first (coalesced, so a burst of
		// callers still produces one exchange) and lease the result.
		if tokenExpiringSoon(token) {
			newTok, err := tryRefreshToken(&row, "lease")
			if err != nil {
				log.Printf("claude-lease: %s: token near expiry and refresh failed: %v — skipping", row.Email, err)
				continue
			}
			token = newTok
		}
		snap := cd.snap
		if snap == nil || time.Since(snap.Ts) >= quotaCacheTTL {
			fresh, err := refreshSnapshot(&row, token)
			if err != nil {
				continue // dead token with no working refresh — skip
			}
			snap = fresh
			if snap.Severity == "critical" || snap.FiveHourPct >= 98 || snap.SevenDayPct >= 98 {
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
		// access_token_exp lets claude-proxy bound its lease cache by the life of
		// the credential inside it rather than by a fixed TTL. Without it a cached
		// lease kept presenting a token this service had since rotated — every
		// rotation invalidates the previous access token immediately — so each
		// rotation produced a burst of "OAuth access token has been revoked" 401s
		// from whichever leases were still holding the old one. Zero when the
		// token carries no parseable exp; the proxy falls back to its fixed TTL.
		var tokenExp int64
		if exp := jwtExpiry(token); !exp.IsZero() {
			tokenExp = exp.Unix()
		}
		// Mark the account in use, so the background loops know it is not
		// dormant. Throttled: dormancy is judged in hours, so a write per lease
		// would be pure churn on the row claude-proxy's bench reporter already
		// writes to most often.
		if row.LastLeasedAt == nil || time.Since(*row.LastLeasedAt) > leaseStampThrottle {
			at := time.Now()
			common.DB.Model(&row).Update("last_leased_at", at)
			row.LastLeasedAt = &at
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"email":            row.Email,
				"access_token":     token,
				"access_token_exp": tokenExp,
				"five_hour_pct":    snap.FiveHourPct,
				"seven_day_pct":    snap.SevenDayPct,
				"severity":         snap.Severity,
				"label":            row.Label,
			},
		})
		return
	}

	// Nothing leasable. Say which constraint bound, so the caller can tell a
	// wait-it-out condition from one that needs a human.
	//
	// A quarantine is only the BINDING constraint when nothing else could have
	// recovered on its own: if even one account is merely quota-exhausted or
	// benched, waiting genuinely does help and the retryable wording is correct.
	// Only when every non-excluded account is quarantined is retrying futile.
	// The leading `pool_state=` token is the MACHINE contract with claude-proxy;
	// the prose after it is for humans reading logs. Keep them separate: the
	// counts that follow necessarily mention every constraint by name
	// ("quarantined=0"), so a consumer matching on a bare word would classify a
	// perfectly ordinary dry pool as a quarantined one. Match the token, not the
	// vocabulary.
	breakdown := fmt.Sprintf("total=%d quarantined=%d benched=%d exhausted=%d excluded=%d",
		len(rows), nQuarantined, nBenched, nExhausted, nExcluded)
	if nQuarantined > 0 && nBenched == 0 && nExhausted == 0 {
		// Deliberately does NOT contain "available quota": claude-proxy's legacy
		// path keys off that phrase, and this state must not reach users as a
		// quota problem they can retry away.
		log.Printf("claude-lease: pool UNAVAILABLE — every account quarantined (%s); re-add with a fresh `claude auth login`", breakdown)
		fail(c, http.StatusServiceUnavailable, 1503,
			"pool_state=quarantined no pooled account usable: all accounts quarantined — operator re-add required ("+breakdown+")")
		return
	}
	// SATURATION, not exhaustion. If the only reason nothing was leasable is
	// that the CALLER excluded every account — each at its per-account in-flight
	// ceiling, or locally benched by the proxy — then quota is untouched and the
	// accounts are merely busy. A freed slot returns in SECONDS.
	//
	// Reporting this as quota_exhausted told users "out of quota — retry in ~5
	// minutes" while the pool's own snapshots read 8% and 25% of their 5h
	// windows at severity normal (measured 2026-08-16, breakdown
	// "exhausted=0 excluded=2"). Wrong cause, and retry advice off by ~60x, on a
	// condition the caller could not act on because nothing was exhausted. The
	// real constraint was 2 accounts x 4 in-flight = 8 concurrent slots org-wide.
	//
	// Deliberately omits "available quota" for the same reason the quarantine
	// branch does — but note that alone is NOT sufficient: claude-proxy's
	// classifier also matches a bare "1503", which every refusal here carries.
	// It ranks this state out explicitly (isPoolSaturated), so this change and
	// claude-proxy cp-<sha> are a matched pair. Against an older proxy this
	// still reads as a quota problem — no worse than before, just not yet fixed.
	if nExcluded > 0 && nQuarantined == 0 && nBenched == 0 && nExhausted == 0 {
		fail(c, http.StatusServiceUnavailable, 1503,
			"pool_state=saturated no pooled account currently free: every candidate is at its "+
				"in-flight ceiling — retry shortly ("+breakdown+")")
		return
	}
	fail(c, http.StatusServiceUnavailable, 1503,
		"pool_state=quota_exhausted no pooled account with available quota ("+breakdown+")")
}

// AdminClaudeUserUsage lists per-user pool consumption over the fixed 5h/7d
// windows anchored in claude_pool_windows — the per-PAT/user counterpart of
// the account quota table.
//
// GET /api/v1/admin/claude-user-usage  (RequireAdmin)
func AdminClaudeUserUsage(c *gin.Context) {
	now := time.Now().UTC()
	far := now.AddDate(100, 0, 0)

	// One row per user who has ever committed a claude_proxy charge — a
	// claude_pool_windows row only exists once ClaudePoolCommit has run,
	// which only happens right after a usage_events row for that user was
	// created, so the INNER JOIN below never drops a real user.
	//
	// five_eff/seven_eff are each either the LIVE anchor (still within its
	// window) or the far-future sentinel — mirrors ClaudePoolUsage's
	// per-user logic, just computed once for the whole table instead of a
	// query per user. Model inclusion is left broader than poolCapApplies
	// deliberately (this admin table intentionally surfaces ALL claude_proxy
	// spend per user, not just what counts against the pool cap).
	rows := []struct {
		UserSub       string
		Email         string
		FiveTokens    int
		SevenTokens   int
		RawInput      int
		RawOutput     int
		RawCacheRead  int
		RawCacheWrite int
		CostCents     int
		Reqs          int
		LastTs        time.Time
	}{}
	// Model-weighted, using the SAME shared expression the gate uses. If this
	// table and ClaudePoolUsage disagreed about how much someone has drawn, the
	// dashboard would show a user comfortably inside their cap while the proxy
	// 429s them — the same class of bug as the 5h/4h window skew.
	wsql := common.ClaudeWeightedTokensSQL("ue.")
	err := common.DB.Raw(fmt.Sprintf(`
		SELECT ue.user_sub                                                              AS user_sub,
		       COALESCE(u.email, ue.user_sub)                                           AS email,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.five_eff  THEN %[1]s ELSE 0 END), 0) AS five_tokens,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN %[1]s ELSE 0 END), 0) AS seven_tokens,
		       -- RAW totals alongside the weighted ones, so the quota number can be
		       -- reconciled against Anthropic's own record instead of taken on trust.
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN ue.input_tokens ELSE 0 END), 0)         AS raw_input,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN ue.output_tokens ELSE 0 END), 0)        AS raw_output,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN ue.cache_read_tokens ELSE 0 END), 0)    AS raw_cache_read,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN ue.cache_creation_tokens ELSE 0 END), 0) AS raw_cache_write,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN ue.cost_cents ELSE 0 END), 0)                      AS cost_cents,
		       COALESCE(SUM(CASE WHEN ue.ts >= w.seven_eff THEN 1 ELSE 0 END), 0)                                  AS reqs,
		       MAX(ue.ts)                                                               AS last_ts
		FROM   usage_events ue
		JOIN  (SELECT user_sub,
		              CASE WHEN five_hour_anchor + INTERVAL ? SECOND > ? THEN five_hour_anchor ELSE ? END AS five_eff,
		              CASE WHEN seven_day_anchor + INTERVAL 7 DAY > ? THEN seven_day_anchor ELSE ? END AS seven_eff
		       FROM   claude_pool_windows) w ON w.user_sub = ue.user_sub
		LEFT JOIN users u ON u.id = ue.user_sub
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= LEAST(w.five_eff, w.seven_eff)
		GROUP  BY ue.user_sub, u.email`, wsql),
		int(common.ClaudePoolShortWindow().Seconds()), now, far, now, far).Scan(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query usage: "+err.Error())
		return
	}

	// Per-model breakdown, anchor-bounded to the 7d window (same seven_eff
	// shape as above, recomputed inline since this is a separate query).
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
		JOIN  (SELECT user_sub,
		              CASE WHEN seven_day_anchor + INTERVAL 7 DAY > ? THEN seven_day_anchor ELSE ? END AS seven_eff
		       FROM   claude_pool_windows) w ON w.user_sub = ue.user_sub
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= w.seven_eff
		GROUP  BY ue.user_sub, ue.model`,
		now, far).Scan(&modelRows)

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

	// Anchor rows, for the reset instants — a trivial small-table read
	// (claude_pool_windows has at most one row per user who's ever used the
	// pool, PK-indexed) plus a Go-side ClaudeWindowLive per row, replacing
	// the old oldest-event query entirely.
	var anchorRows []models.ClaudePoolWindow
	common.DB.Find(&anchorRows)

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
		FiveHourReset string                `json:"five_hour_reset,omitempty"`
		SevenDayReset string                `json:"seven_day_reset,omitempty"`
		Models        map[string]modelUsage `json:"models"`
		// RAW 7d totals exactly as Anthropic reported them. five_hour_tokens and
		// seven_day_tokens above are the WEIGHTED quota unit (cache reads at a
		// tenth, model by price ratio), which is deliberately not a token count —
		// these are here so the two can be reconciled against Anthropic's record
		// rather than the quota number being taken on trust.
		RawInput      int `json:"raw_input_tokens_7d"`
		RawOutput     int `json:"raw_output_tokens_7d"`
		RawCacheRead  int `json:"raw_cache_read_tokens_7d"`
		RawCacheWrite int `json:"raw_cache_creation_tokens_7d"`
		RawTotal      int `json:"raw_total_tokens_7d"`
	}
	byUser := map[string]*userUsage{}
	for _, r := range rows {
		u, ok := byUser[r.UserSub]
		if !ok {
			u = &userUsage{Email: r.Email, Models: map[string]modelUsage{}}
			byUser[r.UserSub] = u
		}
		u.FiveHour = r.FiveTokens
		u.SevenDay = r.SevenTokens
		u.RawInput, u.RawOutput = r.RawInput, r.RawOutput
		u.RawCacheRead, u.RawCacheWrite = r.RawCacheRead, r.RawCacheWrite
		u.RawTotal = r.RawInput + r.RawOutput + r.RawCacheRead + r.RawCacheWrite
		u.CostCents7d = r.CostCents
		u.Requests = r.Reqs
		u.LastTs = r.LastTs
	}
	// Attach per-user reset times from the anchor table.
	for _, win := range anchorRows {
		u, ok := byUser[win.UserSub]
		if !ok {
			continue
		}
		// MUST be the configured short window, not a literal. This read is the
		// third of the three sites ClaudePoolShortWindow warns must never
		// disagree, and it was the one still hardcoded at 5h after the window
		// moved to 4h — so the admin usage table reported resets up to an hour
		// beyond the window that actually governs the budget (a user 23 min into
		// their window was shown "resets in 4h37m", which a 4h window can never
		// produce). Only the displayed reset was wrong; enforcement and the anchor
		// roll already used the configured length.
		if live, resetAt := common.ClaudeWindowLive(win.FiveHourAnchor, common.ClaudePoolShortWindow(), now); live {
			u.FiveHourReset = resetAt.UTC().Format(time.RFC3339)
		}
		if live, resetAt := common.ClaudeWindowLive(win.SevenDayAnchor, 7*24*time.Hour, now); live {
			u.SevenDayReset = resetAt.UTC().Format(time.RFC3339)
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
			// The short window is env-tunable (LUMID_QUOTA_CLAUDE_SHORT_WINDOW)
			// and is no longer 5h, so the UI must render this rather than a
			// hardcoded "5h" — otherwise the dashboard silently lies the next
			// time the window moves. The JSON keys above keep their historical
			// five_hour_* names for wire compatibility.
			"short_window_label": shortWindowLabel(),
		},
	})
}

// shortWindowLabel renders the per-user short window for display ("4h", "90m").
// Whole hours read as "4h"; anything else falls back to Go's duration string
// with the zero-value units trimmed.
func shortWindowLabel() string {
	d := common.ClaudePoolShortWindow()
	if d%time.Hour == 0 {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	if d%time.Minute == 0 {
		return strconv.Itoa(int(d/time.Minute)) + "m"
	}
	return d.String()
}

// AdminClaudeAccountUsers reports how many distinct users are homed on each
// pooled account right now, straight from claude_user_assignments — the
// ground truth the user-count cap (ClaudeMaxUsersPerAccount) enforces
// against. Exists so the cap can be verified via API instead of a raw
// production DB query.
//
// GET /api/v1/admin/claude-account-users  (RequireAdmin)
func AdminClaudeAccountUsers(c *gin.Context) {
	rows := []struct {
		Account    string
		Label      string
		UserSub    string
		Email      string
		Load7d     int64
		AssignedAt time.Time
		Reason     string
	}{}
	err := common.DB.Raw(`
		SELECT a.account                     AS account,
		       COALESCE(t.label, '')         AS label,
		       a.user_sub                    AS user_sub,
		       COALESCE(u.email, a.user_sub) AS email,
		       a.load_7d                     AS load_7d,
		       a.assigned_at                 AS assigned_at,
		       a.reason                      AS reason
		FROM   claude_user_assignments a
		LEFT JOIN users u ON u.id = a.user_sub
		LEFT JOIN claude_quota_tokens t ON t.email = a.account
		ORDER  BY a.account, a.assigned_at DESC`).Scan(&rows).Error
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query assignments: "+err.Error())
		return
	}

	type userEntry struct {
		UserSub    string    `json:"user_sub"`
		Email      string    `json:"email"`
		Load7d     int64     `json:"load_7d"`
		AssignedAt time.Time `json:"assigned_at"`
		Reason     string    `json:"reason"`
	}
	type accountGroup struct {
		Account   string      `json:"account"`
		Label     string      `json:"label,omitempty"`
		NUsers    int         `json:"n_users"`
		OverCap   bool        `json:"over_cap"`
		TotalLoad int64       `json:"total_load_7d"`
		Users     []userEntry `json:"users"`
	}
	byAccount := map[string]*accountGroup{}
	order := []string{}
	for _, r := range rows {
		g, ok := byAccount[r.Account]
		if !ok {
			g = &accountGroup{Account: r.Account, Label: r.Label}
			byAccount[r.Account] = g
			order = append(order, r.Account)
		}
		g.Users = append(g.Users, userEntry{
			UserSub: r.UserSub, Email: r.Email, Load7d: r.Load7d,
			AssignedAt: r.AssignedAt, Reason: r.Reason,
		})
		g.NUsers++
		g.TotalLoad += r.Load7d
	}

	// Deterministic account-name order (insertion sort — small N, avoids a new import).
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && order[j] < order[j-1]; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}

	userCap := common.ClaudeMaxUsersPerAccount()
	overCapAccounts := 0
	groups := make([]accountGroup, 0, len(order))
	for _, acct := range order {
		g := byAccount[acct]
		if userCap > 0 && g.NUsers > userCap {
			g.OverCap = true
			overCapAccounts++
		}
		groups = append(groups, *g)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"accounts":          groups,
			"configured_cap":    userCap,
			"over_cap_accounts": overCapAccounts,
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

// minHealthyPoolAccounts is the floor below which the sweep warns. Two is not a
// comfort level, it is the point at which losing one more account leaves the
// pool with a single credential serving every user.
const minHealthyPoolAccounts = 2

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

// tokenExpiringSoon reports whether an access token is too close to expiry to be
// worth handing back in place of a rotation. An opaque token (no parseable exp)
// is treated as usable — the collapse guard's other arm already proved it was
// freshly written by another refresher.
func tokenExpiringSoon(rawToken string) bool {
	exp := jwtExpiry(rawToken)
	return !exp.IsZero() && time.Until(exp) < accessTokenMinLife
}

// accessTokenMinLife is the headroom a leased access token must still have. It
// bounds both the collapse guard above and the lease TTL claude-proxy derives
// from `access_token_exp`, so a lease can never outlive the credential inside it.
const accessTokenMinLife = 5 * time.Minute

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

// claudeIdleAfter / claudeIdleHeartbeat govern DORMANCY — the pool's answer to
// the fact that every refresh exchange is a draw at the lost-response window
// that permanently kills a token family.
//
// Measured 2026-08-19: the sweep exchanged every account at every 45-minute
// tick, ~32 a day each, and ac5@mlsys took its full share while serving ZERO
// requests all day. The two gates that look like they prevent that — skip if the
// token has >2×tokenRefreshInterval of life left, damp if rotated within
// tokenRefreshInterval/2 — never fire, because the access token does not live
// that long. So an idle account was paying full quarantine exposure for a
// credential nobody was going to use.
//
// A dormant account is skipped by BOTH background loops. Gating only the token
// sweep would make things worse, not better: the snapshot sweeper probes with
// the ACCESS token every few minutes, so letting it expire would turn a
// 45-minute rotation into a 401-driven one every snapshot cycle.
//
// The heartbeat is what bounds the two risks of doing this at all:
//
//   - a refresh token left unused indefinitely might expire on its own (we do
//     not know Anthropic's TTL, and finding out by losing an account is the
//     wrong experiment);
//   - a standby account that has silently died is worth nothing, and dormancy
//     delays discovering it.
//
// Exchanging at least every claudeIdleHeartbeat caps both: the family is
// exercised well inside any plausible TTL, and "this standby still works" is
// never more than one heartbeat stale. At the defaults that is 4 exchanges a
// day instead of 32 — an 8× cut in exposure for the accounts that were getting
// nothing for it — while a busy account is completely unaffected.
var (
	claudeIdleAfter     = envDurationOr("CLAUDE_POOL_IDLE_AFTER", 2*time.Hour)
	claudeIdleHeartbeat = envDurationOr("CLAUDE_POOL_IDLE_HEARTBEAT", 6*time.Hour)
)

// accountIsDormant reports whether the background loops should leave an account
// alone this tick. Never true for an account in recent use, never true for one
// that has never been exchanged, and never true once the heartbeat is due.
//
// Self-healing: the lease path stamps LastLeasedAt, so an account wakes the
// instant it is used. The cost of waking is one inline refresh plus one inline
// snapshot probe on that first lease — the path that already exists for a cold
// account, paid once instead of avoided 32 times a day.
// leaseStampThrottle bounds how often the lease path rewrites last_leased_at.
// Far below claudeIdleAfter, so throttling can never make a busy account look
// dormant.
const leaseStampThrottle = 5 * time.Minute

func accountIsDormant(row *models.ClaudeQuotaToken, now time.Time) bool {
	if row.LastLeasedAt != nil && now.Sub(*row.LastLeasedAt) < claudeIdleAfter {
		return false // in use
	}
	if row.RotatedAt == nil {
		return false // never exchanged — a new account must get its first refresh
	}
	return now.Sub(*row.RotatedAt) < claudeIdleHeartbeat
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

// snapshotRefreshInterval is how often the background sweeper looks for stale
// account quota snapshots. Kept well under quotaCacheTTL so the lease path
// (InternalClaudeTokenLease) always finds a warm snapshot and never has to pay
// a ~1-2s live re-probe inline. Inline re-probes serialize a fan-out burst and
// widen the window where healthy accounts look saturated, which surfaced as
// spurious "no pooled account with available quota" 503s on the burst tail.
const snapshotRefreshInterval = 2 * time.Minute

// StartSnapshotRefreshLoop keeps every non-revoked account's quota snapshot warm
// in the background so leases stay on the fast (~10ms) cache path. Single-sweeper
// across replicas via the shared 'cqr:sweep' lock — which also serializes with
// the token sweep, since a snapshot probe can rotate the access token on a 401
// and concurrent rotations can lose the refresh-token family.
func StartSnapshotRefreshLoop() {
	go func() {
		time.Sleep(90 * time.Second) // let startup settle (token loop waits 3m)
		for {
			refreshAllSnapshots()
			time.Sleep(snapshotRefreshInterval)
		}
	}()
}

func refreshAllSnapshots() {
	_ = common.DB.Connection(func(tx *gorm.DB) error {
		var got int
		if err := tx.Raw("SELECT GET_LOCK('cqr:sweep', 0)").Scan(&got).Error; err != nil || got != 1 {
			// Another sweep (token or snapshot) holds it — try again next tick.
			return nil
		}
		defer tx.Exec("DO RELEASE_LOCK('cqr:sweep')")
		sweepStaleSnapshots()
		return nil
	})
}

// leaseExhaustPct is the per-window utilization at which the lease path refuses
// an account outright (see InternalClaudeTokenLease). Named so the probe-
// suppression rule below cannot drift away from the rule it is reasoning about.
const leaseExhaustPct = 98.0

// exhaustedSnapshotStillTrue reports whether a snapshot showing an exhausted
// window can still be believed past quotaCacheTTL.
//
// It can, and this is the whole basis of the fix. Utilization only ever RISES
// until its window resets, and anything that could raise it is traffic — which
// would itself refresh the snapshot, because claude-proxy reports the real
// rate-limit headers off live responses roughly once a minute per account. So
// "98%, resets Saturday" is still 98%-or-worse on Thursday, and an account that
// is already excluded stays excluded. Re-probing to rediscover that costs a
// synthetic /v1/messages call and learns nothing.
//
// WHY IT MATTERS BEYOND COST. The probe is a bare Go HTTP client — no
// User-Agent, none of the Claude Code identity that account's real traffic
// carries — and it egresses from the cluster, not from the account's field
// relay. On a BUSY account that is a rounding error hidden in real traffic. On
// an idle, exhausted account it is the ONLY thing the credential does: ac9@yao.lu
// spent its last ~6 hours emitting nothing but ~90 of these before its token
// family was revoked mid-life on 2026-08-18. Suppressing them removes the
// anomaly by removing the request, which is the only honest way to remove it.
//
// Returns false for a nil snapshot (nothing known — a probe is warranted) and
// false once the reset has passed (the window rolled; go find out what is true).
func exhaustedSnapshotStillTrue(snap *models.ClaudeQuotaSnapshot, now time.Time) bool {
	if snap == nil {
		return false
	}
	spent := func(pct float64, reset time.Time) bool {
		return pct >= leaseExhaustPct && !reset.IsZero() && reset.After(now)
	}
	return spent(snap.FiveHourPct, snap.FiveHourReset) ||
		spent(snap.SevenDayPct, snap.SevenDayReset)
}

// snapshotIsExhausted reports whether sp currently excludes its account from a
// lease — either a persisted exhaustion that hasn't rolled past its reset
// (exhaustedSnapshotStillTrue) or a fresh snapshot already at leaseExhaustPct.
// Factored out of the lease-candidate loop so InternalClaudePoolHealth can
// answer "would this account actually be leased right now" the same way the
// lease path does — see that endpoint's doc comment. Before this existed, the
// health endpoint counted an account as healthy purely on having a live
// refresh token, so a pool sitting on ONE genuinely servable account (the rest
// quarantined or ≥98% spent) still reported `healthy:true`, and opsagent's P0
// alert — which trusts that field verbatim — never fired.
func snapshotIsExhausted(sp *models.ClaudeQuotaSnapshot, now time.Time) bool {
	if exhaustedSnapshotStillTrue(sp, now) {
		return true
	}
	return sp != nil && time.Since(sp.Ts) < quotaCacheTTL &&
		(sp.Severity == "critical" || sp.FiveHourPct >= leaseExhaustPct || sp.SevenDayPct >= leaseExhaustPct)
}

// sweepStaleSnapshots refreshes any non-revoked account whose latest snapshot is
// missing, older than (quotaCacheTTL - snapshotRefreshInterval), or past a
// window reset — i.e. anything that would otherwise force the lease path to
// re-probe live. Probes are staggered to avoid a shared-egress IP burst.
func sweepStaleSnapshots() {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Where("revoked_at IS NULL").Find(&rows).Error; err != nil {
		log.Printf("snapshot-refresh-loop: db query failed: %v", err)
		return
	}
	staleAfter := quotaCacheTTL - snapshotRefreshInterval // 3m at defaults
	now := time.Now()
	for _, row := range rows {
		// Dormant accounts are skipped here too, and this arm is the load-bearing
		// one. This loop probes with the ACCESS token; if the token sweep has
		// stopped refreshing a dormant account, probing it would 401 and trigger
		// a refresh every few minutes — turning an 8× reduction into a large
		// increase. The snapshot exists to keep the lease path off the slow path,
		// and an account nobody leases has no lease path to keep warm.
		if accountIsDormant(&row, now) {
			continue
		}
		var snap models.ClaudeQuotaSnapshot
		if common.DB.Where("email = ?", row.Email).Order("ts DESC").First(&snap).Error == nil {
			resetPassed := (!snap.FiveHourReset.IsZero() && now.After(snap.FiveHourReset)) ||
				(!snap.SevenDayReset.IsZero() && now.After(snap.SevenDayReset))
			// Known out of quota, window not yet rolled: the answer cannot have
			// changed, so do not go ask for it again.
			if exhaustedSnapshotStillTrue(&snap, now) {
				continue
			}
			if time.Since(snap.Ts) < staleAfter && !resetPassed {
				continue // still warm — leave it (also spares a rotation)
			}
		}
		token, err := common.DecryptGrant(row.ValueEncrypted)
		if err != nil {
			log.Printf("snapshot-refresh-loop: %s: decrypt err: %v — skipping", row.Email, err)
			continue
		}
		if _, err := refreshSnapshot(&row, token); err != nil {
			log.Printf("snapshot-refresh-loop: %s: probe failed: %v", row.Email, err)
		}
		time.Sleep(2 * time.Second) // stagger — avoid a shared-egress IP-burst 429
	}
}

func sweepAllTokens() {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.
		Where("refresh_token_encrypted != '' AND revoked_at IS NULL").
		Find(&rows).Error; err != nil {
		log.Printf("token-refresh-loop: db query failed: %v", err)
		return
	}
	// Name them. A bare count told an operator that something was wrong but not
	// which account, so diagnosing a thin pool meant inferring identities from
	// traffic going quiet in the proxy logs.
	var quarantinedRows []models.ClaudeQuotaToken
	common.DB.Where("revoked_at IS NOT NULL").Find(&quarantinedRows)
	if len(quarantinedRows) > 0 {
		parts := make([]string, 0, len(quarantinedRows))
		for _, q := range quarantinedRows {
			parts = append(parts, fmt.Sprintf("%s (%s)", q.Email, q.RevokeReason))
		}
		log.Printf("token-refresh-loop: %d quarantined account(s) awaiting re-add: %s",
			len(quarantinedRows), strings.Join(parts, "; "))
	}

	// A pool this thin is one bad credential away from a total outage, and the
	// symptom (every user pinned to one account) is invisible from any single
	// request. Warn on the sweep so it lands before the outage does.
	//
	// Refreshable alone undercounts the risk: an account can hold a live
	// refresh token and still be unable to take a lease right now because it's
	// ≥98% spent on its 5h/7d window (snapshotIsExhausted — the same check
	// InternalClaudePoolHealth and the lease path use). Report servable so this
	// line and /internal/claude-pool/health can't tell two different stories.
	now := time.Now()
	exhaustedNow := 0
	for _, row := range rows {
		var snap models.ClaudeQuotaSnapshot
		if common.DB.Where("email = ?", row.Email).Order("ts DESC").First(&snap).Error == nil &&
			snapshotIsExhausted(&snap, now) {
			exhaustedNow++
		}
	}
	if servable := len(rows) - exhaustedNow; servable < minHealthyPoolAccounts {
		log.Printf("token-refresh-loop: WARNING pool is down to %d servable account(s) "+
			"(%d refreshable, %d exhausted; want servable >= %d) — re-add quarantined accounts "+
			"or wait out the exhausted window(s)", servable, len(rows), exhaustedNow, minHealthyPoolAccounts)
	}

	if len(rows) == 0 {
		return
	}
	for _, row := range rows {
		// Damping: if any refresher (a lease, a dashboard probe, the other
		// replica's earlier sweep) rotated this row recently, leave it alone —
		// each rotation is a fresh chance to lose the family.
		//
		// Damps on RotatedAt, never UpdatedAt: UpdatedAt is bumped by every write
		// to the row, and the busiest writer is claude-proxy's bench reporter. On
		// UpdatedAt this check inverted under load — the accounts being benched
		// most were the ones whose proactive refresh got deferred longest, so
		// their tokens drifted to expiry and the pool rediscovered it as a 401
		// burst. A row that has never rotated (nil) is always eligible.
		if row.RotatedAt != nil && time.Since(*row.RotatedAt) < tokenRefreshInterval/2 {
			continue
		}
		// Dormant: nobody is leasing this account, and it was exchanged recently
		// enough that the family is still being exercised. Skip the draw.
		if accountIsDormant(&row, now) {
			log.Printf("token-refresh-loop: %s: dormant (no lease in %v, rotated %v ago) — skipping; "+
				"heartbeat exchange due in %v",
				row.Email, claudeIdleAfter,
				time.Since(*row.RotatedAt).Round(time.Minute),
				(claudeIdleHeartbeat - time.Since(*row.RotatedAt)).Round(time.Minute))
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
		if _, err := tryRefreshToken(&row, "sweep"); err != nil {
			log.Printf("token-refresh-loop: %s: FAILED: %v", row.Email, err)
		} else {
			log.Printf("token-refresh-loop: %s: ok", row.Email)
		}
		time.Sleep(2 * time.Second)
	}
}
