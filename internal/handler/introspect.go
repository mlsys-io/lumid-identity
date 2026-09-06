package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
)

// lastUsedBump throttles the per-token last_used_at UPDATE (id -> last write time.Time).
var lastUsedBump sync.Map

// ── Introspection cache ──────────────────────────────────────────────────────
// Validate a token once per short TTL instead of re-running argon2id + the token/
// user SELECTs on EVERY /oauth/introspect. This is the fix for BOTH failure modes
// seen in prod: (1) the OOM-under-load (lumid-data-service floods introspect; each
// call held ~s of slow serial DB + a goroutine, piling up until the pod OOMed) and
// (2) the ~sub-second per-call latency every authed lum.id/llm request pays. Keyed
// by sha256(token). TTL is short (default 45s) so a revoked/expired token stops
// validating within the window — set INTROSPECT_CACHE_TTL_SEC=0 to disable.
type introCacheEntry struct {
	resp IntrospectResponse
	exp  time.Time
}

var (
	introCache     sync.Map // sha256hex(token) -> introCacheEntry
	introSweepOnce sync.Once
)

func introspectTTL() time.Duration {
	if s := os.Getenv("INTROSPECT_CACHE_TTL_SEC"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 45 * time.Second
}

func introCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// introCacheSweep starts one background goroutine that evicts expired entries so
// the map can't grow unbounded across the token population over time.
func introCacheSweep() {
	introSweepOnce.Do(func() {
		go func() {
			t := time.NewTicker(2 * time.Minute)
			for range t.C {
				now := time.Now()
				introCache.Range(func(k, v any) bool {
					if e, ok := v.(introCacheEntry); ok && now.After(e.exp) {
						introCache.Delete(k)
					}
					return true
				})
			}
		}()
	})
}

// IntrospectResponse follows RFC 7662 with lum.id-specific extras.
// Anyone calling introspect gets the same shape regardless of which
// token prefix went in — this is the whole point of consolidating
// auth on lum.id.
type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub,omitempty"` // canonical user id
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	// Role from the user record — "user" or "admin". Downstream
	// services (Runmesh admin UI via lum.id, etc.) read this to
	// decide whether a lum.id-issued token is allowed to hit admin
	// endpoints without an extra permission map of their own.
	Role      string   `json:"role,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Scope     string   `json:"scope,omitempty"` // space-separated, RFC 7662 shape
	ClientID  string   `json:"client_id,omitempty"`
	TokenType string   `json:"token_type,omitempty"` // pat | jwt
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Source    string   `json:"source,omitempty"` // native | legacy-lqa | legacy-runmesh
	Reason    string   `json:"reason,omitempty"` // why active=false
	// AllowOnprem — may this identity reach the SELF-HOSTED models (the GB10
	// fleet behind lumid-llm)? Resolved from the caller's effective Claude
	// pool; see ClaudeOnpremAllowedFor.
	//
	// Rides on introspection rather than on the lease because claude-proxy
	// gates the model BEFORE it leases an account, and for a self-hosted model
	// it never leases one at all.
	//
	// DELIBERATELY NOT omitempty. `false` is the restrictive verdict, and
	// omitempty would drop it from the wire — leaving the consumer unable to
	// tell "denied" from "this identity server is too old to have an opinion".
	// The consumer decodes it as a *bool and treats absent as allowed, so the
	// pair only fails open when identity genuinely predates the field.
	AllowOnprem bool `json:"allow_onprem"`
	// AllowOpenrouter — may this identity reach EXTERNALLY BILLED models?
	// Same non-omitempty reasoning as AllowOnprem, opposite default: the
	// consumer treats an absent value as DENIED, because an old identity
	// server must not be able to open a spend path.
	AllowOpenrouter bool `json:"allow_openrouter"`
	// AllowFable — may this identity use the Fable tier? Same non-omitempty
	// and fail-closed reasoning as AllowOpenrouter.
	AllowFable bool `json:"allow_fable"`
	// ClaudePoolID — the Claude account pool this identity actually draws
	// from (hint > primary > default), resolved alongside the three verdicts
	// above at no extra query cost.
	//
	// claude-proxy caches a leased pooled credential per session for up to 30
	// minutes. That lease was pool-scoped WHEN ISSUED; nothing re-scopes it
	// afterwards, so a user moved between pools would keep serving from their
	// old pool's subscription for the rest of the lease. The proxy compares
	// this against the pool stamped on the lease and re-leases on a mismatch.
	//
	// omitempty is FINE here, unlike the three flags above: the consumer's
	// check is a comparison, not a verdict, and it skips the comparison when
	// either side is empty. An identity too old to send this therefore
	// degrades to today's behaviour rather than to a wrong answer.
	ClaudePoolID string `json:"claude_pool_id,omitempty"`
}

// Introspect — POST /oauth/introspect (form or JSON body).
//
// During shadow phase (config.Legacy.Enabled=true) we read LQA's
// tbl_rm_personal_access_token directly so the response is
// byte-for-byte a mirror of LQA's /api/v1/identity/introspect —
// that's the acceptance gate for Phase 1.
//
// Response envelope: when the route is the legacy LQA-compatible
// alias `/api/v1/identity/introspect`, we wrap in LQA's
// `{ret_code,message,data}` so Runmesh's existing mapLqaResponse
// stays happy. The OIDC-standard `/oauth/introspect` stays flat
// per RFC 7662.
func Introspect(c *gin.Context) {
	token := extractIntrospectToken(c)

	if token == "" {
		writeIntrospect(c, IntrospectResponse{Active: false, Reason: "no token"})
		return
	}

	// Phase 8 metric: record which prefixes are still seen in the
	// wild so we can time the sunset of legacy rm_pat_*/rmk_*/flm-*.
	// Written async — introspect is on the hot path for every
	// downstream service + must not block on a DB insert.
	go recordIntrospectAudit(c.ClientIP(), c.GetHeader("User-Agent"), token)

	// Cache lookup: a hit skips argon2id + the token/user SELECTs entirely.
	ttl := introspectTTL()
	var key string
	if ttl > 0 {
		introCacheSweep()
		key = introCacheKey(token)
		if v, ok := introCache.Load(key); ok {
			if e, ok := v.(introCacheEntry); ok && time.Now().Before(e.exp) {
				writeIntrospect(c, e.resp)
				return
			}
		}
	}

	resp := enrichClaudePolicy(resolveIntrospect(token))

	// Cache determinate verdicts (active, or a real inactive reason like
	// revoked/expired). Skip "unknown token" so a not-yet-provisioned token
	// isn't pinned negative. Revocation/expiry takes effect within the TTL.
	if ttl > 0 && resp.Reason != "unknown token" {
		introCache.Store(key, introCacheEntry{resp: resp, exp: time.Now().Add(ttl)})
	}
	writeIntrospect(c, resp)
}

// resolveIntrospect runs the actual (expensive) validation: prefix-routed to the
// legacy/native/JWT paths. Split out of Introspect so the cache wraps it.
func resolveIntrospect(token string) IntrospectResponse {
	// Fast path for legacy prefixes during shadow.
	if config.G.Legacy.Enabled && strings.HasPrefix(token, "rm_pat_") {
		if resp := introspectLegacyLQA(token); resp != nil {
			return *resp
		}
	}
	// Native lm_* tokens (Phase 3 onward)
	if strings.HasPrefix(token, "lm_") {
		if resp := introspectNative(token); resp != nil {
			return *resp
		}
	}
	// JWT (lm_session cookies, Bearer Authorization headers)
	if strings.Count(token, ".") == 2 {
		if resp := introspectJWT(token); resp != nil {
			return *resp
		}
	}
	return IntrospectResponse{Active: false, Reason: "unknown token"}
}

// enrichClaudePolicy fills the per-identity model-access verdicts.
//
// Applied once here rather than in introspectLegacyLQA/Native/JWT because all
// three build the same struct and the policy is derived purely from (sub,
// scopes) — three copies would be three places to forget. Only for active
// tokens: an inactive verdict carries no identity to resolve a pool for.
func enrichClaudePolicy(resp IntrospectResponse) IntrospectResponse {
	if !resp.Active {
		return resp
	}
	// ONE resolution for all three verdicts. Calling the single-verdict
	// helpers here cost up to nine queries per introspection, all re-reading
	// the same pool row, on the auth path for the whole platform.
	pol := claudePolicyFor(resp.Sub, resp.Scopes)
	resp.AllowOnprem = pol.Onprem
	resp.AllowOpenrouter = pol.Openrouter
	resp.AllowFable = pol.Fable
	resp.ClaudePoolID = pol.PoolID
	return resp
}

// extractIntrospectToken pulls the token out of form body, JSON body,
// or Authorization header — whichever the caller used. Runmesh sends
// JSON `{"token": "..."}` via WebClient; curl tends to use form;
// OAuth2 clients may use either per the RFC 7662 spec.
func extractIntrospectToken(c *gin.Context) string {
	if t := strings.TrimSpace(c.PostForm("token")); t != "" {
		return t
	}
	// Try JSON body.
	ct := c.ContentType()
	if strings.Contains(ct, "application/json") {
		var body struct {
			Token string `json:"token"`
		}
		if err := c.ShouldBindJSON(&body); err == nil {
			if t := strings.TrimSpace(body.Token); t != "" {
				return t
			}
		}
	}
	// Final fallback: raw body (handles `token=xxx` without proper
	// Content-Type header, which some hand-rolled curl scripts send).
	if c.Request.ContentLength > 0 {
		b, _ := c.GetRawData()
		raw := strings.TrimSpace(string(b))
		if strings.HasPrefix(raw, "token=") {
			return strings.TrimPrefix(raw, "token=")
		}
		// Accept a bare JWT in the body too.
		return raw
	}
	// Authorization header: Bearer <token>.
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// writeIntrospect picks the envelope shape per route. /oauth/introspect
// stays flat (RFC 7662 + OIDC-compatible); the LQA-compatible alias
// at /api/v1/identity/introspect wraps in `{ret_code,message,data}`
// because downstream Runmesh code reads `envelope.data`.
func writeIntrospect(c *gin.Context, resp IntrospectResponse) {
	if strings.HasPrefix(c.FullPath(), "/api/v1/identity/") {
		ok(c, "operation.success", resp)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// introspectLegacyLQA mirrors the shape of LQA's IdentityLogic.Introspect.
// We read the same tbl_rm_personal_access_token rows, so if the row
// exists, is not revoked, and is not expired, active=true. Scopes are
// stored space-separated in LQA too — just pass them through unchanged
// so downstream consumers don't have to learn a new vocabulary until
// Phase 8.
func introspectLegacyLQA(token string) *IntrospectResponse {
	if common.LegacyDB == nil {
		return nil
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	// LQA schema: tbl_rm_personal_access_token has columns
	// user_id, token_hash, scopes, expires_at, revoked_at, name.
	// We query by raw SQL to avoid importing LQA's GORM models.
	var row struct {
		UserID    int64  `gorm:"column:user_id"`
		Scopes    string `gorm:"column:scopes"`
		ExpiresAt *int64 `gorm:"column:expires_at"`
		RevokedAt *int64 `gorm:"column:revoked_at"`
		Name      string `gorm:"column:name"`
	}
	err := common.LegacyDB.Raw(`
		SELECT user_id, scopes, expires_at, revoked_at, name
		FROM tbl_rm_personal_access_token
		WHERE token_hash = ?
		LIMIT 1`, hash).Scan(&row).Error
	if err != nil || row.UserID == 0 {
		return &IntrospectResponse{Active: false, Reason: "no such token"}
	}
	now := time.Now().Unix()
	if row.RevokedAt != nil && *row.RevokedAt > 0 {
		return &IntrospectResponse{Active: false, Reason: "revoked"}
	}
	if row.ExpiresAt != nil && *row.ExpiresAt > 0 && *row.ExpiresAt < now {
		return &IntrospectResponse{Active: false, Reason: "expired"}
	}

	// Pull the LQA user so downstream gets a useful sub + email + role.
	var u struct {
		ID       int64  `gorm:"column:id"`
		Email    string `gorm:"column:email"`
		Username string `gorm:"column:username"`
		Role     string `gorm:"column:role"`
	}
	common.LegacyDB.Raw(`SELECT id, email, username, role FROM tbl_user WHERE id = ? LIMIT 1`, row.UserID).Scan(&u)

	// LQA stores scopes comma-separated; Runmesh stores space-separated.
	// Accept either and normalize so downstream consumers see a clean array.
	raw := strings.ReplaceAll(row.Scopes, ",", " ")
	scopeList := common.ExpandFlowmeshScopes(strings.Fields(raw))
	if u.Role == "admin" || u.Role == "super_admin" {
		scopeList = ensureAdminFlowmeshScopes(scopeList)
	}
	var exp int64
	if row.ExpiresAt != nil {
		exp = *row.ExpiresAt
	}
	return &IntrospectResponse{
		Active:    true,
		Sub:       itoa(row.UserID),
		Email:     u.Email,
		Username:  u.Username,
		Role:      u.Role,
		Scopes:    scopeList,
		Scope:     strings.Join(scopeList, " "),
		TokenType: "pat",
		Exp:       exp,
		Source:    "legacy-lqa",
	}
}

// introspectNative — native lm_* token lookup against lumid_identity.tokens.
// Uses the dual-path lookup (argon2id for new tokens, SHA-256 for legacy).
// Bumps last_used_at on hit so the dashboard can show stale tokens.
func introspectNative(token string) *IntrospectResponse {
	row, ok := findPATRow(token)
	if !ok {
		return &IntrospectResponse{Active: false, Reason: "no such token"}
	}
	now := time.Now()
	if row.RevokedAt != nil {
		return &IntrospectResponse{Active: false, Reason: "revoked"}
	}
	if row.ExpiresAt != nil && row.ExpiresAt.Before(now) {
		return &IntrospectResponse{Active: false, Reason: "expired"}
	}
	// async last_used_at bump; don't block the reply. THROTTLED per-token (>=60s) so a
	// high-frequency service token (e.g. lumid-data-service hammering introspect) doesn't
	// flood the DB with UPDATEs — that write storm contends the synchronous token/user
	// SELECTs (~2s each observed) and piles up goroutines/connections until OOM. The
	// dashboard only needs minute-granular "last used", so a 60s cooldown is lossless there.
	if last, ok := lastUsedBump.Load(row.ID); !ok || now.Sub(last.(time.Time)) >= time.Minute {
		lastUsedBump.Store(row.ID, now)
		go common.DB.Exec(`UPDATE tokens SET last_used_at = ? WHERE id = ?`, now, row.ID)
	}

	// Enrich with email/name for downstream ergonomics.
	var u struct {
		Email string
		Name  string
		Role  string
	}
	common.DB.Raw(`SELECT email, name, role FROM users WHERE id = ? LIMIT 1`, row.UserID).Scan(&u)

	// Expand flowmesh:read/write shortcuts to the fine-grained vocab
	// FlowMesh's plugin v0.2.0+ requires. See common/scopes.go.
	scopes := common.ExpandFlowmeshScopes(strings.Fields(row.Scopes))
	if u.Role == "admin" || u.Role == "super_admin" {
		scopes = ensureAdminFlowmeshScopes(scopes)
	}
	var exp int64
	if row.ExpiresAt != nil {
		exp = row.ExpiresAt.Unix()
	}
	return &IntrospectResponse{
		Active:    true,
		Sub:       row.UserID,
		Email:     u.Email,
		Username:  u.Name,
		Role:      u.Role,
		Scopes:    scopes,
		Scope:     strings.Join(scopes, " "),
		TokenType: "pat",
		Exp:       exp,
		Source:    "native",
	}
}

// introspectJWT — verify the signature against our JWKS + check
// the session isn't revoked. Used when downstream services bounce
// the bearer cookie through introspect instead of verifying locally.
func introspectJWT(token string) *IntrospectResponse {
	claims, err := common.VerifyJWT(token)
	if err != nil {
		return &IntrospectResponse{Active: false, Reason: "jwt verify: " + err.Error()}
	}
	// Session revocation: one row per jti. Logout flips revoked_at.
	// We treat "no such session" as expired (the JWT verified fine
	// but the server has no record — could be post-restart before the
	// session table was migrated; let it through to avoid lockout).
	var sess struct {
		ID        string     `gorm:"column:id"`
		RevokedAt *time.Time `gorm:"column:revoked_at"`
	}
	common.DB.Raw(`SELECT id, revoked_at FROM sessions WHERE jti = ? LIMIT 1`, claims.ID).Scan(&sess)
	if sess.ID != "" && sess.RevokedAt != nil {
		return &IntrospectResponse{Active: false, Reason: "session revoked"}
	}
	scopes := common.ExpandFlowmeshScopes(strings.Fields(claims.Scopes))
	return &IntrospectResponse{
		Active:    true,
		Sub:       claims.Subject,
		Email:     claims.Email,
		Role:      claims.Role,
		Scopes:    scopes,
		Scope:     strings.Join(scopes, " "),
		TokenType: "jwt",
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Source:    "native",
	}
}

// recordIntrospectAudit writes one row per /oauth/introspect hit so
// the deprecation dashboard can see which legacy prefixes are still
// in play. Token body is never logged — only its prefix.
func recordIntrospectAudit(ip, ua, token string) {
	prefix := "unknown"
	switch {
	case strings.HasPrefix(token, "lm_pat_"):
		prefix = "lm_pat"
	case strings.HasPrefix(token, "rm_pat_"):
		prefix = "rm_pat-legacy"
	case strings.HasPrefix(token, "rmk_"):
		prefix = "rmk-legacy"
	case strings.HasPrefix(token, "flm-"):
		prefix = "flm-legacy"
	case strings.Count(token, ".") == 2:
		prefix = "jwt"
	}
	// Only LEGACY prefixes matter for the deprecation-sunset dashboard. The current
	// lm_pat/jwt paths are the high-volume hot path (lumid-data-service et al.) — auditing
	// every hit was a pure write-flood that contended the synchronous token/user SELECTs
	// and drove the introspect OOM. Skip them; keep recording the legacy prefixes we're
	// actually trying to retire.
	switch prefix {
	case "rm_pat-legacy", "rmk-legacy", "flm-legacy":
		common.DB.Exec(
			`INSERT INTO audit_log (event, source, path, detail, ip, user_agent)
			 VALUES ('introspect', ?, '/oauth/introspect', ?, ?, ?)`,
			prefix, `{"prefix":"`+prefix+`"}`, ip, ua,
		)
	}
}

// ensureAdminFlowmeshScopes appends flowmesh:workflows:write for admin/super_admin
// users unless an alias already grants it ("*", "flowmesh:*", "flowmesh:admin").
// JWT tokens already carry "*" so this only fires for PATs with narrower scopes.
func ensureAdminFlowmeshScopes(scopes []string) []string {
	const target = "flowmesh:workflows:write"
	for _, s := range scopes {
		switch s {
		case "*", "flowmesh:*", "flowmesh:admin", target:
			return scopes
		}
	}
	return append(scopes, target)
}

func itoa(i int64) string {
	// small helper, avoids importing strconv for a single call site
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		buf[n] = '-'
	}
	return string(buf[n:])
}
