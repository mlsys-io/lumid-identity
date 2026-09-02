package handler

// me_agent tools: lqt_mailbox_read + lqt_mailbox_submit — read LQT mailbox
// data and submit a strategy from the native (deepseek) chat path.
//
// The LQT mailbox is the governed control-plane for the prediction-market
// runtime (strategies, results, telemetry, venue health). It is NOT reachable
// in-cluster from lumid-identity — the `lqt-allow-ingress` NetworkPolicy only
// admits ingress-nginx + the mailbox consumer, so a direct call to
// `http://lqt.lumid.svc.cluster.local:8088` is DROPPED. The working read path
// is the public route `https://lum.id/dataapp-proxy/lqt/<path>`, which injects
// a read PAT when none is sent; we send the operator's Lumid PAT (kvrunPAT)
// explicitly so the caller's identity rides the request.
//
// lqt_mailbox_read is read-only and available to every role (like data_query).
// The endpoint is WHITELISTED — the model can only name one of the known-good
// read surfaces, never an arbitrary path (SSRF guard). lqt_mailbox_submit is a
// WRITE (deploys a strategy via the `strategy.deploy` mailbox topic) and is
// gated like the operator tools: super_admin-only, in destructiveTools
// (interactive approval), and audited via writeAudit.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	lqtMailboxTimeout = 30 * time.Second
	// Row cap for list endpoints. The server enforces its own cap too, but we
	// clamp before requesting so a careless read doesn't materialize a giant
	// payload into the chat context.
	lqtReadLimit = 100
)

// lqtReadSpec describes one whitelisted read surface. `list` marks the
// endpoints that accept a ?limit= query param (arrays); the scalar/health
// endpoints ignore it.
type lqtReadSpec struct {
	path string
	list bool
	// needsID marks an endpoint whose path is completed by a caller-supplied
	// strategy id: `path` is a fmt template with exactly one %s.
	//
	// This does NOT loosen the SSRF guard. The model still names an endpoint
	// from the allowlist and never supplies a path; the id is separately
	// validated by `safeLQTID` and is the ONLY caller-controlled text that
	// reaches the URL. Without this, a chat grounded to a strategy could list
	// every strategy but not read the one it was grounded to — which is the
	// whole point of grounding it.
	needsID bool
}

// safeLQTID accepts only what a strategy id can actually be: a uuid, or the
// human ids the registry also carries (`researcher_meanrev_hold_v2`,
// `bt-<uuid>`). Everything else is refused rather than escaped — an id is a
// closed alphabet, so a rejection here can never be a false negative on a real
// id, while accepting a path separator would hand the model a URL.
func safeLQTID(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 128 {
		return "", false
	}
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return "", false
		}
	}
	return v, true
}

// lqtReadEndpoints — the allowlist of LQT mailbox read surfaces the model may
// name. Keys are the friendly names the tool advertises; values carry the path
// appended to lqtMailboxBase(). Anything not here is refused outright — this is
// the SSRF guard (no arbitrary paths, no host injection).
var lqtReadEndpoints = map[string]lqtReadSpec{
	"venue_health_nyc":    {path: "/lqt/venue-health/nyc", list: false},
	"venue_health_chi":    {path: "/lqt/venue-health/chi", list: false},
	"venue_health_dublin": {path: "/lqt/venue-health/dublin", list: false},
	"stats":               {path: "/xpio/stats", list: false},
	"strategies":          {path: "/xpio/strategies", list: true},
	"results":             {path: "/xpio/results", list: true},
	"cycles_nyc":          {path: "/runtime/cycles/nyc", list: true},
	"signals_venue_mid":   {path: "/lqt/signals/venue_mid", list: true},
	// Per-strategy reads — what a grounded chat actually needs. Tenant-scoped
	// server-side (unlike the cross-tenant `results` feed), so this narrows
	// exposure rather than widening it.
	"strategy_cycles": {path: "/lqt/inspect/cycles/%s", list: true, needsID: true},
}

// lqtMailboxBase resolves the base URL of the LQT mailbox read/write ingress.
// Defaults to the public dataapp-proxy hairpin (the only path admitted by the
// lqt NetworkPolicy from this service). Trailing slashes are trimmed so callers
// can append paths.
func lqtMailboxBase() string {
	base := strings.TrimSpace(os.Getenv("LQT_MAILBOX_BASE"))
	if base == "" {
		base = "https://lum.id/dataapp-proxy/lqt"
	}
	return strings.TrimRight(base, "/")
}

// lqtMailboxHeaders returns the Authorization header for LQT calls using the
// operator's Lumid PAT. If no PAT is resolvable, returns nil headers — the
// dataapp-proxy path injects a read PAT when none is sent.
func lqtMailboxHeaders() http.Header {
	h := http.Header{}
	if tok, err := kvrunPAT(); err == nil && tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// lqtMailboxDo performs an HTTP request against the LQT mailbox base and
// returns the parsed JSON body + status. Errors are wrapped so the chat sees
// why a read/submit failed.
func lqtMailboxDo(method, path string, body []byte) (map[string]any, int, error) {
	u := lqtMailboxBase() + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return nil, 0, err
	}
	for k, vs := range lqtMailboxHeaders() {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: lqtMailboxTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("lqt mailbox unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out == nil {
		out = map[string]any{"raw": truncateStr(string(rb), 520)}
	}
	return out, resp.StatusCode, nil
}

// lqtMailboxDoAs performs an LQT mailbox request authenticated as a SPECIFIC
// bearer rather than the operator's PAT. Used by the submit path so the drop is
// attributed to the caller, matching the credential carried in
// `payload.auth.pat` — reads keep using the operator PAT via lqtMailboxDo.
func lqtMailboxDoAs(method, path string, body []byte, bearer string) (map[string]any, int, error) {
	u := lqtMailboxBase() + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: lqtMailboxTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("lqt mailbox unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out == nil {
		out = map[string]any{"raw": truncateStr(string(rb), 520)}
	}
	return out, resp.StatusCode, nil
}

// resolveLqtEndpoint normalizes a model-supplied endpoint string to a
// whitelisted spec. Accepts the friendly key ("strategies") or the raw path
// ("/xpio/strategies", "xpio/strategies"). Returns ok=false for anything not on
// the allowlist — the SSRF guard.
func resolveLqtEndpoint(e string) (lqtReadSpec, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	e = strings.TrimPrefix(e, "/lqt/")
	e = strings.TrimPrefix(e, "/")
	if spec, ok := lqtReadEndpoints[e]; ok {
		return spec, true
	}
	for _, spec := range lqtReadEndpoints {
		if strings.TrimPrefix(spec.path, "/lqt/") == e ||
			strings.TrimPrefix(spec.path, "/") == e {
			return spec, true
		}
	}
	return lqtReadSpec{}, false
}

// toolLqtMailboxRead fetches one whitelisted LQT mailbox read surface and
// returns the parsed JSON. `endpoint` names a known-good surface (see
// lqtReadEndpoints); `limit` caps list endpoints. Read-only — no gating beyond
// the endpoint allowlist, mirroring data_query.
func toolLqtMailboxRead(endpoint, strategyID string, limit int) (map[string]any, bool) {
	spec, ok := resolveLqtEndpoint(endpoint)
	if !ok {
		return map[string]any{"error": fmt.Sprintf("unknown lqt endpoint %q — use one of: %s", endpoint, strings.Join(sortedKeys(lqtReadEndpoints), ", "))}, false
	}
	path := spec.path
	if spec.needsID {
		id, ok := safeLQTID(strategyID)
		if !ok {
			return map[string]any{"error": fmt.Sprintf(
				"endpoint %q needs a strategy_id (letters, digits, - and _ only)", endpoint)}, false
		}
		// The id is validated to a closed alphabet above, so it cannot escape
		// the path segment; PathEscape belts-and-braces it anyway.
		path = fmt.Sprintf(spec.path, url.PathEscape(id))
	}
	if spec.list {
		if limit <= 0 || limit > 1000 {
			limit = lqtReadLimit
		}
		path += "?" + url.Values{"limit": {fmt.Sprintf("%d", limit)}}.Encode()
	}
	out, status, err := lqtMailboxDo(http.MethodGet, path, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("lqt mailbox %d: %s", status, out["raw"])}, false
	}
	return map[string]any{"endpoint": endpoint, "data": out}, true
}

// toolLqtMailboxSubmit submits a strategy to the LQT mailbox via the
// `strategy.deploy` topic (POST /xpio/strategies). In destructiveTools
// (interactive approval) + audited.
//
// # Two things this had to fix before the role gate could open
//
//  1. THE ENVELOPE WAS WRONG. It posted `{strategy_id, name, version,
//     strategy}` flat. The shape the consumer actually reads — proven by the
//     app bundle's `send_strategy.py`, the only submit path with deploys to
//     show for it — is `{name, version, strategy_id, payload: {...}}`, the
//     spec NESTED under `payload`.
//
//  2. IT CARRIED NO CALLER CREDENTIAL. The consumer authorises a deploy from
//     `payload.auth.pat`, NOT from the request's Authorization header. This
//     sent neither, so every chatbox submit was accepted into the mailbox and
//     then refused, asynchronously and invisibly, at consume time —
//     `auth_denied: no bearer credential in payload.auth.{pat,jwt}`, which is
//     42 of the 53 rejections on the live mailbox (measured 2026-08-28). The
//     tool was structurally incapable of a successful deploy for EVERY role,
//     super_admin included.
//
// # Why opening the gate is safe now, and was not before
//
// The old code authenticated with the OPERATOR's PAT (`lqtMailboxHeaders`).
// Had it worked, a user's strategy would have registered under the operator's
// tenant, not their own. Opening the role gate on top of that would have been
// a cross-tenant write.
//
// It now carries the CALLER's own short-lived `lqt:strategy` PAT, so the
// consumer introspects it and resolves the caller's tenant and role — the same
// per-tenant attribution `send_strategy.py` gets. A `user` therefore lands in
// their own tenant's prod-paper lane, which is the documented self-serve path.
// Real-money and the nightly-dk canary stay gated downstream, in the consumer,
// on the PAT's own role — this tool cannot widen them.
// ---------------------------------------------------------------------------
// WAIT FOR THE COMPILER, NOT JUST THE MAILBOX
//
// This tool used to return the moment the mailbox ACKed, with a note telling
// the caller to go confirm a program_hash themselves. No model does that, and
// the student never sees the reason either — so a strategy that failed to
// compile presented as a successful submit and then simply never appeared.
//
// Measured 2026-08-29/30 across five onboarding walks: chat-authored strategies
// were rejected in 10-15ms with exact parse errors ("expected `when` to start a
// guard, found identifier `param`"), and every one was reported to the model as
// accepted. A model that gets "accepted" has nothing to correct against.
//
// So the submit now waits for the verdict and hands the compiler's own words
// back in the same turn. Deployed reads core.tenant_strategies; rejected reads
// core.read_tenant_rejections (LQT migration 0079) — the narrow SECURITY
// DEFINER reader, so identity still needs no access to schema mailbox, which
// holds a live PAT on every row.
//
// Budget: the chat turn also pays a cold sandbox spawn and an approval click,
// so this stays well inside a 180s turn.
const lqtVerdictTimeout = 35 * time.Second
const lqtVerdictInterval = 2 * time.Second

type lqtVerdict struct {
	status      string // "deployed" | "rejected" | "" (no verdict in time)
	programHash string
	reason      string
}

// awaitLqtVerdict polls this tenant's own registry + rejection list.
//
// Never returns an error: a read failure here must not turn a real submit into
// a reported failure. An empty status means "no verdict yet", which the caller
// reports as unknown rather than as success.
func awaitLqtVerdict(ctx context.Context, userID, name string) lqtVerdict {
	if strategiesDSN() == "" {
		return lqtVerdict{}
	}
	tenant, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return lqtVerdict{}
	}
	deadline := time.Now().Add(lqtVerdictTimeout)
	for time.Now().Before(deadline) {
		if v, ok := lqtVerdictOnce(ctx, tenant, name); ok {
			return v
		}
		time.Sleep(lqtVerdictInterval)
	}
	return lqtVerdict{}
}

// lqtVerdictOnce is a single poll. ok=false means "nothing decided yet", which
// includes every read failure — the caller keeps waiting rather than reporting
// a verdict it does not have.
func lqtVerdictOnce(ctx context.Context, tenant uuid.UUID, name string) (lqtVerdict, bool) {
	pollCtx, cancel := context.WithTimeout(ctx, strategiesOpTimeout)
	defer cancel()
	conn, err := strategiesConnect(pollCtx)
	if err != nil {
		return lqtVerdict{}, false
	}
	defer func() { _ = conn.Close(context.Background()) }()

	// Registered? A non-empty program_hash is the only proof.
	var hash *string
	if qerr := conn.QueryRow(pollCtx,
		`SELECT program_hash FROM core.tenant_strategies
		  WHERE tenant_id = $1 AND name = $2
		  ORDER BY registered_at DESC NULLS LAST LIMIT 1`,
		tenant, name).Scan(&hash); qerr == nil && hash != nil && *hash != "" {
		return lqtVerdict{status: "deployed", programHash: *hash}, true
	}

	// Rejected? Read the ack through the definer (migration 0079), so identity
	// still needs no access to schema mailbox.
	rows, rerr := conn.Query(pollCtx,
		`SELECT name, reason FROM core.read_tenant_rejections($1, $2)`, tenant, 20)
	if rerr != nil {
		return lqtVerdict{}, false
	}
	defer rows.Close()
	for rows.Next() {
		var rn, rr *string
		if rows.Scan(&rn, &rr) != nil {
			continue
		}
		if rn != nil && *rn == name && rr != nil && *rr != "" {
			return lqtVerdict{status: "rejected", reason: *rr}, true
		}
	}
	return lqtVerdict{}, false
}

func toolLqtMailboxSubmit(c *gin.Context, userID, role, name, version, strategy string) (map[string]any, bool) {
	switch role {
	case "user", "admin", "super_admin":
	default:
		return map[string]any{"error": "lqt_mailbox_submit requires a signed-in role"}, false
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	strategy = strings.TrimSpace(strategy)
	if name == "" || version == "" || strategy == "" {
		return map[string]any{"error": "name, version and strategy are all required"}, false
	}
	// The credential the DEPLOY is authorised from. Minted per caller, scoped
	// `lqt:strategy`, short-lived, cached — see lqt_strategy_pat.go. Without it
	// the submit is accepted and then silently rejected, so refuse up front
	// rather than report a success the consumer will undo.
	pat := lqtStrategyPATCached(userID)
	if pat == "" {
		return map[string]any{"error": "could not mint an lqt:strategy PAT for you — " +
			"the deploy would be rejected at consume time with " +
			"'no bearer credential in payload.auth.{pat,jwt}'"}, false
	}
	body, _ := json.Marshal(map[string]any{
		"name":        name,
		"version":     version,
		"strategy_id": name + "@" + version,
		// Spec NESTED under `payload`, with `auth` inside it — the shape
		// send_strategy.py uses and the consumer reads.
		"payload": map[string]any{
			"dsl":  strategy,
			"auth": map[string]any{"pat": pat},
		},
	})
	// One audit row per submission, written once the OUTCOME is known.
	//
	// It used to be written here, before awaitLqtVerdict below, so it recorded
	// that someone submitted and never what happened. The compiler's verdict
	// does persist — in xpio.strategies.ack_payload->>'reason' — but that table
	// has no tenant_id, and the only bridge back to a user (mailbox.processed)
	// is field-local, never synced, and has no read endpoint. So the two halves
	// existed and nothing joined them: 70 submissions from 31 users on
	// 2026-08-30, and no way to say whether any compiled.
	//
	// Recording the verdict against the caller here is the cheap bridge. The
	// reject reason is the compiler's own diagnostic with offsets into the
	// user's source — the "what do people get wrong" corpus — so it goes in the
	// `detail` TEXT column, as JSON, not the varchar(255) that would clip it.
	started := time.Now()
	audit := func(outcome string, httpStatus int, fields map[string]any) {
		d := map[string]any{
			"name": name, "version": version, "role": role,
			"via": "chatbox", "outcome": outcome,
		}
		for k, v := range fields {
			d[k] = v
		}
		j, _ := json.Marshal(d)
		app := groundedApp(c)
		writeAuditAppMetrics(c, userID, userID, "lqt:strategy.submit", app, string(j),
			httpStatus, int(time.Since(started).Milliseconds()))
	}

	out, status, err := lqtMailboxDoAs(http.MethodPost, "/xpio/strategies", body, pat)
	if err != nil {
		audit("transport_error", 0, map[string]any{"error": err.Error()})
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		audit("mailbox_refused", status, map[string]any{"error": fmt.Sprintf("%v", out["raw"])})
		return map[string]any{"error": fmt.Sprintf("lqt mailbox submit %d: %s", status, out["raw"])}, false
	}
	// The mailbox took it. Now wait for the COMPILER, so a rejection reaches the
	// caller in this turn instead of becoming a strategy that never appears.
	switch v := awaitLqtVerdict(c.Request.Context(), userID, name); v.status {
	case "deployed":
		audit("deployed", status, map[string]any{"program_hash": v.programHash})
		return map[string]any{
			"name":         name,
			"version":      version,
			"status":       "deployed",
			"program_hash": v.programHash,
			"note":         "registered — the consumer compiled it and the registry row carries a program_hash.",
		}, true
	case "rejected":
		// THE POINT. The compiler's own message, with character offsets into the
		// source that was just submitted, handed straight back so the model can
		// fix it and resubmit without a human relaying the error.
		audit("rejected", status, map[string]any{"reason": v.reason})
		return map[string]any{
			"name":    name,
			"version": version,
			"status":  "rejected",
			"error":   v.reason,
			"note": "REJECTED — this strategy did NOT deploy. The error above is the " +
				"compiler's, with character offsets into your source. Fix the source " +
				"and submit again. Do not report this as queued or successful.",
		}, false
	default:
		// No verdict inside the window. Unknown is neither success nor failure,
		// and saying "sent" here is how a submit path that never once worked kept
		// reporting success.
		audit("no_verdict", status, map[string]any{"timeout_s": lqtVerdictTimeout.Seconds()})
		return map[string]any{
			"name":    name,
			"version": version,
			"status":  "submitted",
			"acked":   out,
			"note": "accepted into the mailbox, but no compile verdict within " +
				lqtVerdictTimeout.String() + " — the consumer may be backlogged. NOT yet " +
				"registered: confirm a registry row with a non-empty program_hash before " +
				"believing it landed.",
		}, true
	}
}

// sortedKeys returns the map keys in lexical order — used to render the
// endpoint allowlist in error messages deterministically.
func sortedKeys(m map[string]lqtReadSpec) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lqtToolDefs returns the LQT mailbox WRITE tool definition. Offered to any
// signed-in role: it deploys into the CALLER's own tenant on the caller's own
// scoped PAT (paper lane), so it is a per-user write rather than a
// control-plane one. Still in destructiveTools (interactive approval) and
// audited, and dispatch re-checks the role. lqt_mailbox_read is in the base
// catalog — read-only, available to every role.
func lqtToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "lqt_mailbox_submit",
			"description": "Submit a strategy to the LQT mailbox for deployment (strategy.deploy topic). WRITE — deploys into YOUR tenant's paper lane on your own scoped credential; requires explicit user approval and is audited. Provide the strategy name, semantic version, and the .lqts DSL source. THIS WAITS FOR THE COMPILER and returns one of: status=deployed (with program_hash — it really is registered), status=rejected (with `error`: the compiler's parse message and character offsets into YOUR source — READ IT, fix the source, and submit again), or status=submitted (no verdict in time, which is unknown, NOT success). Do not report a rejection as queued or successful.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":     map[string]any{"type": "string", "description": "Strategy name, e.g. 'zh_momentum'."},
					"version":  map[string]any{"type": "string", "description": "Semantic version, e.g. '1.0.0'."},
					"strategy": map[string]any{"type": "string", "description": "The .lqts DSL source defining the strategy."},
				},
				"required": []string{"name", "version", "strategy"},
			},
		},
	}
}
