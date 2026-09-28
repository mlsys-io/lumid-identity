package handler

// Per-user LQT strategy registry — the read behind the strategy workspace.
//
// WHY THIS LIVES IN IDENTITY, NOT IN THE LQT READ PLATFORM
//
// The obvious homes for this read are both wrong today:
//
//   - `/dataapp-proxy/lqt/` injects the SHARED read-scoped service PAT
//     (`proxy_set_header Authorization $lqt_auth`), so every caller would see
//     every tenant's strategies.
//   - `lqt-inspect` (the declarative read platform) cannot scope per user at
//     all: it connects to the core DB as `postgres` — a SUPERUSER, which
//     bypasses RLS even when FORCEd — the read path never binds a per-request
//     tenant (`SET LOCAL ROLE` is used only for admin *elevation*), and its
//     `Identity` struct carries `{sub, role, email, active, scopes}` with no
//     tenant field to scope by. Its shipped endpoints take the tenant as a PATH
//     PARAMETER (`/risk/decisions/:tenant`), which the caller supplies.
//
// Fixing that platform properly is tracked separately. Identity, by contrast,
// already authenticates the caller and needs no new trust: the scoping value is
// the caller's own id, never anything they send.
//
// THE MAPPING: an LQT tenant IS a lum.id user id.
//
// `lqt-auth` derives the tenant by parsing the lum.id `sub` directly —
// `Uuid::parse_str(sub.trim())` (crates/lqt-auth/src/lib.rs:540, and again at
// :660 / :714 for the JWT paths). Verified against live data: the tenant on
// `lqt.signals` resolves to a real row in `lumid_identity.users`. So the scope
// predicate is `tenant_id = <caller's own id>` with no mapping table involved.
//
// Read-only by construction: one SELECT, no writes, no DDL.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// The core DB is reached over the tailnet; a generous dial bound still
	// fails fast when that hop is down rather than hanging the workspace.
	strategiesDialTimeout = 10 * time.Second
	strategiesOpTimeout   = 15 * time.Second

	// A workspace list, not an export. Bounded so one tenant with a runaway
	// registry cannot turn this into a slow query.
	strategiesRowCap = 500

	// Rejections are additive context beside the list, not a history export.
	// The reader clamps this server-side too, so a wrong value here cannot widen
	// the read.
	rejectionRowCap = 20

	// The rejections read gets its OWN deadline, far below the list's. It joins
	// the mailbox tables on unindexed JSON expressions (lqt_outbox is 4.8M rows /
	// 5.8GB; processed has no index on verified_tenant_id), so it ran into
	// strategiesOpTimeout on every call measured 2026-09-25: the Strategies tab
	// — every researcher's landing page in Quant Research — took 15.2s, and the
	// "Rejected submissions" panel then read empty because the read had been
	// cut off. The list itself answers in ~40ms. Bounding the additive read
	// returns the list promptly and reports the rejections as unavailable
	// (`rejected_unavailable`), which the surface now renders as such.
	rejectionsOpTimeout = 3 * time.Second
)

func strategiesDSN() string { return strings.TrimSpace(os.Getenv("LQT_CORE_DSN")) }

// strategiesConnect dials per request rather than holding a pool — same
// reasoning as findataSQLConnect: identity runs replicas:2 against a shared
// core DB, and a standing pool would hold connections open permanently to serve
// an occasional read.
func strategiesConnect(ctx context.Context) (*pgx.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, strategiesDialTimeout)
	defer cancel()
	return pgx.Connect(dialCtx, strategiesDSN())
}

// MeStrategies — GET /api/v1/me/strategies
//
// Always 200 for an authenticated caller. An empty registry, an unconfigured
// DSN and a non-UUID account are all *states of the workspace*, not errors the
// UI should have to decode from a status code — the same reasoning as
// MeFindataSQL. `available` says whether the read is wired at all; `reason`
// says why the list is empty when it is.
func MeStrategies(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	ok(c, "ok", meStrategiesData(c.Request.Context(), userID, strings.TrimSpace(c.Query("name"))))
}

// strategiesListQuery builds the list SELECT. `name`, when non-empty, narrows
// the list to one strategy name — every version the caller registered under it
// — so a page can show a strategy's history. It is an AND on top of the tenant
// predicate, never instead of it: the tenant term is always $1 and always the
// caller's own id, so a name that exists only under another tenant returns an
// empty list, not their rows. Both values are bound, never interpolated.
func strategiesListQuery(tenant uuid.UUID, name string) (string, []any) {
	args := []any{tenant}
	where := "tenant_id = $1"
	if name != "" {
		args = append(args, name)
		where += fmt.Sprintf(" AND name = $%d", len(args))
	}
	args = append(args, strategiesRowCap)
	q := `
		SELECT strategy_id, name, kind, model, version, status,
		       live_enabled, live_enabled_at, region_scope,
		       program_hash, registered_at, updated_at
		  FROM core.tenant_strategies
		 WHERE ` + where + `
		 ORDER BY updated_at DESC NULLS LAST, registered_at DESC NULLS LAST
		 LIMIT $` + fmt.Sprint(len(args))
	return q, args
}

// meStrategiesData is MeStrategies' body, shared with the chat's app_read
// (me://strategies) so both read the registry through one tenant-scoped path.
// nameFilter is optional (see strategiesListQuery).
func meStrategiesData(reqCtx context.Context, userID, nameFilter string) gin.H {
	data := gin.H{
		"strategies": []gin.H{},
		"available":  strategiesDSN() != "",
	}

	if strategiesDSN() == "" {
		data["reason"] = "strategy registry not configured (LQT_CORE_DSN unset)"
		return data
	}

	// LQT parses the lum.id sub as a UUID to get the tenant. An id that does
	// not parse cannot own an LQT strategy, so the honest answer is an empty
	// list with the reason — not a 500 for a request that was well-formed.
	tenant, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		data["reason"] = "account id is not a UUID, so it cannot own LQT strategies"
		return data
	}

	ctx, cancel := context.WithTimeout(reqCtx, strategiesOpTimeout)
	defer cancel()

	conn, err := strategiesConnect(ctx)
	if err != nil {
		// The core DB is a separate system behind a tailnet hop. Its being
		// down is an availability fact about the registry, not a fault in this
		// request — report it as such so the workspace can say "unreachable"
		// instead of rendering an empty list that looks like "you have none".
		data["available"] = false
		data["reason"] = "strategy registry unreachable"
		return data
	}
	defer func() { _ = conn.Close(context.Background()) }()

	// bytecode_hex and spec_json are deliberately NOT selected: they are large,
	// and a list view never renders them. Fetch them per strategy if a detail
	// view needs them.
	//
	// tenant_id is bound, never interpolated, and comes from the authenticated
	// session — a caller cannot ask for another tenant's rows because there is
	// no request field that reaches this predicate.
	q, args := strategiesListQuery(tenant, nameFilter)
	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		data["available"] = false
		data["reason"] = "strategy registry query failed"
		return data
	}
	defer rows.Close()

	out := make([]gin.H, 0, 16)
	scanFailures := 0
	for rows.Next() {
		// Types mirror the live schema exactly (checked against
		// information_schema): NOT NULL columns scan into values, nullable ones
		// into pointers, and region_scope is text[] — scanning that into a
		// *string fails every row.
		var (
			strategyID, name, kind, status string
			model, version, programHash    *string
			regionScope                    []string
			liveEnabled                    bool
			liveEnabledAt                  *time.Time
			registeredAt, updatedAt        time.Time
		)
		if err := rows.Scan(&strategyID, &name, &kind, &model, &version, &status,
			&liveEnabled, &liveEnabledAt, &regionScope,
			&programHash, &registeredAt, &updatedAt); err != nil {
			// Skipping one malformed row is reasonable; skipping EVERY row
			// because the scan types are wrong is how a systematic bug
			// disguises itself as "you have no strategies". Counted and
			// surfaced below so it can never be silent.
			scanFailures++
			continue
		}
		if regionScope == nil {
			regionScope = []string{}
		}
		out = append(out, gin.H{
			"strategy_id":     strategyID,
			"name":            name,
			"kind":            kind,
			"model":           model,
			"version":         version,
			"status":          status,
			"live_enabled":    liveEnabled,
			"live_enabled_at": liveEnabledAt,
			"region_scope":    regionScope,
			"program_hash":    programHash,
			"registered_at":   registeredAt,
			"updated_at":      updatedAt,
		})
	}
	if scanFailures > 0 {
		data["scan_failures"] = scanFailures
	}
	if rows.Err() != nil {
		data["available"] = false
		data["reason"] = "strategy registry read interrupted"
		return data
	}

	data["strategies"] = out
	if nameFilter != "" {
		// Echo the filter so an empty list reads as "no versions of THIS
		// name", not as an empty registry.
		data["name"] = nameFilter
	}

	// REJECTED SUBMISSIONS — the half a student could not see.
	//
	// A strategy whose .lqts does not compile never reaches core.tenant_strategies,
	// so the list above is silent about it. The consumer does the right thing: it
	// parses, fails, and acks `status: rejected` with an exact reason and
	// character offsets ("expected `when` to start a guard, found identifier
	// `param`"). That ack lands in mailbox.lqt_outbox and nothing rendered it.
	//
	// Measured 2026-08-29: 4 of 14 submissions across four e2e runs were rejected
	// this way. Every one presented to the student as "Queued send_strategy" and
	// then a row that never appeared — no error, anywhere. It reads exactly like
	// data loss and is the opposite: a precise diagnosis nobody surfaced.
	//
	// Scoped the same way as the query above: mailbox.processed.verified_tenant_id
	// is the tenant the CONSUMER verified from the submitter's own token, bound and
	// never interpolated. Deliberately NOT read from /xpio/strategies, which the
	// surface layer reaches through a shared service PAT and which would therefore
	// show another tenant's submissions.
	//
	// Best-effort: a failure here must not take down the strategy list, which is
	// the primary answer. Rejections are additive context.
	rejCtx, rejCancel := context.WithTimeout(ctx, rejectionsOpTimeout)
	defer rejCancel()
	if rej, rejErr := recentRejections(rejCtx, conn, tenant); rejErr != "" {
		// Report, do not swallow. An empty list and a failed query are the same
		// value to a reader, and that ambiguity cost real time: the surfacing
		// this block exists for was itself debugged blind because a failure here
		// looked exactly like "you have no rejections". Same lesson the feature
		// teaches a student — a silent failure is worse than a stated one.
		data["rejected"] = []map[string]any{}
		data["rejected_unavailable"] = rejErr
	} else {
		data["rejected"] = rej
	}
	switch {
	case len(out) == 0 && scanFailures > 0:
		// Rows existed and none could be read — a schema/scan mismatch, NOT an
		// empty registry. Saying "no strategies yet" here would be a lie that
		// looks like a working empty state.
		data["available"] = false
		data["reason"] = "strategy rows could not be decoded — schema mismatch"
	case len(out) == 0 && nameFilter != "":
		data["reason"] = "no strategies named " + strconv.Quote(nameFilter)
	case len(out) == 0:
		// An empty registry is the expected first state — core.tenant_strategies
		// has never held a row. Say so, so the workspace can offer the create
		// path instead of rendering a bare empty table that reads as broken.
		data["reason"] = "no strategies yet"
	}
	return data
}

// recentRejections returns submissions this tenant made that failed to compile,
// newest first, with the consumer's own reason. Empty slice on any error — the
// caller treats this as additive context, never as the primary answer.
func recentRejections(ctx context.Context, conn *pgx.Conn, tenant uuid.UUID) ([]map[string]any, string) {
	// Call the narrow reader, do not join the tables.
	//
	// The reason lives in mailbox.lqt_outbox, and the consumer writes it for
	// EVERY submit path — the Studio form, the self-serve relay, anything that
	// reaches the inbox. (An earlier version joined xpio.strategies, which only
	// has a row for the form's path, so relay rejections stayed invisible.)
	//
	// But identity CANNOT read those tables, and must not be able to: measured
	// 2026-08-29, 1,381,921 of 1,382,164 mailbox.lqt_inbox rows carry a live PAT
	// at payload.auth.pat, because that is how the consumer authenticates a
	// submission. Granting this service USAGE on schema mailbox to render a
	// one-line error would put ~1.38M live bearer tokens one SELECT away.
	//
	// LQT migration 0079 provides core.read_tenant_rejections(tenant, limit) —
	// a SECURITY DEFINER reader owned by postgres that returns three scalar
	// columns and never the payload it read them from. It is defined in `core`
	// precisely so schema `mailbox` is never opened to identity_strategies_ro at
	// all (EXECUTE alone cannot call a function; PostgreSQL also wants USAGE on
	// its schema). Verified as that role: the call returns rows, and a direct
	// read of mailbox.lqt_inbox still fails with permission denied.
	//
	// The tenant is bound and comes from the authenticated session — there is no
	// request field that reaches this argument.
	const q = `SELECT name, submitted_at, reason FROM core.read_tenant_rejections($1, $2)`

	out := []map[string]any{}
	rows, err := conn.Query(ctx, q, tenant, rejectionRowCap)
	if err != nil {
		return out, "rejection query failed: " + err.Error()
	}
	defer rows.Close()
	scanFail := 0
	for rows.Next() {
		var name, reason *string
		var at *time.Time
		if rows.Scan(&name, &at, &reason) != nil {
			scanFail++
			continue
		}
		r := map[string]any{"name": deref(name), "reason": deref(reason)}
		if at != nil {
			r["submitted_at"] = at.UTC().Format(time.RFC3339)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return out, "rejection read interrupted: " + err.Error()
	}
	if scanFail > 0 && len(out) == 0 {
		return out, fmt.Sprintf("%d rejection row(s) could not be decoded", scanFail)
	}
	return out, ""
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// MeStrategyDetail — GET /api/v1/me/strategies/:id
//
// One strategy WITH its body (bytecode_hex / spec_json), for callers that must
// act on the strategy itself — submitting a backtest, which needs
// dsl/program_hex rather than a name.
//
// # WHY THIS EXISTS RATHER THAN READING THE MAILBOX FEED
//
// /xpio/strategies carries the same payload and is far easier to reach, but it
// is backed by `xpio.strategies`, which has NO tenant column — the bundle's own
// backtest verb documents it as "cross-tenant readable by construction" and
// warns that "strategy_id is NOT globally unique across tenants". Resolving a
// body from there would let one researcher backtest another's strategy, keyed
// on an id that does not distinguish them.
//
// So the body is served here, from core.tenant_strategies, under the same
// predicate as the list: tenant_id = the caller's own id. The :id is a filter
// WITHIN that scope, never a lookup key across it — an id belonging to someone
// else returns not-found, not their strategy.
func MeStrategyDetail(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	data, status, code, msg := meStrategyDetailData(c.Request.Context(), userID, c.Param("id"))
	if data == nil {
		fail(c, status, code, msg)
		return
	}
	ok(c, "ok", data)
}

// strategyRow is one core.tenant_strategies row as the detail read selects it.
type strategyRow struct {
	StrategyID, Name, Kind, Status  string
	Model, Version                  *string
	BytecodeHex, SpecJSON, ProgHash string
}

var errStrategyNotFound = errors.New("strategy not found")
var errStrategyUnreachable = errors.New("strategy registry unreachable")

// fetchStrategyRow reads one strategy under the tenant predicate. A package
// var so the response shaping (and its redaction) can be tested without a
// core DB; production never reassigns it.
var fetchStrategyRow = func(ctx context.Context, tenant uuid.UUID, id string) (*strategyRow, error) {
	conn, err := strategiesConnect(ctx)
	if err != nil {
		return nil, errStrategyUnreachable
	}
	defer func() { _ = conn.Close(context.Background()) }()

	// Both predicates bound, tenant first. There is no request field that can
	// widen the tenant term: it comes from the authenticated session.
	const q = `
		SELECT strategy_id, name, kind, model, version, status,
		       coalesce(bytecode_hex, ''), coalesce(spec_json::text, ''),
		       coalesce(program_hash, '')
		  FROM core.tenant_strategies
		 WHERE tenant_id = $1 AND strategy_id = $2`
	var r strategyRow
	if err := conn.QueryRow(ctx, q, tenant, id).Scan(
		&r.StrategyID, &r.Name, &r.Kind, &r.Model, &r.Version, &r.Status,
		&r.BytecodeHex, &r.SpecJSON, &r.ProgHash); err != nil {
		// No row for THIS tenant. Deliberately the same answer whether the id
		// is unknown or belongs to another tenant — distinguishing them would
		// turn this into an existence oracle over other people's strategies.
		return nil, errStrategyNotFound
	}
	return &r, nil
}

// meStrategyDetailData is MeStrategyDetail's body, shared with the chat's
// app_read (me://strategies/<id>) so both go through the same tenant predicate
// AND the same redaction. On failure data is nil and (status, code, msg) is
// the error to report.
func meStrategyDetailData(reqCtx context.Context, userID, rawID string) (gin.H, int, int, string) {
	id := strings.TrimSpace(rawID)
	if id == "" {
		return nil, http.StatusBadRequest, 1400, "strategy id required"
	}
	if strategiesDSN() == "" {
		return nil, http.StatusServiceUnavailable, 1503, "strategy registry not configured"
	}
	tenant, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		// Cannot own an LQT strategy at all — indistinguishable from not found,
		// and saying so leaks nothing about whether the id exists elsewhere.
		return nil, http.StatusNotFound, 1404, "strategy not found"
	}
	ctx, cancel := context.WithTimeout(reqCtx, strategiesOpTimeout)
	defer cancel()
	row, err := fetchStrategyRow(ctx, tenant, id)
	if err != nil {
		if errors.Is(err, errStrategyUnreachable) {
			return nil, http.StatusServiceUnavailable, 1503, "strategy registry unreachable"
		}
		return nil, http.StatusNotFound, 1404, "strategy not found"
	}
	return strategyDetailFromRow(row), 0, 0, ""
}

// strategyDetailFromRow shapes the detail response. spec_json is REDACTED here
// and nowhere else, so every caller of the detail gets the redacted body.
//
// WHY: the mailbox consumer persisted the submitter's whole `strategy` object
// as spec_json, and the submit path carries the submitter's own lum.id PAT at
// strategy.auth.pat (POST /xpio/strategies wraps the field payload under
// `strategy`). Measured 2026-09-28: a reader's own detail returned their live
// 76-char PAT in spec_json. It is "their own" token, but this body is rendered
// in a page, handed to the chat model through app_read, and logged by any
// tool that fetches it — a bearer credential has no business in any of those.
// The consumer now strips it before persisting (LQT), and rows written before
// that fix still carry it, so identity strips it on read regardless.
func strategyDetailFromRow(r *strategyRow) gin.H {
	data := gin.H{
		"strategy_id":  r.StrategyID,
		"name":         r.Name,
		"kind":         r.Kind,
		"model":        r.Model,
		"version":      r.Version,
		"status":       r.Status,
		"program_hash": r.ProgHash,
		// The .lqts the researcher wrote — what a strategy workspace shows.
		// Empty when the strategy was submitted as a JSON model/program with
		// no source text.
		"source": "",
	}
	// The body, in the shape the backtest API and the mailbox both accept:
	// program_hex preferred, dsl as the compile-server-side path.
	if r.BytecodeHex != "" {
		data["program_hex"] = r.BytecodeHex
	}
	if r.SpecJSON != "" {
		spec, src := redactStrategySpec(r.SpecJSON)
		data["source"] = src
		if spec != "" {
			data["spec_json"] = spec
		}
	}
	return data
}

// strategyReadSummary is the chat's view of one strategy: the detail minus
// program_hex (large, and useless to a model) and spec_json (the source is the
// readable part of it).
func strategyReadSummary(d gin.H) gin.H {
	out := gin.H{}
	for _, k := range []string{"strategy_id", "name", "kind", "model", "version", "status", "program_hash", "source"} {
		out[k] = d[k]
	}
	return out
}

// redactStrategySpec parses spec_json, removes every credential-shaped key at
// any depth, and returns the re-serialized spec plus its source text
// (spec.dsl, else spec.source; "" when neither is a string).
//
// Fail CLOSED: a spec_json that does not parse as JSON cannot be inspected, so
// it is withheld entirely ("") rather than passed through verbatim.
func redactStrategySpec(specJSON string) (string, string) {
	var v any
	dec := json.NewDecoder(strings.NewReader(specJSON))
	dec.UseNumber() // keep integer params exact on the round trip
	if err := dec.Decode(&v); err != nil {
		return "", ""
	}
	v = redactCredentials(v)
	src := ""
	if m, isObj := v.(map[string]any); isObj {
		if s, isStr := m["dsl"].(string); isStr && strings.TrimSpace(s) != "" {
			src = s
		} else if s, isStr := m["source"].(string); isStr {
			src = s
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", src
	}
	return string(b), src
}

// credentialKeys are object keys dropped wherever they appear, compared after
// lowercasing and removing '_' / '-'. The token family is an explicit list,
// NOT a "*token" suffix match: prediction-market specs legitimately carry
// market identifiers such as `token_id` / `yes_token`, and those are not
// secrets.
var credentialKeys = map[string]bool{
	"auth": true, "authorization": true, "pat": true, "jwt": true, "bearer": true,
	"token": true, "accesstoken": true, "refreshtoken": true, "idtoken": true,
	"authtoken": true, "apitoken": true, "bearertoken": true, "sessiontoken": true,
	"pattoken": true, "apikey": true, "privatekey": true, "credential": true,
	"credentials": true, "cookie": true, "secret": true, "password": true, "passwd": true,
}

func isCredentialKey(k string) bool {
	lk := strings.ToLower(strings.TrimSpace(k))
	if strings.HasSuffix(lk, "_pat") || strings.HasSuffix(lk, "-pat") {
		return true
	}
	n := strings.NewReplacer("_", "", "-", "").Replace(lk)
	if credentialKeys[n] {
		return true
	}
	return strings.Contains(n, "secret") || strings.Contains(n, "password") ||
		strings.Contains(n, "passwd") || strings.Contains(n, "authorization")
}

// looksLikePAT catches a lum.id / Runmesh PAT under a key the list above does
// not name — defense in depth for a field someone invents later.
func looksLikePAT(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "lm_pat_") || strings.HasPrefix(s, "rm_pat_")
}

func redactCredentials(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isCredentialKey(k) {
				delete(t, k)
				continue
			}
			if s, isStr := val.(string); isStr && looksLikePAT(s) {
				delete(t, k)
				continue
			}
			t[k] = redactCredentials(val)
		}
		return t
	case []any:
		for i, val := range t {
			if s, isStr := val.(string); isStr && looksLikePAT(s) {
				t[i] = "[redacted]"
				continue
			}
			t[i] = redactCredentials(val)
		}
		return t
	default:
		return v
	}
}
