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
	"fmt"
	"net/http"
	"os"
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

	data := gin.H{
		"strategies": []gin.H{},
		"available":  strategiesDSN() != "",
	}

	if strategiesDSN() == "" {
		data["reason"] = "strategy registry not configured (LQT_CORE_DSN unset)"
		ok(c, "ok", data)
		return
	}

	// LQT parses the lum.id sub as a UUID to get the tenant. An id that does
	// not parse cannot own an LQT strategy, so the honest answer is an empty
	// list with the reason — not a 500 for a request that was well-formed.
	tenant, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		data["reason"] = "account id is not a UUID, so it cannot own LQT strategies"
		ok(c, "ok", data)
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), strategiesOpTimeout)
	defer cancel()

	conn, err := strategiesConnect(ctx)
	if err != nil {
		// The core DB is a separate system behind a tailnet hop. Its being
		// down is an availability fact about the registry, not a fault in this
		// request — report it as such so the workspace can say "unreachable"
		// instead of rendering an empty list that looks like "you have none".
		data["available"] = false
		data["reason"] = "strategy registry unreachable"
		ok(c, "ok", data)
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()

	// bytecode_hex and spec_json are deliberately NOT selected: they are large,
	// and a list view never renders them. Fetch them per strategy if a detail
	// view needs them.
	//
	// tenant_id is bound, never interpolated, and comes from the authenticated
	// session — a caller cannot ask for another tenant's rows because there is
	// no request field that reaches this predicate.
	const q = `
		SELECT strategy_id, name, kind, model, version, status,
		       live_enabled, live_enabled_at, region_scope,
		       program_hash, registered_at, updated_at
		  FROM core.tenant_strategies
		 WHERE tenant_id = $1
		 ORDER BY updated_at DESC NULLS LAST, registered_at DESC NULLS LAST
		 LIMIT $2`

	rows, err := conn.Query(ctx, q, tenant, strategiesRowCap)
	if err != nil {
		data["available"] = false
		data["reason"] = "strategy registry query failed"
		ok(c, "ok", data)
		return
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
		ok(c, "ok", data)
		return
	}

	data["strategies"] = out

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
	if rej, rejErr := recentRejections(ctx, conn, tenant); rejErr != "" {
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
	case len(out) == 0:
		// An empty registry is the expected first state — core.tenant_strategies
		// has never held a row. Say so, so the workspace can offer the create
		// path instead of rendering a bare empty table that reads as broken.
		data["reason"] = "no strategies yet"
	}
	ok(c, "ok", data)
}

// recentRejections returns submissions this tenant made that failed to compile,
// newest first, with the consumer's own reason. Empty slice on any error — the
// caller treats this as additive context, never as the primary answer.
func recentRejections(ctx context.Context, conn *pgx.Conn, tenant uuid.UUID) ([]map[string]any, string) {
	// Read the ACK, not xpio.strategies.
	//
	// The first version joined xpio.strategies, which only has a row when the
	// submission came through POST /xpio/strategies — the Studio form's path.
	// A submission through the self-serve relay (POST /registry/strategies)
	// writes mailbox.lqt_inbox directly, so it has NO xpio row and its rejection
	// was invisible again. Verified 2026-08-29: a relay submission that the
	// consumer rejected with a precise reason returned 0 rows from that query.
	//
	// mailbox.lqt_outbox is where the reason actually lives, and the consumer
	// writes it for EVERY path — so this covers the form, the relay, and
	// anything else that reaches the inbox. The name comes from the inbox row
	// the ack points back at, so a rejected submission is identifiable even
	// though it never became a strategy.
	const q = `
		SELECT i.payload->>'name'   AS name,
		       o.created_at,
		       o.payload->>'reason' AS reason
		  FROM mailbox.lqt_outbox o
		  JOIN mailbox.processed  p ON p.msg_id = o.payload->>'ack_of'
		  JOIN mailbox.lqt_inbox  i ON i.msg_id = o.payload->>'ack_of'
		 WHERE p.verified_tenant_id = $1
		   AND o.topic = 'strategy.ack'
		   AND o.payload->>'status' = 'rejected'
		 ORDER BY o.created_at DESC
		 LIMIT 20`
	out := []map[string]any{}
	rows, err := conn.Query(ctx, q, tenant)
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
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		fail(c, http.StatusBadRequest, 1400, "strategy id required")
		return
	}
	if strategiesDSN() == "" {
		fail(c, http.StatusServiceUnavailable, 1503, "strategy registry not configured")
		return
	}
	tenant, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		// Cannot own an LQT strategy at all — indistinguishable from not found,
		// and saying so leaks nothing about whether the id exists elsewhere.
		fail(c, http.StatusNotFound, 1404, "strategy not found")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), strategiesOpTimeout)
	defer cancel()
	conn, err := strategiesConnect(ctx)
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, "strategy registry unreachable")
		return
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

	var (
		strategyID, name, kind, status  string
		model, version                  *string
		bytecodeHex, specJSON, progHash string
	)
	err = conn.QueryRow(ctx, q, tenant, id).Scan(
		&strategyID, &name, &kind, &model, &version, &status,
		&bytecodeHex, &specJSON, &progHash)
	if err != nil {
		// No row for THIS tenant. Deliberately the same answer whether the id
		// is unknown or belongs to another tenant — distinguishing them would
		// turn this into an existence oracle over other people's strategies.
		fail(c, http.StatusNotFound, 1404, "strategy not found")
		return
	}

	data := gin.H{
		"strategy_id":  strategyID,
		"name":         name,
		"kind":         kind,
		"model":        model,
		"version":      version,
		"status":       status,
		"program_hash": progHash,
	}
	// The body, in the shape the backtest API and the mailbox both accept:
	// program_hex preferred, dsl as the compile-server-side path.
	if bytecodeHex != "" {
		data["program_hex"] = bytecodeHex
	}
	if specJSON != "" {
		data["spec_json"] = specJSON
	}
	ok(c, "ok", data)
}
