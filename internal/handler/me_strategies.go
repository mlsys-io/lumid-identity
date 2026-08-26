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
