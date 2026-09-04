package models

import (
	"time"

	"gorm.io/gorm"
)

// ClaudeQuotaToken — admin-managed token store for org members' Claude
// Code OAuth tokens, keyed by email. Intentionally decoupled from the
// lumid users table so non-lumid Claude Code users (e.g. yuncong@lum.id)
// can be tracked without requiring a lumid account.
type ClaudeQuotaToken struct {
	Email                 string    `gorm:"type:varchar(255);primaryKey"       json:"email"`
	ValueEncrypted        string    `gorm:"type:text;not null"                 json:"-"`
	RefreshTokenEncrypted string    `gorm:"type:text"                          json:"-"`
	CreatedAt             time.Time `gorm:"autoCreateTime"                     json:"created_at"`
	UpdatedAt             time.Time `gorm:"autoUpdateTime"                     json:"updated_at"`
	// RotatedAt is when the OAuth token family was last exchanged — the only
	// honest "last rotation" clock. UpdatedAt cannot serve that role: it is
	// bumped by ANY write to the row, and under load the most frequent writer
	// is claude-proxy's bench reporter, not a rotation. Damping the refresh
	// sweep on UpdatedAt therefore made heavy usage SUPPRESS proactive refresh
	// (every bench pushed the next eligible sweep out by another 22.5 min),
	// letting access tokens drift to expiry until the pool discovered it the
	// expensive way — a burst of 401s and a reactive refresh stampede.
	RotatedAt *time.Time `gorm:"column:rotated_at" json:"rotated_at,omitempty"`
	// Quarantine state: set when Anthropic returns invalid_grant (the token
	// family was revoked — typically rotation-reuse detection after the
	// account owner's own Claude Code refreshed a shared credential copy).
	// While set, every refresh path skips this row instead of re-presenting
	// a revoked token; a re-add via AdminClaudeTokenAdd clears it.
	RevokedAt    *time.Time `gorm:"column:revoked_at"                    json:"revoked_at,omitempty"`
	RevokeReason string     `gorm:"column:revoke_reason;size:512"        json:"revoke_reason,omitempty"`
	// Label — optional free-form tag (e.g. "dublin") marking this account as
	// belonging to a field box. When set AND a relay is configured for it in
	// LUMID_CLAUDE_FIELD_RELAYS, both claude-proxy's Messages API dispatch and
	// this service's own OAuth refresh call for this account are routed
	// through that box's relay instead of the default direct path, so every
	// Anthropic-facing call this account makes originates from its one home
	// network. Unset accounts (the default, and every account that predates
	// this field) are completely unaffected.
	//
	// Label is NOT the pool. Label groups accounts by physical EGRESS NETWORK
	// (routing only); PoolID groups them by WHO MAY DRAW ON THEM (access
	// control). An account has exactly one of each, and the two are
	// orthogonal — a pool can freely mix labelled and unlabelled accounts.
	Label string `gorm:"column:label;size:64" json:"label,omitempty"`
	// PoolID — the ClaudePool this account belongs to. An account is a single
	// Anthropic subscription credential, so it belongs to exactly one pool
	// (unlike users, who may hold membership in several — see ClaudePoolMember).
	// Defaults to "default", the pool every pre-existing account is backfilled
	// into (see EnsureDefaultClaudePool), so this column is a no-op for any
	// deployment that never creates a second pool.
	PoolID string `gorm:"column:pool_id;size:64;index;not null;default:'default'" json:"pool_id"`
	// PoolSortOrder — this account's position in its pool's CONSERVATIVE-mode
	// fill order (ascending; ties broken by CreatedAt ascending, so an
	// untouched pool orders itself by add-order with no admin input needed).
	// Meaningless in a "distributed" pool, kept unconditionally so toggling a
	// pool's mode back to conservative doesn't need every account's order
	// re-entered.
	PoolSortOrder int `gorm:"column:pool_sort_order;not null;default:0" json:"pool_sort_order,omitempty"`
	// Bench state: a POOL-WIDE cooldown reported by claude-proxy after Anthropic
	// returned 401/403 for this account. claude-proxy benches locally too, but
	// its state is per-process, so with >1 replica the sibling pod kept leasing
	// a credential another pod had already proven bad — re-presenting a dead
	// token to Anthropic indefinitely. Persisting it here makes the bench apply
	// to every replica.
	//
	// Distinct from RevokedAt: that means the token FAMILY is gone (invalid_grant
	// on refresh, unrecoverable without a re-add), whereas a bench is a timed
	// cooldown that usually expires on its own.
	BenchUntil  *time.Time `gorm:"column:bench_until"        json:"bench_until,omitempty"`
	BenchReason string     `gorm:"column:bench_reason;size:512" json:"bench_reason,omitempty"`
	// BenchDead marks a bench that reached claude-proxy's consecutive-failure
	// threshold. It is not self-clearing on a stray success — recovery is a
	// deliberate operator re-add, matching the alert text the proxy emits.
	BenchDead bool `gorm:"column:bench_dead;not null;default:false" json:"bench_dead,omitempty"`
	// ── Operator drain ────────────────────────────────────────────────────────
	//
	// DrainingSince marks an account an operator has PAUSED from lum.id/code. It
	// is a graceful drain, deliberately not a bench:
	//
	//   - Placement stops using it as a TARGET, so nobody is newly homed here.
	//   - Lease-time keeps serving users already homed or session-pinned here,
	//     so conversations in flight finish on the subscription that started
	//     them. Refusing them instead would make claude-proxy hit
	//     sessionPinMaxWait and fire PIN RELEASED, splitting the session across
	//     subscriptions — the exact suspension signal a pause exists to avoid.
	//   - Users drift off as they go idle, on the normal placement cadence. That
	//     drift IS the safe transfer; there is no deadline and no forced move.
	//
	// A timestamp rather than a bool so the dashboard can say how long a drain
	// has been running, and so an abandoned one is visible rather than silent.
	// Unlike BenchUntil this NEVER expires on its own — a pause that quietly
	// resumed itself would be worse than no pause at all.
	DrainingSince *time.Time `gorm:"column:draining_since"        json:"draining_since,omitempty"`
	DrainReason   string     `gorm:"column:drain_reason;size:512" json:"drain_reason,omitempty"`
	// ── Refresh-exchange forensics ────────────────────────────────────────────
	//
	// Added 2026-08-14. When all four pooled accounts were quarantined on
	// 2026-08-13 there was nothing to diagnose from: the logs died with the pods
	// (no aggregation since the obs stack was removed) and the row recorded only
	// that the family was gone, not what the last exchange did. Two theories —
	// a second credential holder, and a LOST RESPONSE (request lands, Anthropic
	// rotates, response never arrives, so we keep a token it has superseded) —
	// were indistinguishable after the fact. These fields make the next
	// occurrence answerable from the row alone.
	//
	// LastExchangeAt/Outcome/Ms record every attempt, success or not.
	LastExchangeAt      *time.Time `gorm:"column:last_exchange_at"                json:"last_exchange_at,omitempty"`
	LastExchangeOutcome string     `gorm:"column:last_exchange_outcome;size:64"  json:"last_exchange_outcome,omitempty"`
	LastExchangeMs      int        `gorm:"column:last_exchange_ms"               json:"last_exchange_ms,omitempty"`
	// IndeterminateAt is the load-bearing one: set when a request was SENT but
	// no response was read (timeout, connection reset, pod killed mid-flight).
	// After that instant our stored refresh token may already be superseded
	// upstream while looking perfectly valid here — the family is in an unknown
	// state and the next exchange is the one that will discover it. It is NOT
	// cleared by a later success, so it survives as the evidence trail; compare
	// it against RevokedAt to see whether a quarantine followed an indeterminate
	// exchange (lost-response) or a clean one (something else entirely).
	IndeterminateAt     *time.Time `gorm:"column:indeterminate_at"               json:"indeterminate_at,omitempty"`
	IndeterminateReason string     `gorm:"column:indeterminate_reason;size:512"  json:"indeterminate_reason,omitempty"`
	// PreExpiry401At — our access token was refused while still INSIDE its own
	// JWT expiry. A token that merely aged out is routine; one refused mid-life
	// means the family was invalidated under us, which is the clearest evidence
	// of a SECOND HOLDER — the dominant quarantine cause here (a machine that
	// minted the credential and kept running Claude Code, refreshing the family
	// on its own schedule).
	//
	// refreshSnapshot has always DETECTED this and threaded a marker through the
	// caller string, but that reached only the log line and — solely if a
	// quarantine happened to follow — revoke_reason. A pre-expiry 401 whose
	// refresh then succeeds was logged and forgotten, and since the obs stack
	// was torn down logs die with the pod. Persisting it makes the signal
	// survive the pod, which matters most in the minutes after an add: ac9@yao.lu
	// was quarantined 3m04s after being added, and that window is the only one
	// in which "stop the other holder" is still cheap advice.
	PreExpiry401At     *time.Time `gorm:"column:pre_expiry_401_at"              json:"pre_expiry_401_at,omitempty"`
	PreExpiry401Reason string     `gorm:"column:pre_expiry_401_reason;size:512" json:"pre_expiry_401_reason,omitempty"`
	// LastLeasedAt — when this account was last handed to a caller.
	//
	// The pool's own definition of "in use". Every refresh exchange is a draw at
	// the lost-response window that permanently kills a family, so an account
	// nobody leases should not be paying that cost on a 45-minute timer: see
	// accountIsDormant. Stamped by the lease path (throttled — it only needs to
	// be accurate to a few minutes), so an account wakes out of dormancy the
	// instant it is used again.
	//
	// Deliberately NOT inferred from snapshots or usage_events: snapshots are
	// written by the background sweeper too (so they stay fresh on an idle
	// account, which is exactly backwards), and usage_events is keyed by user,
	// not by account.
	LastLeasedAt *time.Time `gorm:"column:last_leased_at" json:"last_leased_at,omitempty"`
	// DeletedAt — TOMBSTONE, not a convenience.
	//
	// AdminClaudeTokenDelete used to hard-DELETE this row and cascade the
	// account's claude_quota_snapshots with it. Removing a quarantined account
	// is the FIRST thing an operator does during an incident, so that erased
	// exactly the evidence the forensics columns above exist to preserve —
	// revoke_reason, rotated_at, indeterminate_at, pre_expiry_401_at,
	// last_exchange_* — plus the snapshot history the sibling-comparison
	// technique needs (an account's token lifetime is only interpretable
	// against the ones minted alongside it).
	//
	// It has now cost two post-mortems. On 2026-08-21 ac2@nati and ac3@nati
	// were quarantined 2m01s apart, deleted 4h20m later, and the incident was
	// only reconstructable because identity's pod logs happened not to have
	// rotated yet. That is not a control.
	//
	// Soft delete keeps the row and every column on it while removing the
	// account from the pool: GORM excludes deleted rows from Find/First
	// automatically, so lease, sweep, placement and pool-health all stop
	// seeing it with no change at their call sites. A re-add resurrects the
	// tombstone in place — see the deleted_at entry in AdminClaudeTokenAdd's
	// update set, without which the ON DUPLICATE KEY UPDATE would write the
	// new credential onto a row that stays invisible.
	DeletedAt gorm.DeletedAt `gorm:"column:deleted_at;index" json:"-"`
}

func (ClaudeQuotaToken) TableName() string { return "claude_quota_tokens" }

// ClaudeQuotaSnapshot — one row per account per poll cycle.
// Stores the latest snapshot from https://claude.ai/api/oauth/usage.
// The reporter script (run as a cron or stop-hook on each machine)
// POSTs to /api/v1/internal/claude-quota/report; this table is the
// sink. The admin endpoint aggregates the latest row per account.
type ClaudeQuotaSnapshot struct {
	ID    uint64    `gorm:"primaryKey;autoIncrement"                                json:"id"`
	Email string    `gorm:"column:email;size:255;index:idx_cqs_email_ts,priority:1;not null" json:"email"`
	Ts    time.Time `gorm:"column:ts;index:idx_cqs_email_ts,priority:2;autoCreateTime"       json:"ts"`
	// Active window summary
	FiveHourPct   float64   `gorm:"column:five_hour_pct;not null;default:0"  json:"five_hour_pct"`
	SevenDayPct   float64   `gorm:"column:seven_day_pct;not null;default:0"  json:"seven_day_pct"`
	FiveHourReset time.Time `gorm:"column:five_hour_reset"  json:"five_hour_reset"`
	SevenDayReset time.Time `gorm:"column:seven_day_reset"  json:"seven_day_reset"`
	// Active severity (normal / warning / critical)
	Severity string `gorm:"column:severity;size:16;not null;default:'normal'" json:"severity"`
	// Full raw payload for debugging / dashboard enrichment
	Raw string `gorm:"column:raw;type:text" json:"raw"`
}

func (ClaudeQuotaSnapshot) TableName() string { return "claude_quota_snapshots" }
