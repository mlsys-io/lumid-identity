package models

import "time"

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
	Label string `gorm:"column:label;size:64" json:"label,omitempty"`
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
