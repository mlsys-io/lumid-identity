package models

import "time"

// ClaudeQuotaTokenHistory is an append-only forensic snapshot of a
// ClaudeQuotaToken row, taken at the two points that overwrite it:
// quarantine (revoked_at/revoke_reason get SET) and re-add
// (AdminClaudeTokenAdd's upsert clears them to restore service).
//
// WHY THIS EXISTS: the verdict text ClaudeQuotaToken.RevokeReason carries —
// LOST-RESPONSE SUSPECTED / REVOKED-UPSTREAM / SECOND-HOLDER OR UPSTREAM
// REVOCATION — is the one fact that tells an operator what to actually do.
// But claudeTokenReAddColumns resets exactly that column as part of
// "clear the quarantine", which is also the FIRST thing an operator does
// during the outage it explains. Recovery and forensics were the same
// write, so fixing the account destroyed the diagnosis, every time. This
// is the same lesson ClaudeQuotaToken.DeletedAt already encodes for
// hard-delete (see its doc comment, citing the 2026-08-21 ac2/ac3
// incident) — a recovery action must never be the only copy of the
// evidence it explains.
//
// Fields mirror ClaudeQuotaToken's forensic columns by value, not by
// reference, so a snapshot survives the source row's own fields being
// reset or reused by a later credential.
type ClaudeQuotaTokenHistory struct {
	ID    uint64 `gorm:"primaryKey;autoIncrement"                                          json:"id"`
	Email string `gorm:"column:email;size:255;index:idx_cqth_email_ts,priority:1;not null" json:"email"`
	// Event — what triggered this snapshot: "quarantined" (revoked_at was
	// just set) or "re_added" (an operator's re-add is about to clear it).
	Event      string    `gorm:"column:event;size:32;not null"                                     json:"event"`
	RecordedAt time.Time `gorm:"column:recorded_at;autoCreateTime;index:idx_cqth_email_ts,priority:2" json:"recorded_at"`

	Label               string     `gorm:"column:label;size:64"                  json:"label,omitempty"`
	RevokedAt           *time.Time `gorm:"column:revoked_at"                     json:"revoked_at,omitempty"`
	RevokeReason        string     `gorm:"column:revoke_reason;size:512"         json:"revoke_reason,omitempty"`
	IndeterminateAt     *time.Time `gorm:"column:indeterminate_at"               json:"indeterminate_at,omitempty"`
	IndeterminateReason string     `gorm:"column:indeterminate_reason;size:512"  json:"indeterminate_reason,omitempty"`
	PreExpiry401At      *time.Time `gorm:"column:pre_expiry_401_at"              json:"pre_expiry_401_at,omitempty"`
	PreExpiry401Reason  string     `gorm:"column:pre_expiry_401_reason;size:512" json:"pre_expiry_401_reason,omitempty"`
	RotatedAt           *time.Time `gorm:"column:rotated_at"                     json:"rotated_at,omitempty"`
	LastExchangeAt      *time.Time `gorm:"column:last_exchange_at"               json:"last_exchange_at,omitempty"`
	LastExchangeOutcome string     `gorm:"column:last_exchange_outcome;size:64"  json:"last_exchange_outcome,omitempty"`
	LastExchangeMs      int        `gorm:"column:last_exchange_ms"               json:"last_exchange_ms,omitempty"`
	BenchUntil          *time.Time `gorm:"column:bench_until"                    json:"bench_until,omitempty"`
	BenchReason         string     `gorm:"column:bench_reason;size:512"          json:"bench_reason,omitempty"`
	BenchDead           bool       `gorm:"column:bench_dead;not null;default:false" json:"bench_dead,omitempty"`
	DrainingSince       *time.Time `gorm:"column:draining_since"                 json:"draining_since,omitempty"`
	DrainReason         string     `gorm:"column:drain_reason;size:512"          json:"drain_reason,omitempty"`
}

func (ClaudeQuotaTokenHistory) TableName() string { return "claude_quota_token_history" }
