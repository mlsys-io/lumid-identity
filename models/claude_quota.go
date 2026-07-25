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
