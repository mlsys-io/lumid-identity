package models

import "time"

// PowerAutomateToken — one row per user holding the SHA-256 hash of
// their inbound webhook secret. The raw token is shown to the user
// ONCE at mint time (it's the value they paste into Power Automate's
// HTTP action URL); only the hash is persisted, so a DB leak can't
// be used to spoof inbound email.
//
// Each user gets ONE active token at a time — minting a fresh one
// rotates by overwriting the row. DELETE clears it (and breaks any
// Power Automate flow that still uses the old URL).
//
// `user_sub` matches `users.id`. The webhook path is
// `/api/v1/inbox/power-automate/<raw_token>` — handler hashes the
// path segment and looks up the matching row.
type PowerAutomateToken struct {
	UserSub    string     `gorm:"primaryKey;column:user_sub;size:36" json:"user_sub"`
	TokenHash  string     `gorm:"column:token_hash;size:64;not null;uniqueIndex" json:"-"`
	IssuedAt   time.Time  `gorm:"column:issued_at;not null;autoCreateTime" json:"issued_at"`
	LastUsedAt *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	UseCount   int64      `gorm:"column:use_count;not null;default:0" json:"use_count"`
}

func (PowerAutomateToken) TableName() string { return "power_automate_tokens" }
