package models

import "time"

// PasswordReset is a single-use token mailed to a user after they
// hit /api/v1/forgot-password. We store sha256(token) — not the
// token itself — so leaking this table can't reveal any live link.
//
// Lifecycle: create with expires_at = now + 30m; mark used_at on
// successful redeem; a nightly cleanup can DELETE rows older than
// 24h (keep a short tail for audit).
type PasswordReset struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    string    `gorm:"type:varchar(36);index;not null" json:"user_id"`
	TokenHash string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	IP        string    `gorm:"type:varchar(64)" json:"ip,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (PasswordReset) TableName() string { return "password_resets" }
