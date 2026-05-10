package models

import "time"

// GoogleGrant — one row per user holding their encrypted Google
// refresh-token and the scopes they consented to.
//
// The refresh-token is encrypted at rest with AES-256-GCM keyed off
// IDENTITY_GRANT_KEY (or a deterministic derivation from the active
// signing key when the env var is unset — the latter is fine for dev
// but production deployments MUST set IDENTITY_GRANT_KEY explicitly
// so the cipher survives signing-key rotation).
//
// `user_sub` matches `users.id` — same UUID that flows through the
// lm_session JWT's `sub` claim; that claim is what the personal-agent
// CLI uses to look up its grant.
type GoogleGrant struct {
	UserSub                string     `gorm:"primaryKey;column:user_sub;size:36" json:"user_sub"`
	RefreshTokenEncrypted  string     `gorm:"column:refresh_token_encrypted;type:text;not null" json:"-"`
	Scopes                 string     `gorm:"column:scopes;type:text" json:"scopes"`
	ClientID               string     `gorm:"column:client_id;size:255" json:"client_id"`
	GrantedAt              time.Time  `gorm:"column:granted_at;not null;autoCreateTime" json:"granted_at"`
	LastUsedAt             *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	RevokedAt              *time.Time `gorm:"column:revoked_at" json:"revoked_at,omitempty"`
}

func (GoogleGrant) TableName() string { return "google_grants" }
