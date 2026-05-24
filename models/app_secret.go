package models

import "time"

// AppSecret — one row per (user, xpio-app, key) for runtime credentials
// the user supplies to their installed apps (LUMID_TOKEN, FINNHUB_TOKEN,
// arbitrary per-app API keys flagged `secret: true` in xpcloud.yaml's
// config_schema).
//
// `value_encrypted` is AES-256-GCM keyed off IDENTITY_GRANT_KEY (same
// key the google_grants table uses). The plaintext is never returned
// in API responses — only presence (`is_set`) is surfaced for the UI.
// CLI / cloud-runtime fetches plaintext on demand via the service-to-
// service introspect path, gated on the user's PAT (`secrets:write`
// or full session JWT).
//
// `user_sub` matches `users.id`. Composite primary key keeps the row
// count tight and supports a single-row read by all three components
// (the natural access pattern for the runner).
type AppSecret struct {
	UserSub        string    `gorm:"primaryKey;column:user_sub;size:36"            json:"user_sub"`
	AppSlug        string    `gorm:"primaryKey;column:app_slug;size:128"           json:"app_slug"`
	Key            string    `gorm:"primaryKey;column:key;size:128"                json:"key"`
	ValueEncrypted string    `gorm:"column:value_encrypted;type:text;not null"     json:"-"`
	CreatedAt      time.Time `gorm:"column:created_at;not null;autoCreateTime"     json:"created_at"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null;autoUpdateTime"     json:"updated_at"`
}

func (AppSecret) TableName() string { return "app_secrets" }
