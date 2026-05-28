package models

import "time"

// MicrosoftGrant — one row per user holding their encrypted Microsoft
// Graph refresh-token + the scopes they consented to.
//
// Mirrors GoogleGrant: AES-256-GCM at rest with IDENTITY_GRANT_KEY,
// `user_sub` matches users.id, refresh-token never leaves the server.
//
// Auth model is device-code OAuth against Microsoft's pre-registered
// Graph PowerShell SDK client_id (14d82eec-…) — a public Microsoft-
// verified app present in every tenant by default. The user grants
// per-user delegated consent in their normal corporate sign-in flow;
// no Azure AD app registration in their tenant is required.
//
// `home_account_id` is MSAL's stable account identifier (e.g.
// "<oid>.<tid>"). We persist it so silent refresh can target the same
// account if a user has multiple Microsoft logins in their browser.
type MicrosoftGrant struct {
	UserSub               string     `gorm:"primaryKey;column:user_sub;size:36" json:"user_sub"`
	RefreshTokenEncrypted string     `gorm:"column:refresh_token_encrypted;type:text;not null" json:"-"`
	Scopes                string     `gorm:"column:scopes;type:text" json:"scopes"`
	ClientID              string     `gorm:"column:client_id;size:64" json:"client_id"`
	HomeAccountID         string     `gorm:"column:home_account_id;size:128" json:"home_account_id"`
	UserPrincipalName     string     `gorm:"column:user_principal_name;size:255" json:"user_principal_name"`
	DisplayName           string     `gorm:"column:display_name;size:255" json:"display_name"`
	GrantedAt             time.Time  `gorm:"column:granted_at;not null;autoCreateTime" json:"granted_at"`
	LastUsedAt            *time.Time `gorm:"column:last_used_at" json:"last_used_at,omitempty"`
	RevokedAt             *time.Time `gorm:"column:revoked_at" json:"revoked_at,omitempty"`
}

func (MicrosoftGrant) TableName() string { return "microsoft_grants" }

// MicrosoftGrantPending — transient row tracking an in-flight device-
// code flow. The device_code is itself a short-lived secret (~15 min)
// that authorizes the polling endpoint. We persist it server-side so
// the user's UI can poll without ever holding it client-side.
//
// One row per user_sub; a fresh /connect/init overwrites any prior
// pending row. Rows older than the flow's expires_at are pruned by
// the poll handler.
type MicrosoftGrantPending struct {
	UserSub      string    `gorm:"primaryKey;column:user_sub;size:36" json:"user_sub"`
	DeviceCode   string    `gorm:"column:device_code;type:text;not null" json:"-"`
	UserCode     string    `gorm:"column:user_code;size:32;not null" json:"user_code"`
	VerificationURI string `gorm:"column:verification_uri;size:512;not null" json:"verification_uri"`
	Interval     int       `gorm:"column:interval_seconds;not null" json:"interval_seconds"`
	ExpiresAt    time.Time `gorm:"column:expires_at;not null" json:"expires_at"`
	StartedAt    time.Time `gorm:"column:started_at;not null;autoCreateTime" json:"started_at"`
}

func (MicrosoftGrantPending) TableName() string { return "microsoft_grant_pendings" }
