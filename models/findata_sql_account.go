package models

import "time"

// FindataSQLAccount maps a lum.id user to their Postgres login on the FinData
// warehouse (`sql_<name>`, see deploy_infra k8s-lift/findata-sql/README.md §8).
//
// WHY THIS TABLE EXISTS RATHER THAN DERIVING THE NAME
// The role name is derived from the user's email local part, and the obvious
// implementation is to re-derive it wherever it is needed. That is how the two
// derivations drift: the roster script that CREATED the roles resolves
// collisions by suffixing (`alice`, `alice2`), which is stateful, so a pure
// function cannot reproduce it. A user whose name silently re-derived to a
// different role would be issued a credential for a role that is not theirs —
// or worse, for someone else's.
//
// So the mapping is recorded once, at provisioning time, and read thereafter.
// RoleName is unique because two users sharing a warehouse login would defeat
// the per-user attribution that is the entire reason these roles exist.
type FindataSQLAccount struct {
	ID     string `gorm:"type:varchar(36);primaryKey"          json:"id"`
	UserID string `gorm:"type:varchar(36);uniqueIndex;not null" json:"user_id"`
	// The Postgres role, INCLUDING the `sql_` prefix, exactly as it exists on
	// the warehouse.
	RoleName string `gorm:"type:varchar(63);uniqueIndex;not null" json:"role_name"`

	// Mirrors what was last written to pgbouncer_auth.credentials, so the UI can
	// show "expires in N days" without reaching across to Postgres on every
	// page load. Postgres remains authoritative — this is a cache, and a stale
	// value here can never grant access, only misreport it.
	CredentialExpiresAt *time.Time `json:"credential_expires_at,omitempty"`
	LastMintedAt        *time.Time `json:"last_minted_at,omitempty"`

	// AES-256-GCM via common.EncryptGrant, same as app_secrets. Empty until the
	// user mints, and cleared on revoke.
	//
	// WHY THIS EXISTS, GIVEN THE HANDLER ONCE ARGUED THE OPPOSITE. The original
	// design returned the password once and dropped it, reasoning that a SQL
	// password "never needs replaying: the user has it". That premise no longer
	// holds — the session/sandbox runs the query on the user's behalf, so the
	// user never handles the password and something must be able to replay it.
	// Once a secret is replayable, this repo's convention is EncryptGrant (the
	// same call google_grants and app_secrets use).
	//
	// The cost the old comment named is real and does not go away: this is a
	// second place to steal it from. Two things bound it. It is NEVER returned
	// on a user-authenticated route — only over the bridge-authed internal
	// endpoint, so a stolen user PAT cannot read it. And the credential it
	// protects is read-only, expires in 7 days, and is capped at 4 connections.
	//
	// `json:"-"` is load-bearing: FindataSQLAccount is returned to the browser
	// by MeFindataSQL, and without this the ciphertext would ride along.
	PasswordEncrypted string `gorm:"type:text" json:"-"`

	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (FindataSQLAccount) TableName() string { return "findata_sql_accounts" }
