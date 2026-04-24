package models

import "time"

// UserAccessGrant is an admin-applied per-service access level override.
//
// Precedence in computeAccess:
//   1. suspended → none (status overrides everything)
//   2. role=admin → admin (role still trumps grants)
//   3. explicit grant exists for user × service → use grant.level
//   4. fall through to role("user") default + PAT-scope upgrades
//
// A grant with level="none" is the admin's way to revoke default read
// access for a regular user on one service without suspending the
// account. Deleting the row falls back to the default (read + PAT).
//
// One row per (user, service) — uniqueness enforced at the DB layer so
// the PUT endpoint can upsert idempotently.
type UserAccessGrant struct {
	ID        string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID    string    `gorm:"type:varchar(36);index;not null;uniqueIndex:uk_user_svc,priority:1" json:"user_id"`
	Service   string    `gorm:"type:varchar(32);not null;uniqueIndex:uk_user_svc,priority:2" json:"service"`
	Level     string    `gorm:"type:varchar(16);not null" json:"level"` // none | read | write | admin
	GrantedBy string    `gorm:"type:varchar(36)" json:"granted_by,omitempty"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"granted_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (UserAccessGrant) TableName() string { return "user_access_grants" }
