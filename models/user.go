package models

import "time"

// User is the canonical identity record. Every downstream service
// (QuantArena, Runmesh, FlowMesh, Lumilake, Umami) FKs its local
// profile table at User.ID. Email is the uniqueness constraint —
// stored lowercased to make MySQL's case-sensitive collation behave
// like Postgres citext.
type User struct {
	ID            string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	Email         string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	EmailVerified bool      `gorm:"default:false" json:"email_verified"`
	PasswordHash  string    `gorm:"type:varchar(255)" json:"-"` // bcrypt; may be empty for OAuth-only users
	Name          string    `gorm:"type:varchar(255)" json:"name,omitempty"`
	AvatarURL     string    `gorm:"type:mediumtext" json:"avatar_url,omitempty"` // may be http URL or base64 data URL
	Role          string    `gorm:"type:varchar(32);default:'user'" json:"role"`
	Status        string    `gorm:"type:varchar(16);default:'active'" json:"status"` // active | suspended | pending
	// InvitationCodeUsed preserves LQA's existing invitation gating.
	// Migrated from tbl_user.invitation_code; may drop in Phase 8.
	InvitationCodeUsed string    `gorm:"type:varchar(64)" json:"invitation_code_used,omitempty"`
	CreatedAt          time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (User) TableName() string { return "users" }

// Identity links an external provider account to a User. A single
// user can have multiple identities (local password + Google +
// GitHub). The (provider, provider_sub) pair is the unique external
// key; provider_sub is the provider's stable user id.
type Identity struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID      string    `gorm:"type:varchar(36);index;not null" json:"user_id"`
	Provider    string    `gorm:"type:varchar(32);not null" json:"provider"` // local | google | github
	ProviderSub string    `gorm:"type:varchar(255);not null" json:"provider_sub"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (Identity) TableName() string { return "identities" }
