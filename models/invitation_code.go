package models

import "time"

// InvitationCode is a redeemable code that an admin mints and hands
// out. A code's uses_remaining counts down each time a user claims
// it at /register; max_uses=0 means unlimited. revoked_at kills a
// code before it's fully consumed.
type InvitationCode struct {
	Code           string     `gorm:"type:varchar(64);primaryKey" json:"code"`
	CreatedByID    string     `gorm:"type:varchar(36);index;not null" json:"created_by_id"`
	Note           string     `gorm:"type:varchar(255)" json:"note,omitempty"`
	MaxUses        int        `gorm:"default:1" json:"max_uses"`
	UsesRemaining  int        `gorm:"default:1" json:"uses_remaining"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedAt      time.Time  `gorm:"autoCreateTime" json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
}

func (InvitationCode) TableName() string { return "invitation_codes" }
