package models

import "time"

// Token stores both native `lm_*` PATs and imported legacy prefixes
// (rm_pat_*, rmk_*, flm-*) in one table. We keep the raw Prefix so
// lookups can shortcut to a hash check. The Hash is argon2id for
// native lm_* tokens; SHA-256 for imported legacy tokens (can't
// re-hash without the cleartext).
type Token struct {
	ID          string     `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID      string     `gorm:"type:varchar(36);index;not null" json:"user_id"`
	Prefix      string     `gorm:"type:varchar(16);index;not null" json:"prefix"`  // lm_ | rm_pat_ | rmk_ | flm-
	Hash        string     `gorm:"type:varchar(255);index;not null" json:"-"`
	HashAlg     string     `gorm:"type:varchar(16);default:'argon2id'" json:"-"`  // argon2id | sha256
	Name        string     `gorm:"type:varchar(128)" json:"name"`
	Scopes      string     `gorm:"type:text" json:"-"` // space-separated; exposed as []string in API
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Source      string     `gorm:"type:varchar(16);default:'native'" json:"source"` // native | legacy-lqa | legacy-runmesh
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (Token) TableName() string { return "tokens" }

// AuditLog is append-only; captures every auth-relevant event for
// compliance/forensics. Mirrors LQA's tbl_rm_pat_access_log shape.
type AuditLog struct {
	ID         uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID     string    `gorm:"type:varchar(36);index" json:"user_id"`
	TokenID    string    `gorm:"type:varchar(36);index" json:"token_id,omitempty"`
	Event      string    `gorm:"type:varchar(32);not null" json:"event"` // login | logout | mint | revoke | introspect | oauth
	Source     string    `gorm:"type:varchar(32)" json:"source,omitempty"` // lqa | runmesh | flowmesh | lumilake | web
	Method     string    `gorm:"type:varchar(8)" json:"method,omitempty"`
	Path       string    `gorm:"type:varchar(255)" json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMs int       `json:"duration_ms,omitempty"`
	IP         string    `gorm:"type:varchar(45)" json:"ip,omitempty"`
	UserAgent  string    `gorm:"type:varchar(255)" json:"user_agent,omitempty"`
	Detail     string    `gorm:"type:text" json:"detail,omitempty"` // JSON blob
	CreatedAt  time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

func (AuditLog) TableName() string { return "audit_log" }
