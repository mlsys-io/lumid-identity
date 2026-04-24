package models

import "time"

// SSHKey is a user-uploaded public SSH key. We store the public half only.
// Fingerprint is SHA256 (base64, no prefix, as `ssh-keygen -lf` prints
// minus the "SHA256:" label) so we can index + deduplicate.
//
// Note: this is the key-storage side. Actual SSH-server-for-push is a
// separate service (xp.io's git-over-SSH gateway, still on the roadmap).
// Uploading a key here is useful today for commit-signature verification
// + future SSH push.
type SSHKey struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID      string    `gorm:"type:varchar(36);index;not null" json:"user_id"`
	Title       string    `gorm:"type:varchar(128);not null" json:"title"`
	PublicKey   string    `gorm:"type:text;not null" json:"public_key"`
	Fingerprint string    `gorm:"type:varchar(64);uniqueIndex;not null" json:"fingerprint"`
	KeyType     string    `gorm:"type:varchar(32);not null" json:"key_type"` // "ssh-ed25519", "ssh-rsa", …
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func (SSHKey) TableName() string { return "ssh_keys" }
