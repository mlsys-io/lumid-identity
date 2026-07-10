package models

import "time"

// MeDoc — DB-backed store for the small per-user JSON documents that used to
// live as files under tenantRoot(user)/.{chats,personas,artifacts} on the
// identity pod's LOCAL filesystem.
//
// Why: identity went HA (replicas=2, task #34) with the RS256 keyring moved
// to a shared Secret — but these file stores stayed pod-local, so every
// round-robined GET of a fresh chat was a coin flip (observed live
// 2026-07-10: sequential GETs of one chat returned 404/200 alternating).
// Same failure class as the /me/apps file queue MeAppIntent replaced.
//
// One table for all three kinds — they are all opaque JSON documents keyed
// (user, kind, id) with identical CRUD; handlers marshal/unmarshal their own
// record shapes. Doc is LONGTEXT: chat message arrays can exceed 64KB.
type MeDoc struct {
	UserSub   string    `gorm:"column:user_sub;size:36;not null;primaryKey"`
	Kind      string    `gorm:"column:kind;size:16;not null;primaryKey"` // chat | persona | artifact
	DocID     string    `gorm:"column:doc_id;size:64;not null;primaryKey"`
	Doc       string    `gorm:"column:doc;type:longtext"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;index:idx_medoc_recent"`
}

func (MeDoc) TableName() string { return "me_docs" }
