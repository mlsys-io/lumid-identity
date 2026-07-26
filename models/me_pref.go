package models

import "time"

// MePref — one long-term "remember_about_me" memory row for the chat
// agent (the me-prefs bank).
//
// It replaces the old per-pod file at
// ~/.tenants/<sub>/.xp/kg/agents/me-prefs/bank.jsonl. That file lived
// on identity's POD-LOCAL ephemeral filesystem, so with 2 replicas the
// agent's memories flapped by pod and were wiped on every image roll.
// Rows now live in the auth DB so both replicas agree; the legacy file
// is still read as a one-shot fallback during the transition window.
type MePref struct {
	ID        uint      `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	UserID    string    `gorm:"column:user_id;index;size:64"       json:"user_id"`
	MemID     string    `gorm:"column:mem_id;size:32"              json:"mem_id"`
	Content   string    `gorm:"column:content;type:text"           json:"content"`
	Tags      string    `gorm:"column:tags;size:255"               json:"tags,omitempty"`
	CreatedAt time.Time `gorm:"column:created_at"                  json:"created_at"`
}

func (MePref) TableName() string { return "me_prefs" }
