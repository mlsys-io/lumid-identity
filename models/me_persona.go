package models

import "time"

// MePersona — a user-defined Studio chat persona (custom system prompt +
// optional tool allowlist + display label).
//
// These were JSON files under `tenantRoot(user)/.personas/` on the pod's own
// container filesystem — the same replica split MeChat was moved off for:
// lumid-identity runs replicas behind a round-robin Service with no shared
// volume, so a persona saved on one pod did not exist on the other. The list
// showed it half the time, the chat applied it half the time, and a delete
// could 404 against the pod that never had it.
//
// AllowedTools stays a JSON array in a text column: it is only ever read
// whole, and a join table would be storage in lockstep with a UI list.
type MePersona struct {
	ID      string `gorm:"column:id;size:32;primaryKey"                                               json:"id"`
	UserSub string `gorm:"column:user_sub;size:36;not null;index:idx_mepersona_user_updated,priority:1" json:"user_sub"`

	Name           string `gorm:"column:name;size:255"            json:"name"`
	Icon           string `gorm:"column:icon;size:64"             json:"icon,omitempty"`
	SystemPrompt   string `gorm:"column:system_prompt;type:text"  json:"system_prompt"` // handler caps at 16 KB
	AllowedTools   string `gorm:"column:allowed_tools;type:text"  json:"-"`             // JSON []string; "" = full catalog
	PreferredModel string `gorm:"column:preferred_model;size:128" json:"preferred_model,omitempty"`

	CreatedAt time.Time `gorm:"column:created_at"                                            json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime:false;index:idx_mepersona_user_updated,priority:2" json:"updated_at"` // set by the handler: what the API returned is what is stored
}

func (MePersona) TableName() string { return "me_personas" }
