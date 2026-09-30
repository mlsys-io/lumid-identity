package models

import "time"

// DeprecatedUse counts calls to a superseded name, one row per name per UTC day.
//
// The verb contract (LumidOS docs/architecture/VERBS.md) removes an alias only
// after two releases with zero use. Pod logs cannot show that: identity's
// stdout rotates in about half an hour, and nothing collects it (Loki was torn
// down 2026-07-04). This table is the durable record the removal waits on.
//
// Surface is "route" (Name = method + route pattern) or "chat_tool" (Name = a
// superseded chat tool the model called by its old name).
type DeprecatedUse struct {
	ID      uint      `gorm:"primaryKey" json:"-"`
	Surface string    `gorm:"column:surface;size:16;not null;uniqueIndex:uq_deprecated_use,priority:1" json:"surface"`
	Name    string    `gorm:"column:name;size:191;not null;uniqueIndex:uq_deprecated_use,priority:2" json:"name"`
	Day     string    `gorm:"column:day;size:10;not null;uniqueIndex:uq_deprecated_use,priority:3" json:"day"`
	Count   int64     `gorm:"column:count;not null;default:0" json:"count"`
	LastAt  time.Time `gorm:"column:last_at" json:"last_at"`
	LastBy  string    `gorm:"column:last_by;size:64" json:"last_by,omitempty"`
}

func (DeprecatedUse) TableName() string { return "deprecated_uses" }
