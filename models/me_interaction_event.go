package models

import "time"

// MeInteractionEvent — what a person actually DID on an app's Studio surface.
//
// Nothing recorded this. `usage_events` bills metered work, `me_app_runs`
// records cycles that ran, `me_app_intents` records clicks that started a loop
// — but opening a surface, submitting a form, or firing a row action that
// resolves client-side left no trace at all. So "41 tenants installed it and
// 31 submitted a strategy" could be answered, and "how many opened the page and
// left" could not.
//
// Deliberately NARROW. It stores what happened and where, never what was in it:
// no form values, no strategy source, no free-text. `Action` is validated
// against a closed vocabulary at the handler, so this stays a product-analytics
// channel and cannot drift into a general logging sink — which is the failure
// mode that turns an events table into an unbounded one nobody dares prune.
//
// Retention is enforced by StartInteractionReclaimLoop, shipped with it.
// `sessions` is the only other table here with a retention policy, and it got
// one only after 238,758 rows nearly filled a shared 2 Gi PVC that carries the
// auth database.
type MeInteractionEvent struct {
	ID      uint64 `gorm:"primaryKey;autoIncrement"                                          json:"-"`
	UserSub string `gorm:"column:user_sub;size:36;not null;index:idx_mie_app_ts,priority:2"  json:"user_sub"`
	App     string `gorm:"column:app;size:128;not null;index:idx_mie_app_ts,priority:1"      json:"app"`

	// Which surface (the ui.surfaces key), which widget kind, and what the
	// person did. All bounded: surface/widget come from the page spec, action
	// from the closed vocabulary.
	Action  string `gorm:"column:action;size:32;not null"  json:"action"`
	Surface string `gorm:"column:surface;size:128"         json:"surface,omitempty"`
	Widget  string `gorm:"column:widget;size:32"           json:"widget,omitempty"`
	// Target names the thing acted on — a loop name for a form submit, an
	// action label for a row action. A NAME, never a value.
	Target string `gorm:"column:target;size:128" json:"target,omitempty"`

	// Outcome, so a form that always fails is distinguishable from one nobody
	// submits. DurationMs is client-observed and advisory.
	Ok         bool `gorm:"column:ok"          json:"ok"`
	DurationMs int  `gorm:"column:duration_ms" json:"duration_ms,omitempty"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;index:idx_mie_app_ts,priority:3" json:"created_at"`
}

func (MeInteractionEvent) TableName() string { return "me_interaction_events" }
