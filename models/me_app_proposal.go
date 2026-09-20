package models

import "time"

// MeAppProposal — the newest slate of CANDIDATE experiments for one app, for
// one user.
//
// WHY THIS IS A TABLE AND NOT AN INTENT.
//
// The obvious design is an intent: a chat turn asks identity to stage a slate,
// identity queues `stage_proposals`, the scheduler writes
// `.lumid/proposals/<ts>.json` into the bundle on its PVC. That produces a
// panel that is empty forever. Identity mounts NO tenant volume — measured, its
// only volumeMount is signing-keys — so `resolveAppDir` falls back to
// materialising the PUBLISHED bundle, and `.lumid/` is runtime state that
// publishing does not carry. The scheduler would write a file identity can
// never read.
//
// This is the same wall MeAppExperiment, MeAppRun and MeAppSpec each hit, and
// it gets the same answer: the producer self-reports through the bridge and
// identity serves MySQL. An intent moves work TO the scheduler; the problem
// here is getting data BACK from it.
//
// ONE ROW PER (user, app). A slate supersedes rather than accumulates — the
// file reader already takes the newest file and ignores older ones, so keeping
// history here would create a second, disagreeing notion of "current". The
// superseded slate stays on disk wherever it was produced.
//
// `Slate` is the verb's output blob VERBATIM, deliberately opaque. The
// annotation pass in the app bundle already decided each candidate's verdict
// against the metric keys that bundle actually emits; re-deriving any of that
// here would put two implementations of one judgement in the codebase, which is
// exactly how mbb-ai produced a spurious +16pp from definition drift. Identity
// stores and serves; it does not judge.
type MeAppProposal struct {
	ID      uint   `gorm:"primaryKey"                                                        json:"-"`
	UserSub string `gorm:"column:user_sub;size:36;not null;uniqueIndex:uq_appprop,priority:1" json:"user_sub"`
	App     string `gorm:"column:app;size:128;not null;uniqueIndex:uq_appprop,priority:2"     json:"app"`

	// The `annotate` result, verbatim: {ts, n, will_collect, will_be_invisible,
	// proposals:[...]}. LONGTEXT because a slate carries every candidate's full
	// findings list, and truncating it would silently drop the reasons that are
	// the whole point of surfacing a blocked candidate.
	Slate string `gorm:"column:slate;type:longtext" json:"-"`

	// Denormalised for listing without parsing the blob. These are REPORTED by
	// the producer, not recomputed here — see the note above about not
	// re-deriving judgements.
	SlateTs         int64 `gorm:"column:slate_ts"          json:"slate_ts"`
	N               int   `gorm:"column:n"                 json:"n"`
	WillCollect     int   `gorm:"column:will_collect"      json:"will_collect"`
	WillBeInvisible int   `gorm:"column:will_be_invisible" json:"will_be_invisible"`

	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeAppProposal) TableName() string { return "me_app_proposals" }
