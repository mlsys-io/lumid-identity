package models

import "time"

// MeAppSpec — an installed app's OWN spec, for ONE user, as a cross-node record.
//
// The declaration half of the problem MeAppExperiment solves for results.
//
// identity mounts no tenant volume, so for a tenant app resolveAppDir falls back
// to materialising the app's PUBLISHED bundle. That copy is fine until someone
// edits the INSTALL — and define_experiment / experiment_control do exactly that,
// through the scheduler, and never publish. So an experiment the user had just
// defined was absent from the only bundle identity could read, list_experiments
// showed only what had been published, and add_experiment_arm answered
// "experiment not found" forever (chiquanji@gmail.com, 2026-09-16).
//
// It is not only experiments: loops, datasets and the UI surface are read from
// the same spec, so every one of them showed the published shape rather than the
// installed one, for every tenant, with nothing anywhere reporting a difference.
//
// Same answer as MeAppRun and MeAppExperiment, which is why this is a third
// table rather than a third mechanism: the writer self-reports through the
// bridge and identity reads MySQL.
//
// `SpecYAML` is the spec file VERBATIM. Identity stores and serves the text; it
// does not parse, normalise or re-serialise it. The scheduler edits these files
// TEXTUALLY on purpose — a yaml round-trip destroyed 58 comments in one pass and
// those comments are the decision record — and a store that reformatted them on
// the way through would undo that from the other end.
type MeAppSpec struct {
	ID      uint   `gorm:"primaryKey"                                                        json:"-"`
	UserSub string `gorm:"column:user_sub;size:36;not null;uniqueIndex:uq_appspec,priority:1" json:"user_sub"`
	App     string `gorm:"column:app;size:128;not null;uniqueIndex:uq_appspec,priority:2"     json:"app"`

	SpecYAML string `gorm:"column:spec_yaml;type:mediumtext" json:"-"`
	// ui_files, as the JSON object the echo sent. Same verbatim rule.
	UIFiles string `gorm:"column:ui_files;type:mediumtext" json:"-"`
	// Where the echo read it from, for diagnosing a tenant/operator mix-up.
	SpecPath string `gorm:"column:spec_path;size:512" json:"spec_path,omitempty"`

	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeAppSpec) TableName() string { return "me_app_specs" }
