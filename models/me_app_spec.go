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
// table and not a third mechanism: the writer self-reports through the bridge
// and identity reads MySQL.
//
// THE TABLE ALREADY EXISTS, AND THIS STRUCT MUST MATCH IT EXACTLY.
//
// `me_app_specs` was created by an earlier implementation whose Go side was
// later deleted — the table outlived its code, still holding rows, while
// _echo_app_spec went on POSTing into a route that no longer existed. Declaring
// the conventional `ID uint gorm:"primaryKey"` here made AutoMigrate issue
// `ALTER TABLE me_app_specs ADD id ... ADD PRIMARY KEY (id)` against a table
// that already has `PRIMARY KEY (user_sub, app)`; MySQL answers 1068 "Multiple
// primary key defined", AutoMigrate returns an error, and identity refuses to
// start. Shipped as v0.5.382 and crash-looped the new pod on 2026-09-16.
//
// So: composite primary key, no surrogate id, and the column types are the ones
// on disk. `spec_yaml`/`ui_files` are LONGTEXT — declaring mediumtext would make
// AutoMigrate NARROW a live column. `app` is varchar(64), not 128, so migration
// is a no-op rather than a lock on a table other code is reading.
type MeAppSpec struct {
	UserSub string `gorm:"column:user_sub;size:36;not null;primaryKey"  json:"user_sub"`
	App     string `gorm:"column:app;size:64;not null;primaryKey"       json:"app"`

	SpecYAML string `gorm:"column:spec_yaml;type:longtext" json:"-"`
	// ui_files, as the JSON object the echo sent. Same verbatim rule.
	UIFiles string `gorm:"column:ui_files;type:longtext" json:"-"`

	UpdatedAt time.Time `gorm:"column:updated_at" json:"updated_at"`
	CreatedAt time.Time `gorm:"column:created_at" json:"created_at"`
}

func (MeAppSpec) TableName() string { return "me_app_specs" }
