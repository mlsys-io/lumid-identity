package models

import "time"

// MeAppExperiment — the evaluated state of ONE experiment, for ONE user, as a
// cross-node record.
//
// The runtime ledger (.lumid/experiments/<id>/{results.jsonl,state.json}) is
// written by sdk/apps/experiments.py onto the SCHEDULER's volume. Identity
// mounts no tenant volume, so for a tenant app it reads its own materialised
// copy of the published bundle — which carries the DECLARATION and never the
// results. Measured 2026-09-04: mbb-consultant's judge_panel_parity held a real
// row (n=1, panel_median3, avg_question_score 0.204) while
// GET /me/apps/:app/experiments answered n=0, variants=[]. The panel showed
// declared arms that could never display a result.
//
// Same shape of problem as MeAppRun, so the same answer: the cycle self-reports
// through the bridge and identity reads MySQL.
//
// `State` is the state.json blob VERBATIM — deliberately opaque. evaluate()
// already applies the dataset_version fence and the compare_within instrument
// guard; recomputing any of that here would put two implementations of one
// metric in the codebase, which is exactly how mbb-ai got a spurious +16pp from
// definition drift. Identity stores and serves; it does not judge.
type MeAppExperiment struct {
	ID           uint   `gorm:"primaryKey"                                                       json:"-"`
	UserSub      string `gorm:"column:user_sub;size:36;not null;uniqueIndex:uq_appexp,priority:1" json:"user_sub"`
	App          string `gorm:"column:app;size:128;not null;uniqueIndex:uq_appexp,priority:2"     json:"app"`
	ExperimentID string `gorm:"column:experiment_id;size:128;not null;uniqueIndex:uq_appexp,priority:3" json:"experiment_id"`

	State     string    `gorm:"column:state;type:text"           json:"-"` // state.json, verbatim
	NResults  int       `gorm:"column:n_results"                 json:"n_results"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeAppExperiment) TableName() string { return "me_app_experiments" }
