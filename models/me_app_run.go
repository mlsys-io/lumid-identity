package models

import "time"

// MeAppRun — a generic, cross-node run record for ANY xpio app cycle (not tied
// to a specific app/dataset/workflow). Run trajectory + experiment metrics are
// runtime data on the scheduler PVC that identity (svc node) can't read; this
// table is the cross-node channel so the Studio trajectory + experiments
// surfaces reconstruct run history for any app. Written by the cycle
// self-report (POST /internal/app-runs) for Run-now + scheduled runs, and
// backfillable from historical scans. Idempotent on (user_sub, app, loop, run_ts).
//
// Universal columns only (run_ts, model, ok, duration). App-specific metrics go
// into the opaque `Metrics` JSON blob; the trajectory score + experiment series
// are pulled from it by the app's OWN declared metric name (experiments[].metric.name),
// so nothing here is hardcoded to any one app's metric shape.
type MeAppRun struct {
	ID      uint   `gorm:"primaryKey"                                                     json:"-"`
	UserSub string `gorm:"column:user_sub;size:36;not null;uniqueIndex:uq_apprun,priority:1" json:"user_sub"`
	App     string `gorm:"column:app;size:128;not null;uniqueIndex:uq_apprun,priority:2"     json:"app"`
	Loop    string `gorm:"column:loop;size:128;not null;uniqueIndex:uq_apprun,priority:3"    json:"loop"`
	RunTs   int64  `gorm:"column:run_ts;not null;uniqueIndex:uq_apprun,priority:4"           json:"run_ts"`

	Model     string    `gorm:"column:model;size:64"             json:"model,omitempty"`
	Ok        bool      `gorm:"column:ok"                        json:"ok"`
	DurationS *float64  `gorm:"column:duration_s"                json:"duration_s,omitempty"`
	Metrics   string    `gorm:"column:metrics;type:text"         json:"-"`                // opaque JSON — the cycle's own summary
	Source    string    `gorm:"column:source;size:24"            json:"source,omitempty"` // self_report | backfill
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeAppRun) TableName() string { return "me_app_runs" }
