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

	Model     string   `gorm:"column:model;size:64"             json:"model,omitempty"`
	Ok        bool     `gorm:"column:ok"                        json:"ok"`
	DurationS *float64 `gorm:"column:duration_s"                json:"duration_s,omitempty"`
	Metrics   string   `gorm:"column:metrics;type:text"         json:"-"` // opaque JSON — the cycle's own summary
	// The cycle's final ARTIFACT, in its own column rather than inside Metrics.
	// metricFromBlob walks the metrics JSON recursively and returns the first
	// key match at ANY depth, so an artifact nested there could answer a metric
	// lookup from the wrong place — a `score` in some payload satisfying a
	// declared metric named `score`. Separate column, no such collision.
	//
	// This exists because identity mounts no tenant volume: MeCycleLog and
	// MeCycleDetail read data/cycles/ off disk, which on identity is empty for
	// every app and every user, so the Outputs tier shipped with no reachable
	// source at all. Same problem MeAppExperiment solves for experiment state,
	// same answer.
	Outputs string `gorm:"column:outputs;type:text"         json:"-"`
	// `events` — what the run SAID, as opposed to what it measured.
	//
	// Offers (the cycle's "criteria met, conclude or promote" prompt) and
	// step_errors both existed only in the cycle dir, on a volume this service
	// does not mount. So the one proactive signal the platform produces reached
	// nobody, and FailureCard could render a failed run with no error text.
	//
	// Its own column, not folded into `outputs`: that field is the cycle's final
	// ARTIFACT and MeAppLatestOutput serves it straight to the Outputs tier,
	// where run events would render as artifact keys.
	Events *string `gorm:"column:events;type:text"                json:"events,omitempty"`
	// `compute_jobs` — WHICH fleet compute jobs this run ran, as a JSON array
	// of {"job_id","site"}.
	//
	// This is an AUTHORIZATION record, not a metric. It is what lets the
	// compute job-status route answer "is this job yours?" instead of proxying
	// any job id any authenticated user happens to learn. Without it that route
	// can only be a service-token proxy over every job on every site.
	//
	// Its own column, not inside `metrics`: metricFromBlob resolves a declared
	// metric name recursively at ANY depth of that blob, so a job_id nested
	// there could answer an app's metric lookup from the wrong place — the same
	// hazard that put `outputs` in its own column.
	//
	// A LIST because dispatch_arms runs N arms inside one cycle; a scalar would
	// record one arm and silently drop the rest, and parallel dispatch is the
	// point of the feature. Each entry carries BOTH halves: every Lumilake read
	// route is /ll/<site>/-scoped and cloud/home/office each answer "not found"
	// for the others' jobs, so an id without a site authorizes nothing.
	ComputeJobs *string   `gorm:"column:compute_jobs;type:text" json:"compute_jobs,omitempty"`
	Source      string    `gorm:"column:source;size:24"            json:"source,omitempty"` // self_report | backfill
	CreatedAt   time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeAppRun) TableName() string { return "me_app_runs" }
