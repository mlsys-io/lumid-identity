package models

import "time"

// MeasureResult is one measurement, keyed by its content: the instrument, the
// instrument's version (an image digest for the simulator) and the canonical
// inputs. Identical requests from any user resolve to the same row, so a
// measurement runs once and is read many times (/me/measure, 2026-11-26).
//
// The row never says who first ran it to anyone but identity: ExecutorSub is
// the account whose credential advances the upstream job, and is not returned.
type MeasureResult struct {
	Key        string `gorm:"column:mkey;primaryKey;size:64" json:"key"`
	Instrument string `gorm:"column:instrument;size:64;not null;index" json:"instrument"`
	Version    string `gorm:"column:version;size:128;not null" json:"version"`
	Inputs     string `gorm:"column:inputs;type:mediumtext" json:"-"`
	// global | tenant:<sub>. The simulator is seeded and pinned, so global.
	ShareScope string `gorm:"column:share_scope;size:48;not null" json:"share_scope"`
	// queued | running | succeeded | failed
	Status string `gorm:"column:status;size:16;not null;index" json:"status"`
	Result string `gorm:"column:result;type:mediumtext" json:"-"`
	Error  string `gorm:"column:error;size:1024" json:"error,omitempty"`

	Executor    string `gorm:"column:executor;size:16" json:"executor"`
	ExecutorRef string `gorm:"column:executor_ref;size:200" json:"executor_ref,omitempty"`
	ExecutorSub string `gorm:"column:executor_sub;size:36;index" json:"-"`

	// NotBefore: an upstream that paces callers (the LQT gateway's 409) left
	// this row queued; the first read after this time submits it.
	NotBefore *time.Time `gorm:"column:not_before" json:"not_before,omitempty"`
	// NoReuse: the settled result answers the run it came from but must not
	// answer an identical request (a synthetic replay, an unpinned window).
	NoReuse bool `gorm:"column:no_reuse;not null;default:false" json:"no_reuse"`

	// What it used (usage metering, 2026-11-28), from the fleet's per-task
	// usage records at settle. nil = not metered (never 0 for "unknown").
	GPUS    *float64 `gorm:"column:gpu_s" json:"gpu_s,omitempty"`
	CPUS    *float64 `gorm:"column:cpu_s" json:"cpu_s,omitempty"`
	GPUType string   `gorm:"column:gpu_type;size:64" json:"gpu_type,omitempty"`
	// measured | estimated
	Metered string `gorm:"column:metered;size:16" json:"metered,omitempty"`
	// ChargedRequestID: the MeasureRequest that actually ran it (and pays for
	// it). Every other request it answered was reused and costs nothing.
	ChargedRequestID uint `gorm:"column:charged_request_id;not null;default:0" json:"-"`

	Hits      int        `gorm:"column:hits;not null;default:0" json:"hits"`
	ClaimedAt time.Time  `gorm:"column:claimed_at" json:"claimed_at"`
	SettledAt *time.Time `gorm:"column:settled_at" json:"settled_at,omitempty"`
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time  `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (MeasureResult) TableName() string { return "measure_results" }

// MeasureRequest is one user's ask for a measurement: "my measurements",
// quotas and audit. Many requests share one MeasureResult.
type MeasureRequest struct {
	ID       uint   `gorm:"primaryKey" json:"-"`
	UserSub  string `gorm:"column:user_sub;size:36;not null;index:ix_measreq_user,priority:1" json:"-"`
	Key      string `gorm:"column:mkey;size:64;not null;index" json:"key"`
	App      string `gorm:"column:app;size:128" json:"app,omitempty"`
	Workflow string `gorm:"column:workflow;size:128" json:"workflow,omitempty"`
	RunID    string `gorm:"column:run_id;size:200" json:"run_id,omitempty"`
	// cached | joined | submitted | fresh — how this request was served.
	Outcome   string    `gorm:"column:outcome;size:16" json:"outcome"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;index:ix_measreq_user,priority:2" json:"created_at"`
}

func (MeasureRequest) TableName() string { return "measure_requests" }
