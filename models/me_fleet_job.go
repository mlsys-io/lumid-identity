package models

import "time"

// MeFleetJob — a compute job run through the Research Fleet API
// (POST /me/fleet/jobs): a FlowMesh compute graph or a Lumilake workflow, on
// one site, owned by the user who ran it.
//
// Its own table rather than a `kind` column on MeComputeJobClaim: that table's
// unique index is (site, job_id), and widening a live unique index needs
// guarded raw SQL at boot — the kind of migration that has crash-looped every
// pod here before (see claude_user_assignment.go). A new table is a plain
// AutoMigrate, and it carries what a claim never needed: the format, the
// study/experiment labels a list is filtered by, and the last status seen.
//
// FIRST WRITER WINS on (site, kind, native_id), as for claims: the index, not a
// check-then-write, decides who owns a job.
type MeFleetJob struct {
	ID       uint   `gorm:"primaryKey" json:"-"`
	Site     string `gorm:"column:site;size:32;not null;uniqueIndex:uq_fleetjob,priority:1" json:"site"`
	Kind     string `gorm:"column:kind;size:8;not null;uniqueIndex:uq_fleetjob,priority:2" json:"kind"`
	NativeID string `gorm:"column:native_id;size:128;not null;uniqueIndex:uq_fleetjob,priority:3" json:"native_id"`
	UserSub  string `gorm:"column:user_sub;size:36;not null;index:ix_fleetjob_user,priority:1" json:"-"`

	Format     string `gorm:"column:format;size:16" json:"format"`
	Name       string `gorm:"column:name;size:128" json:"name,omitempty"`
	Study      string `gorm:"column:study;size:128;index" json:"study,omitempty"`
	Experiment string `gorm:"column:experiment;size:128" json:"experiment,omitempty"`

	// Last unified status observed (queued|running|succeeded|failed|canceled).
	// A cache for the list view, refreshed whenever the job is read; the
	// upstream service stays the source of truth.
	Status   string `gorm:"column:status;size:16" json:"status"`
	Terminal bool   `gorm:"column:terminal" json:"terminal"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;index:ix_fleetjob_user,priority:2" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (MeFleetJob) TableName() string { return "me_fleet_jobs" }
