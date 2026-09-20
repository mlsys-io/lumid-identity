package models

import "time"

// MeComputeJobClaim — who submitted a fleet compute job that did NOT come from
// a scheduled cycle.
//
// The run store (MeAppRun.ComputeJobs) covers cycle-dispatched jobs, because a
// cycle self-reports. It cannot cover the chat path: run_lumilake_job is an MCP
// tool call in a sandbox, there is no cycle around it and nothing writes a run
// row — yet that is precisely the path the workflow canvas was built for. With
// only the run store, the job-status route would 404 every job a user started
// from chat.
//
// So the submitter claims the job immediately after submitting it, from the
// sandbox, as themselves.
//
// FIRST CLAIM WINS, enforced by the database rather than by a check-then-write
// in the handler, which two concurrent claims would race straight through. The
// unique index is on (site, job_id) — NOT including user_sub — because that is
// what makes a second user's claim on the same job fail rather than create a
// second owner.
//
// The model this rests on: a job id is unguessable (req- plus 22 random
// characters) and the real submitter claims within milliseconds of creating it.
// That is weaker than a credential check and stronger than the alternative it
// replaces, which was letting any authenticated user read any job on any site.
// It is recorded here rather than left implicit so the tradeoff is reviewable.
type MeComputeJobClaim struct {
	ID      uint   `gorm:"primaryKey"                                                      json:"-"`
	Site    string `gorm:"column:site;size:32;not null;uniqueIndex:uq_computejob,priority:1"  json:"site"`
	JobID   string `gorm:"column:job_id;size:128;not null;uniqueIndex:uq_computejob,priority:2" json:"job_id"`
	UserSub string `gorm:"column:user_sub;size:36;not null;index"                            json:"user_sub"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
}

func (MeComputeJobClaim) TableName() string { return "me_compute_job_claims" }
