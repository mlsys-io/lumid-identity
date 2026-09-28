package handler

// Which fleet compute jobs a cycle ran — surfaced on the cycle detail.
//
// The run store has recorded each run's compute job addresses since the
// compute-job status route needed an ownership record (models.MeAppRun
// .ComputeJobs). Nothing READ them back out per run: the Studio run page could
// show a run's steps but not the Lumilake jobs / FlowMesh workflows it fanned
// out to, so the only way to get from a run to its fleet work was to already
// know the job id.
//
// Read from the store on EVERY detail path — disk, scheduler and the
// `unavailable` degrade — because it is the one source that is the same on all
// of them: identity mounts no tenant volume, and the cycle dir never carried the
// job list anyway.

import (
	"encoding/json"
	"strconv"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// cycleIDToRunTs is the inverse of runTsToCycleID: the run-store key for a
// cycle id. A bare unix-seconds id is accepted too (some links carry it).
func cycleIDToRunTs(ts string) (int64, bool) {
	if t, err := time.Parse("20060102T150405Z", ts); err == nil {
		return t.Unix(), true
	}
	if n, err := strconv.ParseInt(ts, 10, 64); err == nil && n >= 31_536_000 {
		return n, true
	}
	return 0, false
}

// parseComputeJobs decodes a stored compute_jobs column. Always non-nil, so
// the response carries `[]` rather than `null` for a run with no fleet work —
// the UI then has one shape to test instead of two.
//
// Entries missing either address half are dropped here as well as at write
// time: rows written before the write-side check existed must not surface as a
// job the status route will then refuse to resolve.
func parseComputeJobs(raw *string) []computeJobRef {
	out := []computeJobRef{}
	if raw == nil || *raw == "" {
		return out
	}
	var refs []computeJobRef
	if json.Unmarshal([]byte(*raw), &refs) != nil {
		return out
	}
	for _, r := range refs {
		if r.JobID == "" || r.Site == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// cycleComputeJobs returns the caller's OWN recorded jobs for one cycle.
// Owner-scoped by user_sub: the same predicate the status route authorizes on,
// so every job listed here is one that route will answer for this caller.
func cycleComputeJobs(userID, app, loop, ts string) []computeJobRef {
	runTs, ok := cycleIDToRunTs(ts)
	if !ok || userID == "" || common.DB == nil {
		return []computeJobRef{}
	}
	var row models.MeAppRun
	if err := common.DB.Select("compute_jobs").
		Where("user_sub = ? AND app IN ? AND `loop` = ? AND run_ts = ?", // loop is reserved
			userID, appAliases(app), loop, runTs).
		Take(&row).Error; err != nil {
		return []computeJobRef{}
	}
	return parseComputeJobs(row.ComputeJobs)
}
