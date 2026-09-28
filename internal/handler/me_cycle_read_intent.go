package handler

// Per-step cycle detail for the caller's OWN install, read on the scheduler.
//
// The cycle dir — step outputs, prompt audit, sidecars, the LLM transcript —
// lives only on the scheduler's volume, which identity does not mount. The run
// store (me_app_runs) rebuilds the run LIST, but the drill-down behind a run
// has no copy anywhere identity can read, so every owner's inspector said
// "per-step detail is not available on this deployment" (GOALS T7).
//
// The scheduler can read it, and it already answers synchronous reads for
// next-actions and the improvements ledger (me_read_intent.go). `cycle_read`
// is one more such read: the picker returns the cycle dir's inspector files
// for an install under `_tenant_home(user_sub)` — the caller's own tenant and
// nothing else — and cycleDetailFromFiles parses them exactly as it parses a
// dir on disk.
//
// Owner-only by construction: it is attempted only when ownerWriteTarget says
// the app is the caller's install on the scheduler (viaIntent), and the picker
// resolves the install under the intent row's user_sub, which is the caller.
// An operator-shared app is never read this way.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const cycleReadAction = "cycle_read"

// A FINISHED cycle's files do not change, and the pages that draw run history
// (GoalTrend, LearningVelocity, CompareRuns) fetch one detail per run. The
// generic read-intent cache holds 15 s; a finished cycle is kept longer so a
// page reload does not queue twenty intents again. In-flight cycles are not
// kept here (their files are still being written).
const (
	cycleReadCacheTTL = 10 * time.Minute
	cycleReadCacheMax = 512
)

type cycleReadEntry struct {
	files      cycleFiles
	resolvedTs string
	exp        time.Time
}

var (
	cycleReadMu    sync.Mutex
	cycleReadCache = map[string]cycleReadEntry{}
)

// resetCycleReadCache clears the finished-cycle cache (tests).
func resetCycleReadCache() {
	cycleReadMu.Lock()
	cycleReadCache = map[string]cycleReadEntry{}
	cycleReadMu.Unlock()
}

// errCycleNotOnScheduler: the scheduler answered, and there is no such cycle
// dir in the caller's install. A genuine "not found", not an outage.
var errCycleNotOnScheduler = errors.New("cycle not found")

// cycleReadResult is what the picker's cycle_read returned, decoded.
type cycleReadResult struct {
	files   cycleFiles
	running bool
	skipped []string
	// resolvedTs is the cycle DIR the scheduler read. The run list's ids come
	// from the run store, stamped when a cycle REPORTS (its end), while the dir
	// is named for its start — 20260928T094237Z names dir 20260928T094205Z.
	resolvedTs string
}

// cycleFilesViaScheduler reads app/loop/ts's cycle dir from the caller's
// install on the scheduler. `transcript` also asks for .llm_conversation.jsonl.
func cycleFilesViaScheduler(ctx context.Context, userID, app, loop, ts string, transcript bool) (cycleReadResult, error) {
	key := userID + "\x00" + app + "\x00" + loop + "\x00" + ts
	if transcript {
		key += "\x00t"
	}
	cycleReadMu.Lock()
	if e, hit := cycleReadCache[key]; hit {
		if time.Now().Before(e.exp) {
			cycleReadMu.Unlock()
			return cycleReadResult{files: e.files, resolvedTs: e.resolvedTs}, nil
		}
		delete(cycleReadCache, key)
	}
	cycleReadMu.Unlock()

	payload := map[string]any{"app": app, "loop": loop, "ts": ts}
	if transcript {
		payload["transcript"] = true
	}
	if hint, ok := cycleStartHint(userID, app, loop, ts); ok {
		payload["start_hint"] = hint
	}
	data, err := runReadIntent(ctx, userID, cycleReadAction, payload, readIntentDefaultTimeout)
	if err != nil {
		return cycleReadResult{}, err
	}
	if exists, _ := data["exists"].(bool); !exists {
		return cycleReadResult{}, errCycleNotOnScheduler
	}
	res := cycleReadResult{files: cycleFiles{}}
	res.running, _ = data["running"].(bool)
	res.resolvedTs, _ = data["resolved_ts"].(string)
	if fm, ok := data["files"].(map[string]any); ok {
		for name, v := range fm {
			if s, ok := v.(string); ok && safeSeg(name) {
				res.files[name] = []byte(s)
			}
		}
	}
	if sk, ok := data["skipped"].([]any); ok {
		for _, v := range sk {
			if s, ok := v.(string); ok {
				res.skipped = append(res.skipped, s)
			}
		}
	}
	if !res.running {
		cycleReadMu.Lock()
		if len(cycleReadCache) >= cycleReadCacheMax {
			now := time.Now()
			for k, e := range cycleReadCache {
				if now.After(e.exp) || len(cycleReadCache) >= cycleReadCacheMax {
					delete(cycleReadCache, k)
				}
			}
		}
		cycleReadCache[key] = cycleReadEntry{files: res.files, resolvedTs: res.resolvedTs,
			exp: time.Now().Add(cycleReadCacheTTL)}
		cycleReadMu.Unlock()
	}
	return res, nil
}

// cycleDetailResolved is the inspector's answer for one cycle, from whichever
// source can see it:
//
//  1. the cycle dir on this pod's disk (an operator install on a pod that
//     mounts it);
//  2. the caller's own install on the scheduler, via cycle_read;
//  3. neither: `unavailable` says why, instead of an empty drill-down that
//     reads as "this step did nothing".
//
// found=false with unavailable=="" is a genuine "no such cycle".
func cycleDetailResolved(ctx context.Context, userID, app, loop, ts string) (data gin.H, found bool, unavailable string) {
	if d, ok := cycleDetailForUser(userID, app, loop, ts); ok {
		return d, true, ""
	}
	if _, direct, viaIntent, _ := ownerWriteTarget(userID, app); !direct && viaIntent && safeSeg(loop) && safeSeg(ts) {
		res, err := cycleFilesViaScheduler(ctx, userID, app, loop, ts, false)
		switch {
		case err == nil:
			d := cycleDetailFromFiles(app, loop, ts, res.files)
			d["source"] = "scheduler"
			dirTs := ts
			if res.resolvedTs != "" && res.resolvedTs != ts {
				d["cycle_dir_ts"] = res.resolvedTs
				dirTs = res.resolvedTs
			}
			if res.running {
				d["running"] = true
			}
			if len(res.skipped) > 0 {
				d["skipped_files"] = res.skipped
			}
			d["memories_learned"] = memoriesLearnedInCycle(userID, app, loop, dirTs)
			return d, true, ""
		case errors.Is(err, errCycleNotOnScheduler):
			return nil, false, ""
		default:
			return nil, false, "per-step cycle detail could not be read from the scheduler: " + err.Error()
		}
	}
	return nil, false, unavailableReason(resolveAppDir(userID, app), "per-step cycle detail")
}

// cycleStartHint is when the run named by a run-store id STARTED, as unix
// seconds: run_ts - duration_s from the caller's own store row. The picker
// uses it to choose between overlapping runs; without it, it takes the newest
// run that started at or before the id.
func cycleStartHint(userID, app, loop, ts string) (float64, bool) {
	if common.DB == nil {
		return 0, false
	}
	t, err := time.Parse("20060102T150405Z", ts)
	if err != nil {
		return 0, false
	}
	var row models.MeAppRun
	if common.DB.Select("run_ts", "duration_s").
		Where("user_sub = ? AND app IN ? AND `loop` = ? AND run_ts = ?", userID, appAliases(app), loop, t.Unix()).
		Take(&row).Error != nil || row.DurationS == nil || *row.DurationS <= 0 {
		return 0, false
	}
	return float64(row.RunTs) - *row.DurationS, true
}
