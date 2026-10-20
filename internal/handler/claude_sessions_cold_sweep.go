package handler

// Cold-tier sweep for Claude session recordings.
//
// Moves the turn blobs of sessions idle longer than a cutoff from the hot
// store (common.Blobs, UpCloud) to the cold tier (common.ColdBlobs, the NAS
// MinIO on tank), so the hot bucket stops growing without bound. Reads keep
// working because getTurnBlobs falls back to the cold tier on a hot 404.
//
// Run as a one-shot from the monthly CronJob (`identity -sweep-cold-sessions`),
// not from the server: it is long, bursty I/O with nothing a request waits on.
//
// Per object: GET hot -> PUT cold -> GET cold and compare bytes. Only when
// every object of a session verified are that session's hot keys deleted, and
// only those exact keys — never a prefix — so a session that resumes mid-sweep
// keeps its new turns in the hot store. Re-running is safe: a hot 404 whose
// cold copy exists counts as already moved. A session that finished cleanly is
// stamped cold_at and skipped by later runs unless it resumes (last_ts > cold_at).

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// ColdSweepOptions configures one sweep run.
type ColdSweepOptions struct {
	ColdAfter time.Duration // sessions whose last turn is older than this move
	Workers   int           // sessions processed concurrently
	Limit     int           // max sessions this run (0 = all)
	DryRun    bool          // count only; no copy, no delete
}

// ColdSweepStats summarises a run.
type ColdSweepStats struct {
	Sessions, Moved, AlreadyCold, Failed int64
	Objects, Bytes                       int64
}

var coldBlobSuffixes = []string{"request_meta.gz", "new_messages.gz", "response.gz"}

// SweepColdSessions moves idle sessions' blobs to the cold tier. It returns an
// error if the run could not start or if any session failed to move; failed
// sessions are left fully in the hot store and are retried by the next run.
func SweepColdSessions(opt ColdSweepOptions) (ColdSweepStats, error) {
	var st ColdSweepStats
	if common.Blobs == nil || common.ColdBlobs == nil {
		return st, errors.New("cold sweep needs both S3_SESSIONS_* and S3_SESSIONS_COLD_* configured")
	}
	if opt.ColdAfter < 7*24*time.Hour {
		return st, fmt.Errorf("cold-after %s is below the 7-day floor", opt.ColdAfter)
	}
	if opt.Workers < 1 {
		opt.Workers = 1
	}
	cutoff := time.Now().UTC().Add(-opt.ColdAfter)

	q := common.DB.Model(&models.ClaudeSession{}).
		Where("last_ts < ?", cutoff).
		Where("cold_at IS NULL OR cold_at < last_ts").
		Where("EXISTS (SELECT 1 FROM claude_session_turns t WHERE t.conv_key = claude_sessions.conv_key AND t.blob_key <> '')").
		Order("last_ts")
	if opt.Limit > 0 {
		q = q.Limit(opt.Limit)
	}
	var convs []string
	if err := q.Pluck("conv_key", &convs).Error; err != nil {
		return st, fmt.Errorf("list cold sessions: %w", err)
	}
	st.Sessions = int64(len(convs))
	log.Printf("cold sweep: %d sessions idle since before %s (dry_run=%v, workers=%d)",
		len(convs), cutoff.Format(time.RFC3339), opt.DryRun, opt.Workers)
	if opt.DryRun || len(convs) == 0 {
		return st, nil
	}

	work := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < opt.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for conv := range work {
				moved, objs, n, err := moveSessionToCold(conv)
				switch {
				case err != nil:
					atomic.AddInt64(&st.Failed, 1)
					log.Printf("cold sweep: session %s NOT moved: %v", conv, err)
				case moved:
					atomic.AddInt64(&st.Moved, 1)
				default:
					atomic.AddInt64(&st.AlreadyCold, 1)
				}
				atomic.AddInt64(&st.Objects, objs)
				atomic.AddInt64(&st.Bytes, n)
			}
		}()
	}
	for i, c := range convs {
		work <- c
		if (i+1)%5000 == 0 {
			log.Printf("cold sweep: %d/%d sessions dispatched", i+1, len(convs))
		}
	}
	close(work)
	wg.Wait()

	log.Printf("cold sweep: done sessions=%d moved=%d already_cold=%d failed=%d objects=%d bytes=%d",
		st.Sessions, st.Moved, st.AlreadyCold, st.Failed, st.Objects, st.Bytes)
	if st.Failed > 0 {
		return st, fmt.Errorf("%d of %d sessions failed to move", st.Failed, st.Sessions)
	}
	return st, nil
}

// moveSessionToCold copies and verifies every hot blob of one session, then
// deletes exactly those hot keys. moved=false with a nil error means nothing
// was left in the hot store (already moved by an earlier run).
func moveSessionToCold(conv string) (moved bool, objects, nbytes int64, err error) {
	var keys []string
	if err := common.DB.Model(&models.ClaudeSessionTurn{}).
		Where("conv_key = ? AND blob_key <> ''", conv).
		Order("turn_index").Pluck("blob_key", &keys).Error; err != nil {
		return false, 0, 0, fmt.Errorf("list turns: %w", err)
	}
	var toDelete []string
	for _, bk := range keys {
		for _, suffix := range coldBlobSuffixes {
			rel := bk + "/" + suffix
			data, err := common.Blobs.Get(rel)
			if errors.Is(err, common.ErrNotFound) {
				// Not in hot: fine only if the cold tier already holds it.
				if ok, cerr := common.ColdBlobs.Exists(rel); cerr != nil || !ok {
					return false, objects, nbytes, fmt.Errorf("%s missing from both tiers (cold err: %v)", rel, cerr)
				}
				continue
			}
			if err != nil {
				return false, objects, nbytes, fmt.Errorf("hot get %s: %w", rel, err)
			}
			if err := common.ColdBlobs.Put(rel, data); err != nil {
				return false, objects, nbytes, fmt.Errorf("cold put %s: %w", rel, err)
			}
			back, err := common.ColdBlobs.Get(rel)
			if err != nil {
				return false, objects, nbytes, fmt.Errorf("cold verify get %s: %w", rel, err)
			}
			if !bytes.Equal(back, data) {
				return false, objects, nbytes, fmt.Errorf("cold verify %s: content differs (%d vs %d bytes)", rel, len(back), len(data))
			}
			toDelete = append(toDelete, rel)
			objects++
			nbytes += int64(len(data))
		}
	}
	for _, rel := range toDelete {
		if err := common.Blobs.Delete(rel); err != nil {
			// Copies are verified, so a leftover hot object is only wasted
			// space; the next run sees both and deletes it again.
			return true, objects, nbytes, fmt.Errorf("hot delete %s: %w", rel, err)
		}
	}
	now := time.Now().UTC()
	if err := common.DB.Model(&models.ClaudeSession{}).Where("conv_key = ?", conv).
		Update("cold_at", now).Error; err != nil {
		// The move itself is complete; only the skip marker is missing, so the
		// next run re-checks this session cheaply (hot 404 + cold HEAD).
		return len(toDelete) > 0, objects, nbytes, fmt.Errorf("stamp cold_at: %w", err)
	}
	return len(toDelete) > 0, objects, nbytes, nil
}
