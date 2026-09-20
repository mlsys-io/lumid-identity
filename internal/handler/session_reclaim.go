package handler

import (
	"errors"
	"log"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Session retention. A session row is dead once ExpiresAt passes — the token it
// records is unusable and nothing reads the row again. We keep a short grace
// window past expiry so /api/v1/user/sessions can still show a user their
// recently-ended sessions, and so revocation audits have something to look at.
const (
	sessionRetention      = 7 * 24 * time.Hour
	sessionReclaimEvery   = 6 * time.Hour
	sessionReclaimBatch   = 20000
	sessionReclaimMaxIter = 50 // bounds one pass at 1M rows
)

// StartSessionReclaimLoop deletes long-expired rows from `sessions`.
//
// Nothing pruned this table. Measured 2026-08-17 on mysql-trading: 238,758 rows
// of which 238,732 (99.99%) were expired — 26 live sessions carried in a 161 MB
// table, accumulating ~5.3k rows/day since the July lift. That instance is a
// 2 Gi PVC shared with trading_community and lumid_cluster, and it had reached
// 95% full (99 MB free). A full volume there does not degrade gracefully: this
// is the auth authority's database, so it takes login down estate-wide.
//
// Deleted in bounded batches rather than one statement because the table is on
// the live auth path — a single 238k-row DELETE holds row locks across the
// index for the whole transaction, and writes its entire footprint into the
// binlog as one event.
//
// Serialised across replicas by a MySQL named lock, matching
// StartAssignmentReclaimLoop: identity runs replicas:2, and two concurrent
// sweeps would just contend on the same rows.
func StartSessionReclaimLoop() {
	go func() {
		time.Sleep(reclaimFirstPassDelay)
		for {
			if n, err := reclaimExpiredSessions(); errors.Is(err, errLockBusy) {
				log.Print("session reclaim: skipped, another replica holds the lock")
			} else if err != nil {
				log.Printf("session reclaim failed: %v", err)
			} else if n > 0 {
				log.Printf("session reclaim: deleted %d row(s) expired more than %v ago", n, sessionRetention)
			}
			time.Sleep(sessionReclaimEvery)
		}
	}()
	log.Printf("session reclaim loop every %v (retention %v past expiry)", sessionReclaimEvery, sessionRetention)
}

func reclaimExpiredSessions() (total int64, err error) {
	err = withNamedLock(common.DB, "session_reclaim", 2*time.Second, func() error {
		var e error
		total, e = reclaimExpiredSessionsLocked()
		return e
	})
	return total, err
}

func reclaimExpiredSessionsLocked() (int64, error) {
	cutoff := time.Now().UTC().Add(-sessionRetention)
	var total int64
	for i := 0; i < sessionReclaimMaxIter; i++ {
		res := common.DB.
			Where("expires_at < ?", cutoff).
			Limit(sessionReclaimBatch).
			Delete(&models.Session{})
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected < sessionReclaimBatch {
			break
		}
	}
	return total, nil
}
