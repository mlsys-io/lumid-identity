package handler

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// errLockBusy reports that another holder has the named lock. Callers that
// merely want "one replica does this" treat it as a skip; it is never a fault.
var errLockBusy = errors.New("named lock held elsewhere")

// withNamedLock runs fn while holding the MySQL named lock `name`, with
// acquire AND release pinned to one pooled connection.
//
// GET_LOCK is scoped to the connection that took it. Issuing GET_LOCK and
// RELEASE_LOCK as two separate calls on the *gorm.DB pool lets them land on
// different connections: the release then frees nothing, and the lock stays
// held by an idle pool connection for the rest of that pod's life. Every
// other replica's GET_LOCK fails from then on. On 2026-09-19 that silently
// turned the 6-hourly retention sweep into a once-per-pod-lifetime sweep
// (the second replica's 02:12Z pass never ran), and the same pattern was in
// the session and interaction reclaim loops and the boot-time pool migration
// — where a leaked lock turns into a 30s wait and log.Fatalf on the next
// replica to boot. admin_claude_quota.go's withEmailLock already did it right;
// this is that pattern, shared.
func withNamedLock(db *gorm.DB, name string, timeout time.Duration, fn func() error) error {
	return db.Connection(func(conn *gorm.DB) error {
		var got *int // GET_LOCK returns NULL on error (e.g. killed while waiting)
		if err := conn.Raw("SELECT GET_LOCK(?, ?)", name, int(timeout.Seconds())).Scan(&got).Error; err != nil {
			return fmt.Errorf("acquire %s: %w", name, err)
		}
		if got == nil || *got != 1 {
			return errLockBusy
		}
		defer conn.Exec("DO RELEASE_LOCK(?)", name)
		return fn()
	})
}
