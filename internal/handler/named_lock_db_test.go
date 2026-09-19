package handler

// Integration test for withNamedLock. Runs only when TEST_MYSQL_DSN is set (a
// throwaway MySQL — CI provides one); GET_LOCK has no SQLite equivalent.

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func setupLockDB(t *testing.T) *gorm.DB {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping named-lock integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(8)
	sqlDB.SetMaxOpenConns(8)
	return db
}

// warmPool opens several idle connections, so a GET_LOCK and a later
// RELEASE_LOCK issued through the pool are likely to land on different ones —
// the condition under which the unpinned pattern leaked the lock.
func warmPool(t *testing.T, db *gorm.DB) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db.Exec("DO SLEEP(0.05)")
		}()
	}
	wg.Wait()
}

func lockIsFree(t *testing.T, db *gorm.DB, name string) bool {
	var free int
	if err := db.Raw("SELECT IS_FREE_LOCK(?)", name).Scan(&free).Error; err != nil {
		t.Fatalf("IS_FREE_LOCK: %v", err)
	}
	return free == 1
}

// The regression: after withNamedLock returns, the lock must be free, however
// busy the pool was while fn ran. The unpinned GET_LOCK/RELEASE_LOCK pair left
// it held by an idle pool connection for the pod's lifetime.
func TestWithNamedLockAlwaysReleases(t *testing.T) {
	db := setupLockDB(t)
	const name = "test_named_lock_release"
	for i := 0; i < 25; i++ {
		warmPool(t, db)
		ran := false
		err := withNamedLock(db, name, 2*time.Second, func() error {
			ran = true
			warmPool(t, db) // pooled work inside fn, as the sweeps do
			return nil
		})
		if err != nil || !ran {
			t.Fatalf("iteration %d: err=%v ran=%v", i, err, ran)
		}
		if !lockIsFree(t, db, name) {
			t.Fatalf("iteration %d: lock still held after withNamedLock returned — "+
				"the release ran on a different connection than the acquire", i)
		}
	}
}

// A lock held elsewhere yields errLockBusy — distinguishable, so callers log a
// skip instead of silently returning as the old loops did — and fn never runs.
func TestWithNamedLockBusy(t *testing.T) {
	db := setupLockDB(t)
	const name = "test_named_lock_busy"
	sqlDB, _ := db.DB()
	holder, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(context.Background(), "DO GET_LOCK(?, 0)", name); err != nil {
		t.Fatalf("holder GET_LOCK: %v", err)
	}
	defer holder.ExecContext(context.Background(), "DO RELEASE_LOCK(?)", name)

	ran := false
	err = withNamedLock(db, name, 0, func() error { ran = true; return nil })
	if !errors.Is(err, errLockBusy) {
		t.Fatalf("err = %v, want errLockBusy", err)
	}
	if ran {
		t.Fatal("fn ran without holding the lock")
	}
}

// fn's error must come back unchanged, and the lock must still be released.
func TestWithNamedLockPropagatesFnError(t *testing.T) {
	db := setupLockDB(t)
	const name = "test_named_lock_err"
	boom := errors.New("boom")
	if err := withNamedLock(db, name, 2*time.Second, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if !lockIsFree(t, db, name) {
		t.Fatal("lock held after fn returned an error")
	}
}
