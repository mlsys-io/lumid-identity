package common

import (
	"testing"

	"gorm.io/gorm"
)

// releaseTestDBOnCleanup releases a test's idle MySQL connections when the test
// ends. Every DB-backed test opened a pool and never closed it, so the suite
// reached the server's 151-connection limit and a new test failed an unrelated
// one with Error 1040. The pool itself stays open: later tests reuse
// common.DB from an earlier setup, so closing it would break them.
func releaseTestDBOnCleanup(t testing.TB, db *gorm.DB) {
	t.Helper()
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.SetMaxIdleConns(0)
		}
	})
}
