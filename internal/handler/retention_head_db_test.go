package handler

// Integration test for hasColdHead. Runs only when TEST_MYSQL_DSN is set.

import (
	"fmt"
	"testing"
	"time"

	"lumid_identity/internal/common"
)

// Reproduces audit_log after its first pass on 2026-09-19: the lowest ids are
// dated rows INSIDE the window (kept), and the cold NULL-timestamp rows sit
// behind them. The head check must still see the cold rows.
func TestHasColdHeadSeesColdRowsBehindKeptOnes(t *testing.T) {
	db := setupLockDB(t)
	common.DB = db
	const table = "test_retention_head"
	db.Exec("DROP TABLE IF EXISTS " + table)
	if err := db.Exec("CREATE TABLE " + table + " (id BIGINT AUTO_INCREMENT PRIMARY KEY, created_at DATETIME(3) NULL)").Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	defer db.Exec("DROP TABLE " + table)

	now := time.Now().UTC()
	for i := 0; i < 50; i++ { // kept: recent, lowest ids
		db.Exec("INSERT INTO "+table+" (created_at) VALUES (?)", now.Add(-time.Duration(i)*time.Hour))
	}
	spec := archiveSpec{table: table, idColumn: "id", tsColumn: "created_at", retention: 400 * 24 * time.Hour, nullTsIsCold: true}
	cutoff := now.Add(-spec.retention)

	cold, err := hasColdHead(spec, cutoff)
	if err != nil || cold {
		t.Fatalf("only kept rows: cold=%v err=%v, want false", cold, err)
	}

	db.Exec("INSERT INTO " + table + " (created_at) VALUES (NULL), (NULL), (NULL)") // cold, behind the kept rows
	cold, err = hasColdHead(spec, cutoff)
	if err != nil || !cold {
		t.Fatalf("cold rows behind %d kept rows: cold=%v err=%v, want true", 50, cold, err)
	}

	// Without nullTsIsCold the same NULL rows are NOT cold.
	spec.nullTsIsCold = false
	if cold, err = hasColdHead(spec, cutoff); err != nil || cold {
		t.Fatalf("%s", fmt.Sprintf("nullTsIsCold=false: cold=%v err=%v, want false", cold, err))
	}
}
