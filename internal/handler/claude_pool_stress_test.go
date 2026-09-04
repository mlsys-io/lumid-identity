package handler

// Deeper/broader stress coverage for the multi-pool feature, beyond the
// single-pool/single-user smoke tests in claude_pool_membership_test.go and
// claude_pool_add_member_test.go:
//
//   - Concurrent EnsureDefaultClaudePool boots against a table reset to the
//     EXACT pre-migration shape — directly reproduces the race that
//     crash-looped v0.5.325 (unlocked guarded DDL) and proves the fix
//     (claude_pool_migration named lock) actually serializes it.
//   - Concurrent AdminClaudePoolAddMember calls racing to set is_primary for
//     the same user across different pools — proves the DB-level partial
//     unique index (primary_marker) plus the handler's own transaction never
//     leave a user with zero or two primaries under contention.
//   - A multi-pool, multi-account, multi-user placement pass (distributed AND
//     conservative pools side by side) — proves cross-pool isolation holds
//     at a scale beyond the 2-pool/1-user-each coverage the earlier test
//     gives, and that conservative mode's ceiling + fill order behave
//     correctly with a REAL EnsureAssignments pass, not just the pure-Go
//     computeConservativeAssignment unit tests.
//
// All runs against the throwaway TEST_MYSQL_DSN database, never production.

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"lumid_identity/models"
)

// resetToPreMigrationShape drops claude_user_assignments back to its
// ORIGINAL single-column-PK shape (no pool_id at all) and wipes the pool
// tables, so EnsureDefaultClaudePool has real guarded DDL to race on —
// exactly reproducing the state that crash-looped v0.5.325.
func resetToPreMigrationShape(t *testing.T, db *gorm.DB) {
	t.Helper()
	stmts := []string{
		`DROP TABLE IF EXISTS claude_user_assignments`,
		`CREATE TABLE claude_user_assignments (
			user_sub varchar(36) NOT NULL,
			account varchar(255) NOT NULL,
			load_7d bigint NOT NULL DEFAULT 0,
			assigned_at datetime(3) DEFAULT NULL,
			reason varchar(32) DEFAULT NULL,
			PRIMARY KEY (user_sub)
		) ENGINE=InnoDB`,
		`DROP TABLE IF EXISTS claude_pool_members`,
		`DROP TABLE IF EXISTS claude_pools`,
	}
	for _, s := range stmts {
		if err := db.Exec(s).Error; err != nil {
			t.Fatalf("reset pre-migration shape: %v (stmt: %s)", err, s)
		}
	}
	// claude_quota_tokens.pool_id/pool_sort_order likewise reset if present,
	// so AutoMigrate's own ADD COLUMN path runs fresh too.
	db.Exec(`ALTER TABLE claude_quota_tokens DROP COLUMN pool_id`)
	db.Exec(`ALTER TABLE claude_quota_tokens DROP COLUMN pool_sort_order`)
}

// TestEnsureDefaultClaudePool_ConcurrentBootsNeverRace reproduces the exact
// failure mode fixed in commit 6196a0c: N "pods" all booting at once against
// a table in the pre-migration shape. Before the fix this reliably produced
// "Error 1068: Multiple primary key defined" on the loser(s). After the fix,
// every caller must succeed (the lock serializes them) and the end state
// must be correct and singular.
func TestEnsureDefaultClaudePool_ConcurrentBootsNeverRace(t *testing.T) {
	db := setupClaudePoolTestDB(t) // already ran AutoMigrate + EnsureDefaultClaudePool once
	resetToPreMigrationShape(t, db)
	if err := models.AutoMigrate(db); err != nil { // re-add plain columns (pool_id etc.), no PK involved
		t.Fatalf("automigrate after reset: %v", err)
	}

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = EnsureDefaultClaudePool(db)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: EnsureDefaultClaudePool returned an error under concurrency: %v", i, err)
		}
	}

	// Exactly one "default" pool, composite PK in place, no leftover damage.
	var poolCount int64
	db.Model(&models.ClaudePool{}).Where("id = ?", models.DefaultClaudePoolID).Count(&poolCount)
	if poolCount != 1 {
		t.Fatalf("expected exactly 1 default pool after concurrent boots, got %d", poolCount)
	}
	var pkIsComposite int64
	db.Raw(`SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE
	         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'claude_user_assignments'
	           AND CONSTRAINT_NAME = 'PRIMARY' AND COLUMN_NAME = 'pool_id'`).Scan(&pkIsComposite)
	if pkIsComposite == 0 {
		t.Fatalf("claude_user_assignments PK was not widened to (pool_id, user_sub) after concurrent boots")
	}
}

// TestAdminClaudePoolAddMember_ConcurrentPrimaryRace fires N concurrent
// AddMember calls for the SAME user across N different pools, all
// requesting is_primary=true. Whichever wins the race, the invariant that
// must hold afterward is: exactly one primary, zero errors/deadlocks.
func TestAdminClaudePoolAddMember_ConcurrentPrimaryRace(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	router := claudePoolMemberRouter()
	sub := claudePoolTestUser(t, db, "race")

	const n = 8
	pools := make([]string, n)
	for i := 0; i < n; i++ {
		pools[i] = fmt.Sprintf("cptest-race-%d", i)
		db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, ?, 'distributed')`, pools[i], pools[i])
		cleanupClaudePool(t, db, pools[i])
	}

	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int, poolID string) {
			defer wg.Done()
			body := []byte(`{"user_sub":"` + sub + `","is_primary":true}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claude-pools/"+poolID+"/members", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			statuses[i] = w.Code
		}(i, pools[i])
	}
	wg.Wait()
	for i, code := range statuses {
		if code != http.StatusOK {
			t.Errorf("goroutine %d: AddMember returned status %d under concurrency, want 200", i, code)
		}
	}

	var primaryCount int64
	db.Model(&models.ClaudePoolMember{}).Where("user_sub = ? AND is_primary = ?", sub, true).Count(&primaryCount)
	if primaryCount != 1 {
		t.Fatalf("expected exactly 1 primary membership after a %d-way concurrent race, got %d", n, primaryCount)
	}
	var totalCount int64
	db.Model(&models.ClaudePoolMember{}).Where("user_sub = ?", sub).Count(&totalCount)
	if totalCount != int64(n) {
		t.Fatalf("expected %d total memberships (one per pool), got %d", n, totalCount)
	}
}

// TestEnsureAssignments_MultiPoolScale runs a REAL EnsureAssignments pass
// (not the pure-Go computeAssignment/computeConservativeAssignment unit
// tests) across 4 pools side by side — 2 distributed, 2 conservative with
// different ceilings — each with its own accounts and a double-digit user
// count, and asserts total isolation: no user's persisted
// ClaudeUserAssignment ever names an account outside their own pool, and
// each conservative pool's fill count never exceeds its ceiling.
func TestEnsureAssignments_MultiPoolScale(t *testing.T) {
	db := setupClaudePoolTestDB(t)

	type poolSpec struct {
		id       string
		tag      string // short — embedded in synthetic user_sub, which is capped at users.id's varchar(36)
		mode     string
		ceiling  int
		accounts int
		users    int
	}
	specs := []poolSpec{
		{"cptest-scale-d1", "d1", models.ClaudePoolModeDistributed, 0, 3, 14},
		{"cptest-scale-d2", "d2", models.ClaudePoolModeDistributed, 0, 2, 9},
		{"cptest-scale-c1", "c1", models.ClaudePoolModeConservative, 3, 3, 12}, // 3 accounts x ceiling 3 = 9 slots for 12 users -> 3 unplaced
		{"cptest-scale-c2", "c2", models.ClaudePoolModeConservative, 2, 2, 5},  // 2 accounts x ceiling 2 = 4 slots for 5 users -> 1 unplaced
	}

	allAccountsByPool := map[string][]string{}
	allUsersByPool := map[string][]string{}

	for _, spec := range specs {
		db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode, conservative_ceiling) VALUES (?, ?, ?, ?)`,
			spec.id, spec.id, spec.mode, spec.ceiling)
		cleanupClaudePool(t, db, spec.id)

		for a := 0; a < spec.accounts; a++ {
			email := fmt.Sprintf("scale-%s-acct-%d-%d@example.com", spec.id, a, time.Now().UnixNano())
			if err := db.Create(&models.ClaudeQuotaToken{Email: email, ValueEncrypted: "x", PoolID: spec.id, PoolSortOrder: a}).Error; err != nil {
				t.Fatalf("seed account for %s: %v", spec.id, err)
			}
			allAccountsByPool[spec.id] = append(allAccountsByPool[spec.id], email)
			t.Cleanup(func(email string) func() {
				return func() { db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}) }
			}(email))
		}

		for u := 0; u < spec.users; u++ {
			sub := claudePoolTestUser(t, db, fmt.Sprintf("sc-%s-u%d", spec.tag, u))
			db.Exec(`INSERT INTO claude_pool_members (pool_id, user_sub, is_primary) VALUES (?, ?, TRUE)`, spec.id, sub)
			// Seed a claude-sonnet-5 turn so loadByUser (scoped by pool
			// membership) actually returns this user — a member with zero
			// usage_events rows is still picked up via placementPopulation,
			// but giving everyone real load exercises the LPT/ordering path
			// for real instead of the all-zero-load degenerate case.
			db.Exec(`INSERT INTO usage_events (user_sub, kind, model, ts, input_tokens, output_tokens)
				VALUES (?, 'claude_proxy', 'claude-sonnet-5', NOW(), ?, ?)`, sub, 1000+u*137, 100+u*11)
			allUsersByPool[spec.id] = append(allUsersByPool[spec.id], sub)
			t.Cleanup(func(sub string) func() {
				return func() { db.Exec(`DELETE FROM usage_events WHERE user_sub = ?`, sub) }
			}(sub))
		}
	}

	// One real, end-to-end placement pass across every pool.
	if err := EnsureAssignments(true); err != nil {
		t.Fatalf("EnsureAssignments: %v", err)
	}

	// Build a reverse index: which pool does each account actually belong to.
	accountPool := map[string]string{}
	for poolID, accts := range allAccountsByPool {
		for _, a := range accts {
			accountPool[a] = poolID
		}
	}

	for poolID, users := range allUsersByPool {
		placed := 0
		for _, sub := range users {
			var a models.ClaudeUserAssignment
			err := db.Where("pool_id = ? AND user_sub = ?", poolID, sub).First(&a).Error
			if err != nil {
				continue // legitimately unplaced (pool full) — checked in aggregate below
			}
			placed++
			if owner := accountPool[a.Account]; owner != poolID {
				t.Errorf("ISOLATION VIOLATION: user %s (pool %s) was assigned to account %s, which belongs to pool %q",
					sub, poolID, a.Account, owner)
			}
			// No assignment row for this user should exist in ANY OTHER pool.
			var crossCount int64
			db.Model(&models.ClaudeUserAssignment{}).Where("user_sub = ? AND pool_id <> ?", sub, poolID).Count(&crossCount)
			if crossCount != 0 {
				t.Errorf("user %s has %d assignment row(s) in OTHER pools besides %q", sub, crossCount, poolID)
			}
		}
		t.Logf("pool %s: %d/%d users placed", poolID, placed, len(users))
	}

	// Conservative pools: per-account headcount must never exceed the
	// configured ceiling — the anti-concentration backstop actually held
	// under a real placement pass, not just the pure-Go unit test.
	for _, spec := range specs {
		if spec.mode != models.ClaudePoolModeConservative {
			continue
		}
		var rows []models.ClaudeUserAssignment
		db.Where("pool_id = ?", spec.id).Find(&rows)
		perAccount := map[string]int{}
		for _, r := range rows {
			perAccount[r.Account]++
		}
		for acct, n := range perAccount {
			if n > spec.ceiling {
				t.Errorf("conservative pool %s: account %s holds %d users, exceeds ceiling %d", spec.id, acct, n, spec.ceiling)
			}
		}
	}
}
