package handler

// Integration tests for multi-pool membership resolution, cross-pool
// placement isolation, and the migration backfill — against a throwaway
// MySQL, matching this package's existing convention (see
// admin_claude_user_usage_test.go). Runs only when TEST_MYSQL_DSN is set:
//
//   TEST_MYSQL_DSN='root:testpass@tcp(127.0.0.1:3306)/lumid_identity?parseTime=true' \
//     go test ./internal/handler -run ClaudePool

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// setupClaudePoolTestDB runs the FULL migration path production uses
// (models.AutoMigrate + EnsureDefaultClaudePool), not a hand-picked table
// subset — the migration/backfill behavior IS what these tests exercise.
func setupClaudePoolTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping claude-pool integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := EnsureDefaultClaudePool(db); err != nil {
		t.Fatalf("EnsureDefaultClaudePool: %v", err)
	}
	common.DB = db
	return db
}

// claudePoolTestUserSub returns a synthetic, test-run-unique user sub and
// registers a minimal `users` row for it (role lookups and the owner
// backfill both read that table) — cleaned up by the caller's t.Cleanup.
// users.id is varchar(36) (UUID-sized), so this must stay short.
func claudePoolTestUser(t *testing.T, db *gorm.DB, tag string) string {
	t.Helper()
	sub := fmt.Sprintf("cp-%s-%d", tag, time.Now().UnixNano()%1_000_000_000)
	if err := db.Exec(`INSERT INTO users (id, email, role, status) VALUES (?, ?, 'user', 'active')`,
		sub, sub+"@example.com").Error; err != nil {
		t.Fatalf("seed user %s: %v", sub, err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM claude_pool_members WHERE user_sub = ?`, sub)
		db.Exec(`DELETE FROM claude_user_assignments WHERE user_sub = ?`, sub)
		db.Exec(`DELETE FROM users WHERE id = ?`, sub)
	})
	return sub
}

func cleanupClaudePool(t *testing.T, db *gorm.DB, poolID string) {
	t.Helper()
	t.Cleanup(func() {
		db.Exec(`DELETE FROM claude_pool_members WHERE pool_id = ?`, poolID)
		db.Exec(`DELETE FROM claude_user_assignments WHERE pool_id = ?`, poolID)
		db.Exec(`DELETE FROM claude_quota_tokens WHERE pool_id = ?`, poolID)
		db.Exec(`DELETE FROM claude_pools WHERE id = ?`, poolID)
	})
}

// The migration backfill (EnsureDefaultClaudePool) seeds "default" once and
// is a complete no-op on every subsequent call — no duplicate rows, no
// errors, and the default pool's owner resolves to admin@lum.id when that
// row exists.
func TestClaudePoolMigration_BackfillIsIdempotent(t *testing.T) {
	db := setupClaudePoolTestDB(t)

	var before, after models.ClaudePool
	if err := db.Where("id = ?", models.DefaultClaudePoolID).First(&before).Error; err != nil {
		t.Fatalf("default pool missing after first EnsureDefaultClaudePool: %v", err)
	}
	var countBefore int64
	db.Model(&models.ClaudePoolMember{}).Where("pool_id = ?", models.DefaultClaudePoolID).Count(&countBefore)

	if err := EnsureDefaultClaudePool(db); err != nil {
		t.Fatalf("second EnsureDefaultClaudePool call: %v", err)
	}
	if err := db.Where("id = ?", models.DefaultClaudePoolID).First(&after).Error; err != nil {
		t.Fatalf("default pool missing after second call: %v", err)
	}
	var countAfter int64
	db.Model(&models.ClaudePoolMember{}).Where("pool_id = ?", models.DefaultClaudePoolID).Count(&countAfter)

	if before.CreatedAt.Unix() != after.CreatedAt.Unix() {
		t.Errorf("default pool was re-created (created_at changed): %v -> %v", before.CreatedAt, after.CreatedAt)
	}
	if countBefore != countAfter {
		t.Errorf("member count changed on idempotent re-run: %d -> %d", countBefore, countAfter)
	}

	// A user created AFTER the backfill has zero memberships until they are
	// resolved once — resolveUserPool's lazy-enrollment path, not the
	// migration's bulk INSERT. Confirms the two mechanisms don't double-book.
	sub := claudePoolTestUser(t, db, "postmigration")
	var cnt int64
	db.Model(&models.ClaudePoolMember{}).Where("user_sub = ?", sub).Count(&cnt)
	if cnt != 0 {
		t.Errorf("a user created after migration should have 0 memberships until resolved, got %d", cnt)
	}
	poolID, mode := resolveUserPool(sub, "")
	if poolID != models.DefaultClaudePoolID || mode != models.ClaudePoolModeDistributed {
		t.Errorf("resolveUserPool(new user) = (%q,%q), want (default, distributed)", poolID, mode)
	}
	db.Model(&models.ClaudePoolMember{}).Where("user_sub = ?", sub).Count(&cnt)
	if cnt != 1 {
		t.Errorf("lazy enrollment should have created exactly 1 membership, got %d", cnt)
	}
}

// resolveUserPool's three branches: valid hint wins, foreign hint falls back
// to primary (logged, not an error), and a user with no membership at all is
// lazily enrolled into "default" as primary.
func TestResolveUserPool_ThreeBranches(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	poolA, poolB := "cptest-pool-a", "cptest-pool-b"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'A', 'distributed')`, poolA)
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'B', 'distributed')`, poolB)
	cleanupClaudePool(t, db, poolA)
	cleanupClaudePool(t, db, poolB)

	sub := claudePoolTestUser(t, db, "multi")
	db.Exec(`INSERT INTO claude_pool_members (pool_id, user_sub, is_primary) VALUES (?, ?, TRUE)`, poolA, sub)
	db.Exec(`INSERT INTO claude_pool_members (pool_id, user_sub, is_primary) VALUES (?, ?, FALSE)`, poolB, sub)

	if got, _ := resolveUserPool(sub, ""); got != poolA {
		t.Errorf("no hint: resolveUserPool = %q, want primary %q", got, poolA)
	}
	if got, _ := resolveUserPool(sub, poolB); got != poolB {
		t.Errorf("valid hint for a real (non-primary) membership: resolveUserPool = %q, want %q", got, poolB)
	}
	if got, _ := resolveUserPool(sub, "cptest-pool-not-a-member"); got != poolA {
		t.Errorf("hint for a pool the user is NOT a member of: resolveUserPool = %q, want fallback to primary %q", got, poolA)
	}
}

// Two pools' placement passes never touch each other's accounts: a user in
// pool A must never land on an account that belongs to pool B, even when
// pool B's accounts would otherwise look attractive (e.g. lightly loaded).
func TestEnsureAssignments_CrossPoolIsolation(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	poolA, poolB := "cptest-iso-a", "cptest-iso-b"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'A', 'distributed')`, poolA)
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'B', 'distributed')`, poolB)
	cleanupClaudePool(t, db, poolA)
	cleanupClaudePool(t, db, poolB)

	acctA := fmt.Sprintf("acct-a-%d@example.com", time.Now().UnixNano())
	acctB := fmt.Sprintf("acct-b-%d@example.com", time.Now().UnixNano())
	if err := db.Create(&models.ClaudeQuotaToken{Email: acctA, ValueEncrypted: "x", PoolID: poolA}).Error; err != nil {
		t.Fatalf("seed acctA: %v", err)
	}
	if err := db.Create(&models.ClaudeQuotaToken{Email: acctB, ValueEncrypted: "x", PoolID: poolB}).Error; err != nil {
		t.Fatalf("seed acctB: %v", err)
	}
	t.Cleanup(func() {
		db.Unscoped().Where("email IN ?", []string{acctA, acctB}).Delete(&models.ClaudeQuotaToken{})
	})

	subA := claudePoolTestUser(t, db, "isoA")
	db.Exec(`INSERT INTO claude_pool_members (pool_id, user_sub, is_primary) VALUES (?, ?, TRUE)`, poolA, subA)
	db.Exec(`INSERT INTO usage_events (user_sub, kind, model, ts, input_tokens, output_tokens) VALUES (?, 'claude_proxy', 'claude-sonnet-5', NOW(), 1000, 100)`, subA)
	t.Cleanup(func() { db.Exec(`DELETE FROM usage_events WHERE user_sub = ?`, subA) })

	poolARow := models.ClaudePool{}
	db.Where("id = ?", poolA).First(&poolARow)
	if err := ensurePoolAssignments(poolARow, true); err != nil {
		t.Fatalf("ensurePoolAssignments(A): %v", err)
	}

	var assignment models.ClaudeUserAssignment
	if err := db.Where("pool_id = ? AND user_sub = ?", poolA, subA).First(&assignment).Error; err != nil {
		t.Fatalf("subA should be placed in pool A: %v", err)
	}
	if assignment.Account != acctA {
		t.Errorf("subA placed on %q, want %q (pool B's account must never be reachable from pool A's placement pass)", assignment.Account, acctA)
	}
	var crossPoolRow int64
	db.Model(&models.ClaudeUserAssignment{}).Where("pool_id = ? AND user_sub = ?", poolB, subA).Count(&crossPoolRow)
	if crossPoolRow != 0 {
		t.Errorf("subA must have no assignment row in pool B, found %d", crossPoolRow)
	}

	// Assignable-accounts scoping directly: pool B's account list must never
	// include pool A's account, and vice versa.
	accountsA, err := assignableAccounts(poolA)
	if err != nil {
		t.Fatalf("assignableAccounts(A): %v", err)
	}
	for _, a := range accountsA {
		if a == acctB {
			t.Errorf("assignableAccounts(%q) leaked pool B's account %q", poolA, acctB)
		}
	}
	accountsB, err := assignableAccounts(poolB)
	if err != nil {
		t.Fatalf("assignableAccounts(B): %v", err)
	}
	for _, a := range accountsB {
		if a == acctA {
			t.Errorf("assignableAccounts(%q) leaked pool A's account %q", poolB, acctA)
		}
	}
}
