package handler

// Removing a pooled account must NOT destroy the evidence.
//
// AdminClaudeTokenDelete used to hard-DELETE the row and cascade
// claude_quota_snapshots with it. Removing an account is the first thing an
// operator does during a quarantine incident, so that erased exactly the
// forensic columns added on 2026-08-14 to make quarantines answerable —
// revoke_reason, rotated_at, indeterminate_at, pre_expiry_401_at,
// last_exchange_* — plus the snapshot history the sibling-comparison technique
// needs.
//
// It cost two post-mortems. On 2026-08-21 ac2@nati and ac3@nati were
// quarantined 2m01s apart and deleted 4h20m later; the incident was only
// reconstructable because identity's pod logs happened not to have rotated.
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run Tombstone

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func setupTombstoneDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping claude-token tombstone integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.ClaudeQuotaToken{}, &models.ClaudeQuotaSnapshot{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	return db
}

func tombstoneRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.DELETE("/api/v1/admin/claude-token/:email", AdminClaudeTokenDelete)
	return r
}

// seedDoomedAccount writes a row carrying every forensic column a real
// quarantine would have populated, plus two snapshots.
func seedDoomedAccount(t *testing.T, db *gorm.DB, email string) {
	t.Helper()
	db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{})
	db.Where("email = ?", email).Delete(&models.ClaudeQuotaSnapshot{})
	t.Cleanup(func() {
		db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{})
		db.Where("email = ?", email).Delete(&models.ClaudeQuotaSnapshot{})
	})

	now := time.Now().UTC().Truncate(time.Second)
	rotated := now.Add(-13 * time.Minute)
	revoked := now.Add(-2 * time.Minute)
	row := models.ClaudeQuotaToken{
		Email:                 email,
		ValueEncrypted:        "enc-access",
		RefreshTokenEncrypted: "enc-refresh",
		Label:                 "denmark",
		RotatedAt:             &rotated,
		RevokedAt:             &revoked,
		RevokeReason:          "invalid_grant — Refresh token not found or invalid",
		LastExchangeAt:        &revoked,
		LastExchangeOutcome:   "invalid_grant",
		LastExchangeMs:        353,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed row: %v", err)
	}
	for i := 0; i < 2; i++ {
		// Reset timestamps must be real: MySQL strict mode rejects the zero
		// time, and these columns are NOT NULL-able datetimes.
		if err := db.Create(&models.ClaudeQuotaSnapshot{
			Email: email, Ts: now.Add(-time.Duration(i+1) * time.Hour), SevenDayPct: 40,
			FiveHourReset: now.Add(time.Hour), SevenDayReset: now.Add(72 * time.Hour),
		}).Error; err != nil {
			t.Fatalf("seed snapshot: %v", err)
		}
	}
}

func TestTombstoneRetainsForensicsAndSnapshots(t *testing.T) {
	db := setupTombstoneDB(t)
	const email = "tombstone-forensics@test"
	seedDoomedAccount(t, db, email)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/claude-token/"+email, nil)
	w := httptest.NewRecorder()
	tombstoneRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete returned %d, want 200: %s", w.Code, w.Body.String())
	}

	// Gone from the pool: every lease/sweep/placement/health query uses a plain
	// (scoped) read, so the account must be invisible to one.
	var live models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&live).Error; err != gorm.ErrRecordNotFound {
		t.Errorf("deleted account still visible to a scoped query (err=%v) — it would keep being leased", err)
	}

	// ...but the evidence survives.
	var kept models.ClaudeQuotaToken
	if err := db.Unscoped().Where("email = ?", email).First(&kept).Error; err != nil {
		t.Fatalf("row was HARD deleted — the forensics are gone: %v", err)
	}
	if kept.RevokeReason == "" || kept.RotatedAt == nil || kept.LastExchangeOutcome != "invalid_grant" {
		t.Errorf("forensic columns lost on delete: reason=%q rotated=%v outcome=%q",
			kept.RevokeReason, kept.RotatedAt, kept.LastExchangeOutcome)
	}
	if !kept.DeletedAt.Valid {
		t.Errorf("row retained but deleted_at not set — it is not a tombstone, it is still live")
	}

	// Snapshots must NOT be cascaded: token lifetime is only interpretable
	// against the accounts minted alongside it.
	var snaps int64
	db.Model(&models.ClaudeQuotaSnapshot{}).Where("email = ?", email).Count(&snaps)
	if snaps != 2 {
		t.Errorf("snapshot history = %d rows, want 2 — the sibling-comparison evidence was cascaded away", snaps)
	}
}

func TestTombstoneIsResurrectedByReAdd(t *testing.T) {
	db := setupTombstoneDB(t)
	const email = "tombstone-readd@test"
	seedDoomedAccount(t, db, email)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/claude-token/"+email, nil)
	tombstoneRouter().ServeHTTP(httptest.NewRecorder(), req)

	// Exactly what AdminClaudeTokenAdd does after verifyAnthropic succeeds.
	// The upsert itself is replicated (the handler makes a live Anthropic call
	// we cannot make here) but the COLUMN SET is the production one, which is
	// where the failure mode lives: drop "deleted_at" and the new credential
	// lands on a row that stays invisible forever.
	fresh := models.ClaudeQuotaToken{Email: email, ValueEncrypted: "enc-access-2", RefreshTokenEncrypted: "enc-refresh-2"}
	if err := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}},
		DoUpdates: clause.AssignmentColumns(claudeTokenReAddColumns(false, false)),
	}).Create(&fresh).Error; err != nil {
		t.Fatalf("re-add upsert: %v", err)
	}

	var back models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&back).Error; err != nil {
		t.Fatalf("re-added account is STILL invisible — the tombstone was not resurrected: %v", err)
	}
	if back.ValueEncrypted != "enc-access-2" {
		t.Errorf("credential not replaced: %q", back.ValueEncrypted)
	}
	if back.RevokedAt != nil {
		t.Errorf("re-add did not clear the quarantine (revoked_at=%v)", back.RevokedAt)
	}
	// A re-add with no label must not wipe the existing field-box tag.
	if back.Label != "denmark" {
		t.Errorf("label wiped by an unrelated re-add: %q, want denmark", back.Label)
	}
}

func TestReAddColumnSetIncludesDeletedAt(t *testing.T) {
	// Cheap guard that runs without a DB: the resurrection above is invisible
	// in production if this column is ever dropped from the set.
	for _, want := range []string{"deleted_at", "revoked_at", "value_encrypted"} {
		found := false
		for _, c := range claudeTokenReAddColumns(false, false) {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("re-add column set is missing %q", want)
		}
	}
	if got := claudeTokenReAddColumns(true, false); got[len(got)-1] != "label" {
		t.Errorf("withLabel=true must append label, got %v", got)
	}
	if got := claudeTokenReAddColumns(true, true); got[len(got)-1] != "pool_id" {
		t.Errorf("withLabel=true,withPool=true must append pool_id last, got %v", got)
	}
}
