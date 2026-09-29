package handler

// consumeInvitationCodeTx is the invite gate RegisterHandler was missing: before
// 2026-09-29 register stored ANY non-empty string (4 of 88 real signups in the
// preceding 90 days used codes like "qwe" and "NA"). These run against a real
// MySQL because the gate's correctness is the conditional UPDATE's row count.
//
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/idtest?parseTime=true' \
//     go test ./internal/handler -run TestConsumeInvitation

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"lumid_identity/models"
)

func inviteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — the gate's correctness is the conditional UPDATE, which needs a real DB")
	}
	db, err := gorm.Open(mysqldriver.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&models.InvitationCode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func seedInvite(t *testing.T, db *gorm.DB, inv models.InvitationCode) string {
	t.Helper()
	inv.Code = "t-" + time.Now().UTC().Format("150405.000000000") + "-" + inv.Code
	if inv.CreatedByID == "" {
		inv.CreatedByID = "test"
	}
	remaining := inv.UsesRemaining
	if err := db.Create(&inv).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// uses_remaining has `default:1`, so GORM drops an explicit 0 on insert and
	// the column reads 1. Set it after the insert so an exhausted seed is one.
	if err := db.Model(&models.InvitationCode{}).Where("code = ?", inv.Code).
		Update("uses_remaining", remaining).Error; err != nil {
		t.Fatalf("seed uses_remaining: %v", err)
	}
	t.Cleanup(func() { db.Where("code = ?", inv.Code).Delete(&models.InvitationCode{}) })
	return inv.Code
}

func consumeIn(db *gorm.DB, code string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		_, err := consumeInvitationCodeTx(tx, code)
		return err
	})
}

func wantInviteErr(t *testing.T, err error, msg string) {
	t.Helper()
	var ie *invitationCodeError
	if !errors.As(err, &ie) || ie.msg != msg {
		t.Fatalf("got %v, want invitation error %q", err, msg)
	}
}

func TestConsumeInvitationRejectsWhatIsNotAUsableCode(t *testing.T) {
	db := inviteTestDB(t)
	past := time.Now().Add(-time.Hour)

	wantInviteErr(t, consumeIn(db, ""), "invitation_code required")
	wantInviteErr(t, consumeIn(db, "qwe-definitely-not-a-code"), "invitation code invalid")
	wantInviteErr(t, consumeIn(db, seedInvite(t, db, models.InvitationCode{Code: "rev", MaxUses: 1, UsesRemaining: 1, RevokedAt: &past})), "invitation code revoked")
	wantInviteErr(t, consumeIn(db, seedInvite(t, db, models.InvitationCode{Code: "exp", MaxUses: 1, UsesRemaining: 1, ExpiresAt: &past})), "invitation code expired")
	wantInviteErr(t, consumeIn(db, seedInvite(t, db, models.InvitationCode{Code: "used", MaxUses: 1, UsesRemaining: 0})), "invitation code exhausted")
}

func TestConsumeInvitationSpendsExactlyOneSeat(t *testing.T) {
	db := inviteTestDB(t)
	code := seedInvite(t, db, models.InvitationCode{Code: "two", MaxUses: 2, UsesRemaining: 2})
	if err := consumeIn(db, code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	var inv models.InvitationCode
	db.Where("code = ?", code).First(&inv)
	if inv.UsesRemaining != 1 || inv.LastUsedAt == nil {
		t.Fatalf("after one use: remaining=%d last_used=%v, want 1 and set", inv.UsesRemaining, inv.LastUsedAt)
	}
	// A rolled-back signup (user create failed later in the tx) returns the seat.
	_ = db.Transaction(func(tx *gorm.DB) error {
		if _, err := consumeInvitationCodeTx(tx, code); err != nil {
			t.Fatalf("second use: %v", err)
		}
		return errors.New("user create failed")
	})
	db.Where("code = ?", code).First(&inv)
	if inv.UsesRemaining != 1 {
		t.Fatalf("rollback kept the seat spent: remaining=%d, want 1", inv.UsesRemaining)
	}
}

func TestConsumeInvitationConcurrentSignupsCannotOverspend(t *testing.T) {
	db := inviteTestDB(t)
	code := seedInvite(t, db, models.InvitationCode{Code: "last", MaxUses: 1, UsesRemaining: 1})
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if consumeIn(db, code) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d signups won a 1-seat code, want exactly 1", wins)
	}
}
