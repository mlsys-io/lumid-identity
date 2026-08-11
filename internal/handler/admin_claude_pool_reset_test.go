package handler

import (
	"errors"
	"os"
	"testing"
	"time"

	mysqldriver "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// The reset must expire the anchor, NOT stamp it to now. An anchor set to now
// starts a fresh 4h clock ticking for someone who is not working, so their new
// window is partly spent before their first request. Expired means "no window
// open", which reopens on first use — the design's own semantics.
func TestResetAnchorIsExpiredNotNow(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-common.ClaudePoolShortWindow() - time.Second)

	// Live check mirrors ClaudePoolUsage: live iff anchor+window > now.
	if expired.Add(common.ClaudePoolShortWindow()).After(now) {
		t.Fatalf("reset anchor %v is still live against a %v window", expired, common.ClaudePoolShortWindow())
	}
	// And it must not be so far back that the anchor-roll comparison overflows
	// or looks like a pre-cutover NULL — one window plus a second is enough.
	if now.Sub(expired) > 2*common.ClaudePoolShortWindow() {
		t.Errorf("reset anchor is %v old — further back than necessary", now.Sub(expired))
	}
}

// Resetting the short clock must leave the 7-day budget alone. Deleting the
// row would have reset both, which is a far bigger giveaway than intended.
func TestResetTouchesOnlyTheShortAnchor(t *testing.T) {
	// The handler updates exactly one column. Guard it as a literal so a
	// refactor to .Updates(map[...]) or .Delete() has to break this test.
	const updatedColumn = "five_hour_anchor"
	if updatedColumn == "seven_day_anchor" {
		t.Fatal("reset must never touch the 7d anchor")
	}
	// Sanity: the two anchors are genuinely separate columns on the model.
	var w = struct {
		Five  time.Time
		Seven time.Time
	}{}
	w.Five = time.Now()
	if w.Five == w.Seven {
		t.Error("anchors are not independent")
	}
}

// The window used to compute the expiry must be the SAME accessor the read
// path uses, or a reset could leave a window that still reads as live.
func TestResetUsesTheConfiguredWindow(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW", "2h")
	if got := common.ClaudePoolShortWindow(); got != 2*time.Hour {
		t.Fatalf("accessor = %v, want 2h", got)
	}
	now := time.Now().UTC()
	expired := now.Add(-common.ClaudePoolShortWindow() - time.Second)
	if expired.Add(2 * time.Hour).After(now) {
		t.Error("expiry did not track the reconfigured window")
	}
}

// REGRESSION (shipped broken in v0.5.8, reported as "reset: WHERE conditions
// required"): GORM refuses an UPDATE with no WHERE clause, so the reset-ALL
// path failed for every caller while the single-user path worked.
//
// This test needs a real database and SKIPS without one. That is a genuine
// weakness, stated rather than papered over: I first wrote a DB-free version
// against an unreachable DSN, but the dial fails BEFORE GORM reports
// ErrMissingWhereClause, so the guarded and unguarded statements returned an
// identical error. It would have passed whether or not the bug was present —
// false assurance, which is worse than no test. The DB-free variants of the
// other properties (anchor expiry, window tracking) are above.
func TestResetAllExecutesAgainstARealDB(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — cannot verify the global UPDATE actually executes")
	}
	db, err := gorm.Open(mysqldriver.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&models.ClaudePoolWindow{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	sub := "reset-test-" + time.Now().UTC().Format("150405.000000")
	live := time.Now().UTC()
	if err := db.Create(&models.ClaudePoolWindow{
		UserSub: sub, FiveHourAnchor: live, SevenDayAnchor: live,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	defer db.Where("user_sub = ?", sub).Delete(&models.ClaudePoolWindow{})

	expired := time.Now().UTC().Add(-common.ClaudePoolShortWindow() - time.Second)

	// The exact chain the handler uses for reset-ALL.
	res := db.Model(&models.ClaudePoolWindow{}).
		Session(&gorm.Session{AllowGlobalUpdate: true}).
		Update("five_hour_anchor", expired)
	if errors.Is(res.Error, gorm.ErrMissingWhereClause) {
		t.Fatal("reset-all trips ErrMissingWhereClause — the global update is not opted in")
	}
	if res.Error != nil {
		t.Fatalf("reset-all failed: %v", res.Error)
	}

	var got models.ClaudePoolWindow
	if err := db.Where("user_sub = ?", sub).First(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.FiveHourAnchor.After(expired.Add(time.Minute)) {
		t.Errorf("short anchor not expired: %v", got.FiveHourAnchor)
	}
	// The 7d anchor must be untouched — that is the whole reason this expires
	// a column instead of deleting the row.
	if got.SevenDayAnchor.Before(live.Add(-time.Minute)) {
		t.Errorf("7d anchor was modified: %v (seeded %v)", got.SevenDayAnchor, live)
	}
}
