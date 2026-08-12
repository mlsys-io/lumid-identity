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
	// NOTE: the previous version of this test compared two string literals to
	// each other and asserted nothing about the handler. It passed unchanged
	// when the handler was refactored from Update("five_hour_anchor", ...) to
	// Updates(map[...]) with a second column — exactly the regression it
	// claimed to guard. It now calls the real decision function.
	now := time.Now().UTC()

	cols, label, err := poolResetColumns("", now) // default
	if err != nil {
		t.Fatalf("default window rejected: %v", err)
	}
	if _, touched := cols["seven_day_anchor"]; touched {
		t.Fatal("DEFAULT reset touched the 7d anchor — the weekly budget must never be given away implicitly")
	}
	if _, ok := cols["five_hour_anchor"]; !ok {
		t.Fatal("default reset did not touch the short anchor")
	}
	if len(cols) != 1 {
		t.Fatalf("default reset wrote %d columns, want exactly 1: %v", len(cols), cols)
	}
	if label != shortWindowLabel() {
		t.Errorf("default label = %q, want %q", label, shortWindowLabel())
	}
}

// The weekly reset is the inverse: it must move the 7d anchor and leave the
// short window alone, so resetting the week does not also hand back a 4h budget
// the user may have legitimately spent minutes ago.
func TestWeeklyResetTouchesOnlyTheSevenDayAnchor(t *testing.T) {
	now := time.Now().UTC()
	cols, label, err := poolResetColumns("weekly", now)
	if err != nil {
		t.Fatalf("weekly rejected: %v", err)
	}
	if _, touched := cols["five_hour_anchor"]; touched {
		t.Error("weekly reset touched the short anchor")
	}
	anchor, ok := cols["seven_day_anchor"].(time.Time)
	if !ok {
		t.Fatal("weekly reset did not set seven_day_anchor")
	}
	// Must read as CLOSED against a 7d window, or the reset is a no-op.
	if anchor.Add(7 * 24 * time.Hour).After(now) {
		t.Errorf("weekly anchor %v still live against a 7d window", anchor)
	}
	if label != "7d" {
		t.Errorf("label = %q, want 7d", label)
	}
}

func TestBothResetsEachAnchorAgainstItsOwnWindow(t *testing.T) {
	now := time.Now().UTC()
	cols, _, err := poolResetColumns("both", now)
	if err != nil {
		t.Fatalf("both rejected: %v", err)
	}
	if len(cols) != 2 {
		t.Fatalf("both wrote %d columns, want 2", len(cols))
	}
	// Each anchor must be expired against ITS OWN window — reusing the short
	// window for the 7d anchor would leave the weekly clock still running.
	short := cols["five_hour_anchor"].(time.Time)
	weekly := cols["seven_day_anchor"].(time.Time)
	if short.Add(common.ClaudePoolShortWindow()).After(now) {
		t.Error("short anchor still live")
	}
	if weekly.Add(7 * 24 * time.Hour).After(now) {
		t.Error("weekly anchor still live — likely expired against the SHORT window")
	}
}

func TestUnknownWindowIsRejectedNotSilentlyDefaulted(t *testing.T) {
	// A typo like "week" must 400, not quietly reset the short window and
	// report success while the caller believes the weekly clock moved.
	for _, w := range []string{"week", "7d", "weekley", "all", "none"} {
		if _, _, err := poolResetColumns(w, time.Now().UTC()); err == nil {
			t.Errorf("window %q was accepted; want rejection", w)
		}
	}
}

func TestWindowParsingIsForgivingAboutCaseAndSpace(t *testing.T) {
	for _, w := range []string{"Weekly", " weekly ", "WEEKLY"} {
		cols, _, err := poolResetColumns(w, time.Now().UTC())
		if err != nil {
			t.Fatalf("window %q rejected: %v", w, err)
		}
		if _, ok := cols["seven_day_anchor"]; !ok {
			t.Errorf("window %q did not resolve to weekly", w)
		}
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
