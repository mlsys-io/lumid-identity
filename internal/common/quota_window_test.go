package common

// Tests for the fixed-window (hard count-down-and-reset) Claude pool quota
// clock — ClaudeWindowLive, ClaudePoolUsage, ClaudePoolCommit, and their
// wiring through CheckAndCharge's claude_proxy case.
//
// Pure tests run always. Live-DB tests reuse quota_test.go's
// connectTestDB/cleanupSub and are gated the same way (LUMID_QUOTA_TEST_DSN),
// run via:
//
//	docker run --rm --network=host -v /proj/lumid_identity:/src \
//	  -v /tmp/gocache:/root/.cache/go-build -v /tmp/gopath:/go \
//	  -w /src -e LUMID_QUOTA_TEST_DSN="root:<pw>@tcp(172.17.0.1:3306)/lumid_identity?parseTime=true&loc=UTC" \
//	  golang:1.25 go test -buildvcs=false -v ./internal/common/ -run 'TestClaudeWindow|TestClaudePoolWindow'

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"lumid_identity/models"
)

func TestClaudeWindowLive(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	const fiveH = 5 * time.Hour

	t.Run("zero anchor is never live", func(t *testing.T) {
		live, reset := ClaudeWindowLive(time.Time{}, fiveH, now)
		if live {
			t.Fatalf("zero anchor: live=true, want false")
		}
		if !reset.IsZero() {
			t.Fatalf("zero anchor: reset=%v, want zero", reset)
		}
	})

	t.Run("now inside window is live", func(t *testing.T) {
		anchor := now.Add(-1 * time.Hour) // opened 1h ago, 4h left
		live, reset := ClaudeWindowLive(anchor, fiveH, now)
		if !live {
			t.Fatalf("mid-window: live=false, want true")
		}
		wantReset := anchor.Add(fiveH)
		if !reset.Equal(wantReset) {
			t.Fatalf("mid-window: reset=%v want %v", reset, wantReset)
		}
	})

	t.Run("one nanosecond before boundary is live", func(t *testing.T) {
		anchor := now.Add(-fiveH).Add(time.Nanosecond) // boundary is 1ns in the future
		live, _ := ClaudeWindowLive(anchor, fiveH, now)
		if !live {
			t.Fatalf("1ns before boundary: live=false, want true")
		}
	})

	t.Run("boundary instant is expired-inclusive, not live", func(t *testing.T) {
		anchor := now.Add(-fiveH) // now == anchor+5h exactly
		live, reset := ClaudeWindowLive(anchor, fiveH, now)
		if live {
			t.Fatalf("now==anchor+windowLen: live=true, want false (boundary is expired-inclusive)")
		}
		if !reset.Equal(now) {
			t.Fatalf("boundary: reset=%v want %v (still reports the elapsed boundary)", reset, now)
		}
	})
}

// user_sub is size:36 — keep well under that even for longer test names.
func claudePoolTestSub(name string) string {
	return fmt.Sprintf("qp-%s-%d", name, time.Now().UnixNano()%1_000_000_000)
}

func TestClaudePoolWindow_OpensOnFirstCharge(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("open")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// Never charged: idle, blank reset, zero used.
	status, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage before any charge: %v", err)
	}
	if status.FiveHourUsed != 0 || !status.FiveHourReset.IsZero() {
		t.Fatalf("before any charge: want idle, got %+v", status)
	}

	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 1000, OutputTokens: 500,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("first charge: err=%v allowed=%v deny=%q", err, res.Allowed, res.DenyReason)
	}
	if res.FiveHourReset == "" || res.SevenDayReset == "" {
		t.Fatalf("first charge should open both windows, got five=%q seven=%q", res.FiveHourReset, res.SevenDayReset)
	}

	var win models.ClaudePoolWindow
	if err := db.Where("user_sub = ?", sub).First(&win).Error; err != nil {
		t.Fatalf("expected an anchor row after first charge: %v", err)
	}
	firstFive := win.FiveHourAnchor

	// Second charge inside the same window must NOT move the anchor, and
	// usage must accumulate on top of the first charge.
	res2, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 200, OutputTokens: 100,
	})
	if err != nil || !res2.Allowed {
		t.Fatalf("second charge: err=%v allowed=%v", err, res2.Allowed)
	}
	var win2 models.ClaudePoolWindow
	db.Where("user_sub = ?", sub).First(&win2)
	if !win2.FiveHourAnchor.Equal(firstFive) {
		t.Fatalf("anchor moved within the same window: %v -> %v", firstFive, win2.FiveHourAnchor)
	}
	status, err = ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage after two charges: %v", err)
	}
	if status.FiveHourUsed != 1800 { // 1000+500+200+100
		t.Fatalf("five_hour_used=%d want 1800", status.FiveHourUsed)
	}
}

func TestClaudePoolWindow_BackdatedRoll(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("backdate")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	old := time.Now().UTC().Add(-10 * time.Hour) // long past both would-be 5h/7d... just 5h here
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 5000, OutputTokens: 0,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("seed charge: err=%v allowed=%v", err, res.Allowed)
	}
	// Force the anchor into the past directly, simulating a window that has
	// since fully expired (avoids a real 5h sleep in the test).
	if err := db.Model(&models.ClaudePoolWindow{}).Where("user_sub = ?", sub).
		Update("five_hour_anchor", old).Error; err != nil {
		t.Fatalf("backdate: %v", err)
	}

	now := time.Now().UTC()
	status, err := ClaudePoolUsage(db, sub, now)
	if err != nil {
		t.Fatalf("usage after backdate: %v", err)
	}
	if status.FiveHourUsed != 0 || !status.FiveHourReset.IsZero() {
		t.Fatalf("expired 5h window should read idle before any new charge, got %+v", status)
	}

	// A new charge must roll the anchor forward and count only itself.
	res2, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 777, OutputTokens: 0,
	})
	if err != nil || !res2.Allowed {
		t.Fatalf("post-expiry charge: err=%v allowed=%v", err, res2.Allowed)
	}
	status, err = ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage after roll: %v", err)
	}
	if status.FiveHourUsed != 777 {
		t.Fatalf("five_hour_used after roll=%d want 777 (old 5000 must not count)", status.FiveHourUsed)
	}
	var win models.ClaudePoolWindow
	db.Where("user_sub = ?", sub).First(&win)
	// Compare against `old` with a wide margin rather than the precise
	// pre-charge `now` snapshot — MySQL may store DATETIME with lower
	// sub-second precision than Go's time.Time, so a tight comparison can
	// spuriously fail on truncation even though the roll happened correctly.
	if !win.FiveHourAnchor.After(old.Add(time.Hour)) {
		t.Fatalf("anchor did not roll forward past the backdated value: got %v, backdated to %v", win.FiveHourAnchor, old)
	}
}

func TestClaudePoolWindow_DeniedNeverCommits(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000") // tiny cap, easy to blow through
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("denied")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 5000, OutputTokens: 0, // over the 1000 cap
	})
	if err != nil {
		t.Fatalf("oversized charge: %v", err)
	}
	if res.Allowed {
		t.Fatalf("oversized charge should be denied")
	}
	var winCnt, evCnt int64
	db.Model(&models.ClaudePoolWindow{}).Where("user_sub = ?", sub).Count(&winCnt)
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evCnt)
	if winCnt != 0 {
		t.Fatalf("denied charge must not create an anchor row, found %d", winCnt)
	}
	if evCnt != 0 {
		t.Fatalf("denied charge must not write a usage_events row, found %d", evCnt)
	}

	// A subsequent smaller, allowed charge is what actually opens the window.
	res2, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 500, OutputTokens: 0,
	})
	if err != nil || !res2.Allowed {
		t.Fatalf("follow-up small charge: err=%v allowed=%v", err, res2.Allowed)
	}
	db.Model(&models.ClaudePoolWindow{}).Where("user_sub = ?", sub).Count(&winCnt)
	if winCnt != 1 {
		t.Fatalf("allowed charge should open exactly one anchor row, found %d", winCnt)
	}
}

func TestClaudePoolWindow_DryRunNeverCommits(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("dryrun")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// claude-proxy's pre-request gate: repeated dry-run, empty model, zero tokens.
	for i := 0; i < 3; i++ {
		res, err := CheckAndCharge(db, ChargeReq{UserSub: sub, Kind: "claude_proxy", DryRun: true})
		if err != nil || !res.Allowed {
			t.Fatalf("dry-run gate %d: err=%v allowed=%v", i, err, res.Allowed)
		}
		if res.FiveHourReset != "" || res.SevenDayReset != "" {
			t.Fatalf("dry-run gate %d must never report a live reset, got five=%q seven=%q",
				i, res.FiveHourReset, res.SevenDayReset)
		}
	}
	var winCnt, evCnt int64
	db.Model(&models.ClaudePoolWindow{}).Where("user_sub = ?", sub).Count(&winCnt)
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evCnt)
	if winCnt != 0 || evCnt != 0 {
		t.Fatalf("dry-run gate calls must be fully side-effect-free, found windows=%d events=%d", winCnt, evCnt)
	}
}

func TestClaudePoolWindow_ConcurrentRollConvergence(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("concurrent")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// Seed a long-expired anchor so every concurrent commit below sees a
	// "roll needed" state at once — the scenario ClaudePoolCommit's
	// ON DUPLICATE KEY UPDATE guard has to converge safely under.
	expired := time.Now().UTC().Add(-48 * time.Hour)
	if err := db.Exec(`
		INSERT INTO claude_pool_windows (user_sub, five_hour_anchor, seven_day_anchor, updated_at)
		VALUES (?, ?, ?, ?)`, sub, expired, expired, expired).Error; err != nil {
		t.Fatalf("seed expired anchor: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	allowed := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := CheckAndCharge(db, ChargeReq{
				UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
				InputTokens: 100, OutputTokens: 0,
			})
			errs[i], allowed[i] = err, res.Allowed
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
		if !allowed[i] {
			t.Fatalf("goroutine %d: charge should be allowed", i)
		}
	}

	// All n usage_events rows must be preserved — the guard must never lose
	// a charge, only converge the anchor.
	var evCnt int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evCnt)
	if evCnt != n {
		t.Fatalf("usage_events rows=%d want %d (concurrency must not drop charges)", evCnt, n)
	}

	// Exactly one anchor row, rolled well past the seeded 48h-expired value.
	// Compared against `expired` with a wide margin rather than a precise
	// "now" snapshot — MySQL may store DATETIME with lower sub-second
	// precision than Go's time.Time, so a tight comparison can spuriously
	// fail on truncation even though the roll happened correctly.
	var wins []models.ClaudePoolWindow
	db.Where("user_sub = ?", sub).Find(&wins)
	if len(wins) != 1 {
		t.Fatalf("anchor rows=%d want 1", len(wins))
	}
	if !wins[0].FiveHourAnchor.After(expired.Add(time.Hour)) {
		t.Fatalf("converged anchor %v did not roll forward past the seeded expired value %v", wins[0].FiveHourAnchor, expired)
	}

	status, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage after convergence: %v", err)
	}
	if status.FiveHourUsed != n*100 {
		t.Fatalf("five_hour_used=%d want %d (all concurrent charges must count under the converged anchor)",
			status.FiveHourUsed, n*100)
	}
}
