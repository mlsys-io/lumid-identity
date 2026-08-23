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
	"math"
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
	// The window counts WEIGHTED units, not raw tokens: both charges are sonnet
	// (×0.6). (1500 + 300) × 0.6 = 1080.
	if want := int(math.Round(float64(1500+300) * claudeWeightSonnet)); status.FiveHourUsed != want {
		t.Fatalf("five_hour_used=%d want %d (weighted units, not raw tokens)",
			status.FiveHourUsed, want)
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
	// Weighted sonnet (×0.6): 777 × 0.6 = 466.
	if want := int(math.Round(float64(777) * claudeWeightSonnet)); status.FiveHourUsed != want {
		t.Fatalf("five_hour_used after roll=%d want %d (old 5000 must not count)", status.FiveHourUsed, want)
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

// A REFUSED request writes nothing — it never consumed anything. For
// claude_proxy that means the DRY-RUN gate, which is the only call that can
// actually refuse: it happens before the request is served. Other kinds are
// pre-authorization by nature, so a plain denial covers them.
func TestClaudePoolWindow_RefusedNeverCommits(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000") // tiny cap, easy to blow through
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("refused")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// Seed usage so the user is already over, then let the gate refuse.
	if _, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-sonnet-5",
		InputTokens: 5000, OutputTokens: 0,
	}); err != nil {
		t.Fatalf("seed charge: %v", err)
	}
	var evBefore int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evBefore)

	// The dry-run gate: zero tokens, must refuse and must write nothing.
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "", DryRun: true,
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if res.Allowed {
		t.Fatalf("gate must refuse a user already over the cap")
	}
	var evAfter int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evAfter)
	if evAfter != evBefore {
		t.Fatalf("refused gate wrote %d usage_events rows, want 0", evAfter-evBefore)
	}
}

// An OVERSPEND — a non-dry-run claude_proxy charge whose tokens Anthropic has
// already served — MUST be recorded even though it breaches the cap.
//
// This inverts the older "denied charge never commits" rule, which conflated
// refusal with accounting. claude-proxy gates on a dry run carrying zero tokens
// and charges for real only after the response is served, so dropping the
// over-cap record left the counter frozen one request short of the cap forever:
// the gate kept seeing used+0 <= cap and kept allowing, while the user consumed
// without limit and never received a single 429. Observed live 2026-08-12 with
// two users pinned just under a 5M cap while still serving traffic.
func TestClaudePoolWindow_OverspendIsRecorded(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("overspend")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// Land just under the cap.
	if _, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-opus-5",
		InputTokens: 900, OutputTokens: 0,
	}); err != nil {
		t.Fatalf("under-cap charge: %v", err)
	}
	before, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage before: %v", err)
	}

	// A real charge that crosses the cap: denied, but recorded.
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "claude-opus-5",
		InputTokens: 500, OutputTokens: 0,
	})
	if err != nil {
		t.Fatalf("overspend charge: %v", err)
	}
	if res.Allowed {
		t.Fatalf("charge crossing the cap should report Allowed=false")
	}

	after, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage after: %v", err)
	}
	if after.FiveHourUsed <= before.FiveHourUsed {
		t.Fatalf("overspend was not recorded: usage stayed at %d (the frozen-counter bug)",
			before.FiveHourUsed)
	}
	if after.FiveHourUsed <= 1000 {
		t.Fatalf("recorded usage %d must now EXCEED the 1000 cap, or the next gate still allows",
			after.FiveHourUsed)
	}

	// The point of recording it: the next gate now refuses.
	gate, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "", DryRun: true,
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if gate.Allowed {
		t.Fatalf("gate must refuse after an overspend pushed the user over the cap")
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
	// Weighted sonnet (×0.6): n×100 raw × 0.6 = 480.
	if want := int(math.Round(float64(n) * 100 * claudeWeightSonnet)); status.FiveHourUsed != want {
		t.Fatalf("five_hour_used=%d want %d (all concurrent charges must count under the converged anchor)",
			status.FiveHourUsed, want)
	}
}

// A non-Anthropic model (deepseek-v4-flash) must count toward the SAME shared
// 5h/7d window as Claude, open the window anchor like Claude, and be able to
// deny a subsequent Claude request once the shared cap is crossed. This is the
// metering-gap closure: previously deepseek bypassed entirely (unmetered, never
// gated). Cost is handled by the weight, not exclusion — weighted tokens of a
// deepseek charge count against the same caps a Claude charge counts against.
func TestClaudePoolWindow_NonClaudeCounts(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1000") // tight share cap for fast test
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10000")
	db := connectTestDB(t)
	sub := claudePoolTestSub("nonclaude")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// One deepseek turn: 1000 fresh input. Weighted at claudeWeightNonClaude (0.1)
	// → 100 weighted units.
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "deepseek-v4-flash",
		InputTokens: 1000, OutputTokens: 200,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("deepseek charge: err=%v allowed=%v", err, res.Allowed)
	}
	if res.FiveHourReset == "" {
		t.Fatalf("deepseek charge should open the shared window anchor, got empty reset")
	}

	// The deepseek charge counted into the shared window at its weight.
	status, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("usage after deepseek: %v", err)
	}
	if want := int(math.Round(float64(1200) * claudeWeightNonClaude)); status.FiveHourUsed != want {
		t.Fatalf("five_hour_used=%d want %d (deepseek weighted into the shared window)",
			status.FiveHourUsed, want)
	}

	// A second deepseek charge pushes the SHARED cap past 1000 weighted units →
	// a subsequent CLAUDE request must now be denied. Cross-model same-window.
	if _, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "deepseek-v4-flash",
		InputTokens: 9000, OutputTokens: 0, // +900 weighted → total ~1020
	}); err != nil {
		t.Fatalf("second deepseek charge: %v", err)
	}
	gate, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "", DryRun: true,
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if gate.Allowed {
		t.Fatalf("a Claude model must be denied once the SHARED window (exhausted by deepseek) is over the cap")
	}
}

// An admin/super_admin has NO quota cap (claudePoolUnlimitedSentinel) but their
// usage must STILL be counted: the event is recorded and the window anchor rolls,
// so /me/claude-usage and the admin table show it. "No quota" applies to the cap
// check, not to the accounting.
func TestClaudePoolWindow_AdminStillCounts(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "1") // absurdly tiny — only binds for non-admins
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "10")
	db := connectTestDB(t)
	sub := claudePoolTestSub("admin-count")
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// The role lookup reads users.id (the sub). A synthetic sub has no users row
	// and would fail OPEN to the tiny global caps — proving nothing about admins.
	// connectTestDB only migrates UsageEvent + ClaudePoolWindow, so ensure the
	// minimal users table exists, insert a real admin row, and clear any stale
	// role-cache entry so the role actually resolves to admin.
	db.Exec(`CREATE TABLE IF NOT EXISTS users (id VARCHAR(36) PRIMARY KEY,
		email VARCHAR(255), role VARCHAR(32) DEFAULT 'user')`)
	db.Exec(`INSERT INTO users (id, email, role) VALUES (?, ?, 'admin')
		ON DUPLICATE KEY UPDATE role = 'admin'`, sub, sub+"@test")
	t.Cleanup(func() { db.Exec(`DELETE FROM users WHERE id = ?`, sub) })
	roleCacheMu.Lock()
	delete(roleCache, sub)
	roleCacheMu.Unlock()

	// The sentinel is what frees admins from the cap.
	if short, seven := ClaudePoolLimitsForRole("super_admin"); short != claudePoolUnlimitedSentinel || seven != claudePoolUnlimitedSentinel {
		t.Fatalf("admin caps = (%d,%d), want sentinel (%d,%d)",
			short, seven, claudePoolUnlimitedSentinel, claudePoolUnlimitedSentinel)
	}

	// An admin's deepseek charge is allowed (uncapped) and still recorded.
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "claude_proxy", Model: "deepseek-v4-flash",
		InputTokens: 1_000_000, OutputTokens: 0, // huge, but uncapped
	})
	if err != nil || !res.Allowed {
		t.Fatalf("admin deepseek charge: err=%v allowed=%v deny=%q", err, res.Allowed, res.DenyReason)
	}
	var evCnt int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&evCnt)
	if evCnt != 1 {
		t.Fatalf("admin charge recorded %d usage_events rows, want 1 (must still count)", evCnt)
	}
	var win models.ClaudePoolWindow
	if err := db.Where("user_sub = ?", sub).First(&win).Error; err != nil {
		t.Fatalf("admin charge should still roll the window anchor: %v", err)
	}
	status, err := ClaudePoolUsage(db, sub, time.Now().UTC())
	if err != nil {
		t.Fatalf("admin usage: %v", err)
	}
	if status.FiveHourUsed <= 0 {
		t.Fatalf("admin usage must be counted, got %d", status.FiveHourUsed)
	}
}
