package common

import (
	"testing"
	"time"

	"lumid_identity/models"
)

func setRoleForTest(sub, role string) {
	roleCacheMu.Lock()
	roleCache[sub] = roleCacheEntry{role: role, exp: time.Now().Add(time.Hour)}
	roleCacheMu.Unlock()
}

// Live-DB: LUMID_QUOTA_TEST_DSN=... go test ./internal/common -run Opus
//
// Usage is seeded the way real usage accrues: OLD Opus usage inside the 7-day
// window but outside the short one (days ago), plus RECENT usage in the short
// window — a single user cannot draw 150M in one 4-hour window under the 45M
// overall cap, so a 7d-cap test must spread it.
func TestOpusAdminCap(t *testing.T) {
	db := connectTestDB(t)
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "45000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "500000000")
	now := time.Now().UTC()
	cases := []struct {
		sub, role           string
		oldOpus, recentOpus int // weighted == raw input for Opus (weight 1.0, no cache)
		wantExhausted       bool
		wantWindow          string
		wantOpusFields      bool
	}{
		{"opus-t-admin-7d", "admin", 145_000_000, 6_000_000, true, "7d", true},   // 151M in 7d
		{"opus-t-admin-short", "admin", 0, 16_000_000, true, "short", true},      // 16M in 4h
		{"opus-t-admin-under", "admin", 100_000_000, 5_000_000, false, "", true}, // 105M / 5M
		{"opus-t-super", "super_admin", 145_000_000, 16_000_000, false, "", false},
	}
	for _, c := range cases {
		cleanupSub(t, db, c.sub)
		setRoleForTest(c.sub, c.role)
		db.Create(&models.ClaudePoolWindow{UserSub: c.sub, FiveHourAnchor: now.Add(-time.Hour), SevenDayAnchor: now.Add(-72 * time.Hour)})
		ev := func(ts time.Time, model string, in int) {
			if in == 0 {
				return
			}
			if err := db.Create(&models.UsageEvent{UserSub: c.sub, Ts: ts, Kind: "claude_proxy", Model: model, InputTokens: in}).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
		ev(now.Add(-48*time.Hour), "claude-opus-5-5", c.oldOpus)
		ev(now.Add(-30*time.Minute), "claude-opus-5-5", c.recentOpus)
		ev(now.Add(-20*time.Minute), "claude-sonnet-5", 2_000_000) // must NOT count toward Opus
		gate, err := CheckAndCharge(db, ChargeReq{UserSub: c.sub, Kind: "claude_proxy", Model: "", DryRun: true})
		if err != nil {
			t.Fatalf("%s gate: %v", c.sub, err)
		}
		if gate.OpusExhausted != c.wantExhausted || gate.OpusWindow != c.wantWindow {
			t.Errorf("%s: exhausted=%v window=%q, want %v %q (used5=%d used7=%d)", c.sub, gate.OpusExhausted, gate.OpusWindow, c.wantExhausted, c.wantWindow, gate.OpusFiveHourUsed, gate.OpusSevenDayUsed)
		}
		if (gate.OpusSevenDayLimit > 0) != c.wantOpusFields {
			t.Errorf("%s: opus limit present=%v, want %v", c.sub, gate.OpusSevenDayLimit > 0, c.wantOpusFields)
		}
		if c.wantOpusFields && (gate.OpusSevenDayUsed != c.oldOpus+c.recentOpus || gate.OpusFiveHourUsed != c.recentOpus) {
			t.Errorf("%s: opus used5=%d used7=%d, want %d %d (sonnet must not count)", c.sub, gate.OpusFiveHourUsed, gate.OpusSevenDayUsed, c.recentOpus, c.oldOpus+c.recentOpus)
		}
		if c.wantExhausted && gate.OpusReset == "" {
			t.Errorf("%s: exhausted but no reset time", c.sub)
		}
		if !gate.Allowed {
			t.Errorf("%s: overall verdict must stay allowed (Opus cap only gates Opus): %s", c.sub, gate.DenyReason)
		}
		cleanupSub(t, db, c.sub)
	}
}
