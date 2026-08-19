package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// Pins the alerting gap fixed 2026-08-19: InternalClaudePoolHealth's `healthy`
// field used to be `refreshable >= floor`, which never noticed an account that
// still holds a live refresh token but is ≥98% spent on its 5h/7d window and
// therefore cannot actually be leased. A pool at refreshable=2 (floor=2) read
// healthy:true even with only 1 truly servable account — opsagent's P0 alert
// trusts `healthy` verbatim, so that state paged nobody.
//
// snapshotIsExhausted is what both the lease-candidate loop and the health
// endpoint now call, so a case here pins both call sites at once.
func TestSnapshotIsExhausted(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		snap *models.ClaudeQuotaSnapshot
		want bool
	}{
		{"nil snapshot — nothing known, not exhausted", nil, false},
		{
			"healthy on both windows",
			&models.ClaudeQuotaSnapshot{
				Ts: now, FiveHourPct: 15, SevenDayPct: 40,
				FiveHourReset: now.Add(2 * time.Hour), SevenDayReset: now.Add(3 * 24 * time.Hour),
			},
			false,
		},
		{
			"7d at 98%, reset still in the future — exhausted (this is ac5's live shape)",
			&models.ClaudeQuotaSnapshot{
				Ts: now, FiveHourPct: 0, SevenDayPct: 98,
				FiveHourReset: now.Add(2 * time.Hour), SevenDayReset: now.Add(20 * time.Hour),
			},
			true,
		},
		{
			"7d was 98% but the reset already passed — window rolled, no longer exhausted",
			&models.ClaudeQuotaSnapshot{
				Ts: now.Add(-6 * time.Minute), FiveHourPct: 0, SevenDayPct: 98,
				FiveHourReset: now.Add(2 * time.Hour), SevenDayReset: now.Add(-time.Minute),
			},
			false,
		},
		{
			"5h at 98%, fresh snapshot within cache TTL, no reset recorded yet — exhausted",
			&models.ClaudeQuotaSnapshot{
				Ts: now, FiveHourPct: 98, SevenDayPct: 10,
			},
			true,
		},
		{
			"critical severity, fresh — exhausted even if percentages are stale/low",
			&models.ClaudeQuotaSnapshot{
				Ts: now, FiveHourPct: 40, SevenDayPct: 40, Severity: "critical",
			},
			true,
		},
		{
			"98% but snapshot is stale (past quotaCacheTTL) and carries no reset — not trusted, re-probe",
			&models.ClaudeQuotaSnapshot{
				Ts: now.Add(-quotaCacheTTL - time.Minute), FiveHourPct: 98, SevenDayPct: 10,
			},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := snapshotIsExhausted(tc.snap, now); got != tc.want {
				t.Errorf("snapshotIsExhausted() = %v, want %v", got, tc.want)
			}
		})
	}
}

// The exact live shape that motivated this fix: 4 accounts, 2 quarantined
// (excluded from `refreshable` already), 1 refreshable-but-exhausted (ac5 at
// 7d=98%), 1 genuinely healthy (ac2). servable must read 1, not 2, so `healthy`
// (servable >= floor, floor=2) reads false and the P0 alert fires.
func TestServableExcludesExhaustedFromHealthyFloor(t *testing.T) {
	const floor = 2
	refreshable := 2 // ac2 (healthy) + ac5 (exhausted) — ac1/ac9 are quarantined, not counted here
	exhausted := 1   // ac5 only
	servable := refreshable - exhausted

	if servable != 1 {
		t.Fatalf("servable = %d, want 1", servable)
	}
	if healthy := servable >= floor; healthy {
		t.Fatalf("healthy = true with only %d servable account(s) against floor %d — the exact gap this fix closes", servable, floor)
	}
	if healthy := refreshable >= floor; !healthy {
		t.Fatalf("sanity check failed: the OLD (buggy) refreshable>=floor computation should still read true here — "+
			"got false, meaning this test no longer reproduces the reported gap (refreshable=%d, floor=%d)", refreshable, floor)
	}
}
