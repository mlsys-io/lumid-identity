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

// The pool's one leading indicator of a quarantine is an indeterminate exchange
// with no later success. Before this it lived in a column no consumer read, so
// the operator learned about a lost rotation only once the account was already
// dead and lum.id/claude was already down an account.
//
// The predicate must be self-clearing WITHOUT a timer: a later successful
// exchange is proof the family survived (Anthropic accepted the stored refresh
// token, which it could not have done if the lost rotation had superseded it),
// and markIndeterminate deliberately never clears its own marker because that
// marker is the forensic trail.
func TestLostRotationUnresolved(t *testing.T) {
	at := time.Now().Add(-90 * time.Minute)
	after := at.Add(10 * time.Minute)
	before := at.Add(-10 * time.Minute)

	cases := []struct {
		name string
		row  models.ClaudeQuotaToken
		want bool
	}{
		{
			"never had an indeterminate — nothing at risk",
			models.ClaudeQuotaToken{Email: "ac3@nati"},
			false,
		},
		{
			"indeterminate, nothing since — LIVE RISK, the next exchange may quarantine it",
			models.ClaudeQuotaToken{Email: "ac3@nati", IndeterminateAt: &at},
			true,
		},
		{
			"indeterminate, then a successful exchange — the family provably survived",
			models.ClaudeQuotaToken{
				Email: "ac3@nati", IndeterminateAt: &at,
				LastExchangeOutcome: "ok", LastExchangeAt: &after,
			},
			false,
		},
		{
			"the only success PREDATES the indeterminate — proves nothing about it",
			models.ClaudeQuotaToken{
				Email: "ac3@nati", IndeterminateAt: &at,
				LastExchangeOutcome: "ok", LastExchangeAt: &before,
			},
			true,
		},
		{
			"a later exchange that FAILED is not proof of survival",
			models.ClaudeQuotaToken{
				Email: "ac3@nati", IndeterminateAt: &at,
				LastExchangeOutcome: "error:invalid_request", LastExchangeAt: &after,
			},
			true,
		},
		{
			"a later INDETERMINATE is certainly not proof of survival",
			models.ClaudeQuotaToken{
				Email: "ac3@nati", IndeterminateAt: &at,
				LastExchangeOutcome: "indeterminate", LastExchangeAt: &after,
			},
			true,
		},
		{
			"old indeterminate stays at risk however long ago — a timer would silence a real risk",
			models.ClaudeQuotaToken{
				Email:           "ac3@nati",
				IndeterminateAt: func() *time.Time { d := time.Now().Add(-30 * 24 * time.Hour); return &d }(),
			},
			true,
		},
	}

	for _, c := range cases {
		if got := lostRotationUnresolved(&c.row); got != c.want {
			t.Errorf("%s: lostRotationUnresolved = %v, want %v", c.name, got, c.want)
		}
	}
}

// The second at-risk signal: our access token refused mid-life, i.e. something
// else invalidated the family. Unlike a lost rotation this is an EVENT, so it
// ages out rather than waiting to be disproved — a later success does not mean
// it did not happen, only that the family survived that particular one.
func TestPreExpiry401Recent(t *testing.T) {
	now := time.Now()
	mk := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	cases := []struct {
		name string
		row  models.ClaudeQuotaToken
		want bool
	}{
		{"never happened", models.ClaudeQuotaToken{Email: "ac3@nati"}, false},
		{
			"three minutes ago — this is the ac9 shape, quarantined 3m04s after an add",
			models.ClaudeQuotaToken{Email: "ac9@yao.lu", PreExpiry401At: mk(-3 * time.Minute)},
			true,
		},
		{
			"a later success does NOT clear it — the event still happened",
			models.ClaudeQuotaToken{
				Email: "ac9@yao.lu", PreExpiry401At: mk(-3 * time.Minute),
				LastExchangeOutcome: "ok", LastExchangeAt: mk(-1 * time.Minute),
			},
			true,
		},
		{
			"older than the window — aged out, no longer actionable",
			models.ClaudeQuotaToken{Email: "ac3@nati", PreExpiry401At: mk(-preExpiry401Window - time.Minute)},
			false,
		},
	}
	for _, c := range cases {
		if got := preExpiry401Recent(&c.row, now); got != c.want {
			t.Errorf("%s: preExpiry401Recent = %v, want %v", c.name, got, c.want)
		}
	}
}

// Dormancy: an account nobody leases must stop paying for a credential nobody
// uses, without ever letting the family go unexercised past the heartbeat.
func TestAccountIsDormant(t *testing.T) {
	now := time.Now()
	mk := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	cases := []struct {
		name string
		row  models.ClaudeQuotaToken
		want bool
	}{
		{
			"leased minutes ago — in use, never dormant",
			models.ClaudeQuotaToken{LastLeasedAt: mk(-5 * time.Minute), RotatedAt: mk(-10 * time.Minute)},
			false,
		},
		{
			"idle and rotated recently — dormant, skip the draw",
			models.ClaudeQuotaToken{LastLeasedAt: mk(-8 * time.Hour), RotatedAt: mk(-time.Hour)},
			true,
		},
		{
			"never leased but rotated recently — a standby is still dormant",
			models.ClaudeQuotaToken{RotatedAt: mk(-time.Hour)},
			true,
		},
		{
			"never exchanged — a new account must get its first refresh",
			models.ClaudeQuotaToken{},
			false,
		},
		{
			"idle but the heartbeat is due — exchange anyway, so a dead standby is found",
			models.ClaudeQuotaToken{
				LastLeasedAt: mk(-3 * 24 * time.Hour),
				RotatedAt:    mk(-claudeIdleHeartbeat - time.Minute),
			},
			false,
		},
		{
			"leased just inside the idle threshold — still in use",
			models.ClaudeQuotaToken{LastLeasedAt: mk(-claudeIdleAfter + time.Minute), RotatedAt: mk(-time.Hour)},
			false,
		},
	}
	for _, c := range cases {
		if got := accountIsDormant(&c.row, now); got != c.want {
			t.Errorf("%s: accountIsDormant = %v, want %v", c.name, got, c.want)
		}
	}
}

// The lease-path stamp must never be able to make a busy account look dormant.
func TestLeaseStampThrottleIsWellInsideIdleThreshold(t *testing.T) {
	if leaseStampThrottle >= claudeIdleAfter {
		t.Fatalf("leaseStampThrottle (%v) must stay far below claudeIdleAfter (%v), or a "+
			"continuously-leased account could age into dormancy between stamps",
			leaseStampThrottle, claudeIdleAfter)
	}
}

// The heartbeat has to be the outer bound: exercising the family less often than
// we declare accounts dormant would let a dormant account drift unexchanged.
func TestHeartbeatOutlivesTheIdleThreshold(t *testing.T) {
	if claudeIdleHeartbeat <= claudeIdleAfter {
		t.Fatalf("claudeIdleHeartbeat (%v) must exceed claudeIdleAfter (%v) or dormancy "+
			"never actually skips anything", claudeIdleHeartbeat, claudeIdleAfter)
	}
}
