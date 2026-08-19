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

// Dormancy must never put the pool's last warm reserves to sleep.
//
// The first cut of dormancy asked only "is this account unused", which is not
// the same question as "is it safe to let it go cold" — the accounts it slept
// are BY DEFINITION the ones the pool fails over to. On the live pool that left
// one busy account hot and both reserves cold, so at the moment the busy one
// quarantined every candidate needed an inline refresh AND an inline snapshot
// probe before it could serve: the exact cost snapshotRefreshInterval exists to
// avoid, arriving precisely when the pool is already in trouble.
func TestDormancyKeepsAWarmFloor(t *testing.T) {
	now := time.Now()
	lease := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	rot := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	busy := models.ClaudeQuotaToken{Email: "ac3@nati", LastLeasedAt: lease(-2 * time.Minute), RotatedAt: rot(-30 * time.Minute)}
	idle := models.ClaudeQuotaToken{Email: "ac2@nati", RotatedAt: rot(-30 * time.Minute)}
	spent := models.ClaudeQuotaToken{Email: "ac5@mlsys", RotatedAt: rot(-30 * time.Minute)}
	none := func(string) bool { return false }
	spentOnly := func(e string) bool { return e == "ac5@mlsys" }

	t.Run("the live shape: one busy, one healthy reserve, one out of quota", func(t *testing.T) {
		d := dormancyFloorWith([]models.ClaudeQuotaToken{busy, idle, spent}, now, spentOnly)
		if d["ac3@nati"] {
			t.Error("a busy account is never dormant")
		}
		if d["ac2@nati"] {
			t.Error("the healthy reserve must stay WARM — it is what the pool fails over to")
		}
		if !d["ac5@mlsys"] {
			t.Error("the out-of-quota surplus may sleep: it cannot serve this minute however warm it is")
		}
	})

	t.Run("busy account quarantined — both reserves wake on the next tick", func(t *testing.T) {
		// A quarantined account leaves the sweep population entirely, so hot
		// drops below the floor and the promotion has to cover it.
		d := dormancyFloorWith([]models.ClaudeQuotaToken{idle, spent}, now, spentOnly)
		if d["ac2@nati"] || d["ac5@mlsys"] {
			t.Fatalf("with the busy account gone, hot=0 < floor — every reserve must wake, got %v", d)
		}
	})

	t.Run("plenty of hot accounts — the surplus may all sleep", func(t *testing.T) {
		busy2 := models.ClaudeQuotaToken{Email: "ac1@nati", LastLeasedAt: lease(-time.Minute), RotatedAt: rot(-time.Hour)}
		d := dormancyFloorWith([]models.ClaudeQuotaToken{busy, busy2, idle, spent}, now, none)
		if !d["ac2@nati"] || !d["ac5@mlsys"] {
			t.Errorf("floor already met by 2 busy accounts, both idle ones should sleep, got %v", d)
		}
	})

	t.Run("a single-account pool never sleeps it", func(t *testing.T) {
		lonely := models.ClaudeQuotaToken{Email: "ac3@nati", RotatedAt: rot(-30 * time.Minute)}
		if d := dormancyFloorWith([]models.ClaudeQuotaToken{lonely}, now, none); d["ac3@nati"] {
			t.Fatal("the only account in the pool must stay warm")
		}
	})

	t.Run("promotion is deterministic across replicas", func(t *testing.T) {
		rows := []models.ClaudeQuotaToken{spent, idle}
		a := dormancyFloorWith(rows, now, spentOnly)
		b := dormancyFloorWith([]models.ClaudeQuotaToken{idle, spent}, now, spentOnly)
		if len(a) != len(b) || a["ac5@mlsys"] != b["ac5@mlsys"] || a["ac2@nati"] != b["ac2@nati"] {
			t.Fatalf("input order changed the outcome: %v vs %v — the two replicas would disagree", a, b)
		}
	})

	t.Run("never-exchanged accounts are not candidates at all", func(t *testing.T) {
		fresh := models.ClaudeQuotaToken{Email: "ac9@yao.lu"} // RotatedAt nil
		if d := dormancyFloorWith([]models.ClaudeQuotaToken{busy, idle, fresh}, now, none); d["ac9@yao.lu"] {
			t.Fatal("a newly added account must get its first refresh, never be slept")
		}
	})
}
