package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// The quota probe is a synthetic /v1/messages call made with a pooled account's
// own OAuth credential, from the cluster rather than the account's field relay
// and without any of the Claude Code client identity the account's real traffic
// carries. On a busy account it hides in real traffic; on an idle, exhausted one
// it is the only thing the credential does at all.
//
// These pin the rule that removes it: a snapshot showing an exhausted window is
// still true until that window resets, because utilization only rises and any
// traffic that could raise it would have refreshed the snapshot via claude-proxy.
func TestExhaustedSnapshotStillTrue(t *testing.T) {
	now := time.Date(2026, 8, 18, 14, 0, 0, 0, time.UTC)
	future := now.Add(3 * 24 * time.Hour)
	past := now.Add(-time.Minute)

	cases := []struct {
		name string
		snap *models.ClaudeQuotaSnapshot
		want bool
		why  string
	}{
		{
			name: "nil snapshot is not authoritative",
			snap: nil,
			want: false,
			why:  "nothing is known about the account, so a probe is exactly what is warranted",
		},
		{
			name: "ac9 shape: 7d spent, reset days away",
			snap: &models.ClaudeQuotaSnapshot{SevenDayPct: 98, SevenDayReset: future},
			want: true,
			why:  "this is the row ac9@yao.lu was re-probed ~90 times to re-read before it was revoked",
		},
		{
			name: "5h spent, reset ahead",
			snap: &models.ClaudeQuotaSnapshot{FiveHourPct: 99.5, FiveHourReset: future},
			want: true,
		},
		{
			name: "spent but the window already rolled",
			snap: &models.ClaudeQuotaSnapshot{SevenDayPct: 100, SevenDayReset: past},
			want: false,
			why:  "the reset passed, so the old number says nothing — go find out what is true now",
		},
		{
			name: "spent but no reset recorded",
			snap: &models.ClaudeQuotaSnapshot{SevenDayPct: 100},
			want: false,
			why:  "with no reset instant there is no bound on the suppression; never suppress blind",
		},
		{
			name: "healthy account is always probeable",
			snap: &models.ClaudeQuotaSnapshot{FiveHourPct: 10, SevenDayPct: 40, FiveHourReset: future, SevenDayReset: future},
			want: false,
		},
		{
			name: "just under the lease exclusion is not exhausted",
			snap: &models.ClaudeQuotaSnapshot{SevenDayPct: leaseExhaustPct - 0.1, SevenDayReset: future},
			want: false,
			why:  "the account can still be leased, so its quota must stay fresh for routing",
		},
		{
			name: "idle-but-warning ac9 (7d=98 exactly) is at the boundary and suppressed",
			snap: &models.ClaudeQuotaSnapshot{FiveHourPct: 0, SevenDayPct: leaseExhaustPct, SevenDayReset: future},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exhaustedSnapshotStillTrue(tc.snap, now); got != tc.want {
				t.Fatalf("exhaustedSnapshotStillTrue = %v, want %v — %s", got, tc.want, tc.why)
			}
		})
	}
}

// The suppression must never outlast the window it is based on: one second past
// the reset the account becomes probeable again, with no other state involved.
func TestExhaustedSuppressionEndsExactlyAtReset(t *testing.T) {
	reset := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	snap := &models.ClaudeQuotaSnapshot{SevenDayPct: 98, SevenDayReset: reset}

	if !exhaustedSnapshotStillTrue(snap, reset.Add(-time.Second)) {
		t.Fatal("must still be suppressed one second before the reset")
	}
	if exhaustedSnapshotStillTrue(snap, reset) {
		t.Fatal("must be probeable at the reset instant")
	}
	if exhaustedSnapshotStillTrue(snap, reset.Add(time.Second)) {
		t.Fatal("must be probeable after the reset")
	}
}
