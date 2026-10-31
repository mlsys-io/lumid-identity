package handler

// A snapshot whose probe response carries no reset header must still be
// storable.
//
// ClaudeQuotaSnapshot.FiveHourReset / SevenDayReset were bare time.Time. When
// Anthropic omitted anthropic-ratelimit-unified-{5h,7d}-reset (it does — 429s
// and some 200s carry only the utilization headers), the field stayed at the Go
// zero value and GORM wrote '0000-00-00' into a DATETIME. MySQL runs with
// NO_ZERO_DATE + STRICT_TRANS_TABLES, so it rejected the INSERT outright:
//
//	Error 1292 (22007): Incorrect datetime value: '0000-00-00'
//	  for column 'five_hour_reset' at row 1        (admin_claude_quota.go:793)
//
// The failure is worse than a missing column: the whole row is lost, so the
// quota dashboard keeps serving a stale snapshot and nothing records that the
// probe ever ran. Observed 2026-10-31: ylu@yao.lu snapshots unpicged for 24h+
// with 19 consecutive "save snapshot" failures.
//
// The fix is that "unknown reset" has a representation of its own — NULL — not
// the zero time. These tests pin both directions of that conversion plus the
// nil-safety of every read site.

import (
	"testing"
	"time"

	"lumid_identity/models"
)

func TestResetPtr_ZeroBecomesNil(t *testing.T) {
	if got := models.ResetPtr(time.Time{}); got != nil {
		t.Fatalf("ResetPtr(zero) = %v, want nil — a zero reset must persist as NULL, "+
			"not fall through to '0000-00-00'", got)
	}
	if got := models.ResetAt(nil); !got.IsZero() {
		t.Fatalf("ResetAt(nil) = %v, want zero time", got)
	}
}

func TestResetPtr_RoundTrip(t *testing.T) {
	at := time.Unix(1761900000, 0).UTC()
	p := models.ResetPtr(at)
	if p == nil {
		t.Fatal("ResetPtr(dropped a real reset")
	}
	if !models.ResetAt(p).Equal(at) {
		t.Fatalf("round trip = %v, want %v", models.ResetAt(p), at)
	}
}

// The construction path that used to crash: utilization headers present, reset
// headers absent. Both durations must survive as nil rather than zero values.
func TestSnapshotWithoutResetHeadersIsStorable(t *testing.T) {
	snap := &models.ClaudeQuotaSnapshot{FiveHourPct: 42, SevenDayPct: 12}
	// Exactly what fetchClaudeUsage leaves behind when ParseInt fails.
	snap.FiveHourReset = models.ResetPtr(time.Time{})
	snap.SevenDayReset = models.ResetPtr(time.Time{})

	if snap.FiveHourReset != nil || snap.SevenDayReset != nil {
		t.Fatalf("unknown resets became %v/%v, want nil", snap.FiveHourReset, snap.SevenDayReset)
	}
}

// Read sites must not dereference nil. These are the three shapes present in
// the codebase: a nil-safe comparison, a fault-tolerance check, and the
// "window has rolled" predicate that decides whether a cached snapshot is
// still usable.
func TestReadSitesTolerateNilReset(t *testing.T) {
	now := time.Now()

	// exhaustedSnapshotStillTrue: an unknown reset can never be "still spent".
	if exhaustedSnapshotStillTrue(&models.ClaudeQuotaSnapshot{SevenDayPct: 100}, now) {
		t.Error("unknown reset treated as unexpired exhaustion")
	}

	// resetPassed (both call sites use the same expression).
	check := func(s *models.ClaudeQuotaSnapshot) bool {
		r5, r7 := models.ResetAt(s.FiveHourReset), models.ResetAt(s.SevenDayReset)
		return (!r5.IsZero() && now.After(r5)) || (!r7.IsZero() && now.After(r7))
	}
	if check(&models.ClaudeQuotaSnapshot{}) {
		t.Error("nil resets reported as passed")
	}
	if !check(&models.ClaudeQuotaSnapshot{SevenDayReset: models.ResetPtr(now.Add(-time.Minute))}) {
		t.Error("past reset not reported as passed")
	}

	// Formatting a nil reset must not panic (the limits[] build).
	_ = models.ResetAt(nil).Format(time.RFC3339)
}
