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

// THE TEST THAT ACTUALLY PROVES THE FIX. Everything above is pure-value and
// would pass even with the old bare time.Time, because the failure lives in the
// GORM/MySQL layer: the zero value renders as '0000-00-00', which production
// sql_mode (NO_ZERO_DATE + STRICT_TRANS_TABLES) rejects. Only a real INSERT
// reproduces it, and only a real INSERT shows NULL now succeeds.
func TestSnapshotWithUnknownResetPersistsThroughGORM(t *testing.T) {
	db := setupClaudePoolTestDB(t)

	snap := models.ClaudeQuotaSnapshot{
		Email:       "csnap-null@x",
		FiveHourPct: 0,
		SevenDayPct: 83,
		Severity:    "normal",
		// Exactly what fetchClaudeUsage leaves when the 5h headers are absent
		// and the 7d ones are present.
		FiveHourReset: models.ResetPtr(time.Time{}),
		SevenDayReset: models.ResetPtr(time.Now().Add(48 * time.Hour)),
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, "csnap-null@x") })

	if err := db.Create(&snap).Error; err != nil {
		t.Fatalf("insert with an unknown reset failed: %v — 'we don't know when it "+
			"resets' must persist as NULL, not take the whole row down", err)
	}

	var back models.ClaudeQuotaSnapshot
	if err := db.Where("email = ?", "csnap-null@x").Order("ts DESC").First(&back).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !models.ResetAt(back.FiveHourReset).IsZero() {
		t.Errorf("five_hour_reset = %v, want NULL/zero", models.ResetAt(back.FiveHourReset))
	}
	if models.ResetAt(back.SevenDayReset).IsZero() {
		t.Error("seven_day_reset lost — the known half must survive alongside the unknown half")
	}
}

// Out-of-range instants must not reach the INSERT either; they fail the same
// way '0000-00-00' did (year is not in the range [1, 9999]).
func TestResetPtrDropsUnstorableInstants(t *testing.T) {
	for _, in := range []time.Time{
		time.Time{},
		time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("x", 8*3600)),
		time.Date(99, 12, 31, 0, 0, 0, 0, time.UTC),
		time.Date(57802, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got := models.ResetPtr(in); got != nil {
			t.Errorf("ResetPtr(%v) = %v, want nil — MySQL DATETIME cannot hold it", in, got)
		}
	}
	ok := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	if models.ResetPtr(ok) == nil {
		t.Error("a valid future reset was dropped")
	}
}
