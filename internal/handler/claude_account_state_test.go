package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// The drain pair was declared on quotaResult and never assigned, so /code could
// not see a paused account: the button never flipped to "resume", and a second
// press hit the idempotent no-op (which logs nothing), making a working write
// look like a dead control. Pin the mapping.
func TestAccountStateReportsAnOperatorPause(t *testing.T) {
	since := time.Date(2026, 8, 25, 0, 10, 0, 0, time.UTC)
	var res quotaResult
	applyAccountState(&res, models.ClaudeQuotaToken{
		Email: "a@x", DrainingSince: &since, DrainReason: "rotating out",
	}, time.Now())

	if res.DrainingSince == nil || !res.DrainingSince.Equal(since) {
		t.Fatalf("draining_since not reported (%v) — the dashboard cannot see the pause", res.DrainingSince)
	}
	if res.DrainReason != "rotating out" {
		t.Fatalf("drain_reason = %q, want the operator's reason", res.DrainReason)
	}
}

// A drain has no expiry, unlike a bench: it must still report long after it was
// set, or the pill would vanish while the account is still paused.
func TestAccountStatePauseDoesNotExpire(t *testing.T) {
	old := time.Now().Add(-30 * 24 * time.Hour)
	var res quotaResult
	applyAccountState(&res, models.ClaudeQuotaToken{Email: "a@x", DrainingSince: &old}, time.Now())
	if res.DrainingSince == nil {
		t.Fatal("a month-old pause stopped being reported — a drain clears only on resume")
	}
}

func TestAccountStateOmitsAPauseThatIsNotSet(t *testing.T) {
	var res quotaResult
	applyAccountState(&res, models.ClaudeQuotaToken{Email: "a@x"}, time.Now())
	if res.DrainingSince != nil || res.DrainReason != "" {
		t.Fatalf("reported a pause on an un-paused account: %+v", res)
	}
}

// Bench keeps its expiry semantics — the two states are independent and must not
// be collapsed into one another.
func TestAccountStateBenchStillExpires(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	var expired, live quotaResult
	applyAccountState(&expired, models.ClaudeQuotaToken{Email: "a@x", BenchUntil: &past}, time.Now())
	applyAccountState(&live, models.ClaudeQuotaToken{Email: "a@x", BenchUntil: &future}, time.Now())
	if expired.BenchedUntil != nil {
		t.Fatal("an expired bench was still reported")
	}
	if live.BenchedUntil == nil {
		t.Fatal("a live bench was not reported")
	}
}
