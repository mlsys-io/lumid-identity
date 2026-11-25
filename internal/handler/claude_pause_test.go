package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"lumid_identity/models"
)

func tp(t time.Time) *time.Time { return &t }

// The 2026-11-25 shape: pausing ac5 in a pool of {ac4 at 98% on 7d, ac5, ylu}.
// The old guard counted ac4 as alive. Only ylu can take users, so exactly one
// sibling is usable, which is the "warn" case, not "fine".
func TestPauseSiblingsCountsAnExhaustedSiblingAsUnusable(t *testing.T) {
	now := time.Now()
	rows := []models.ClaudeQuotaToken{
		{Email: "ac4"}, {Email: "ac5"}, {Email: "ylu"},
	}
	q := map[string]accountQuota{
		"ac4": {pct5: 0, pct7: 98, known: true},
		"ylu": {pct5: 0, pct7: 1, known: true},
	}
	s := classifyPauseSiblings("ac5", rows, q, now)
	if len(s.Usable) != 1 || s.Usable[0] != "ylu" {
		t.Fatalf("usable = %v, want [ylu]", s.Usable)
	}
	if len(s.Exhausted) != 1 || s.Exhausted[0] != "ac4" {
		t.Fatalf("exhausted = %v, want [ac4]", s.Exhausted)
	}
}

func TestPauseSiblingsSkipsPausedBenchedRevokedAndSelf(t *testing.T) {
	now := time.Now()
	rows := []models.ClaudeQuotaToken{
		{Email: "self"},
		{Email: "paused", DrainingSince: tp(now.Add(-time.Hour))},
		{Email: "benched", BenchUntil: tp(now.Add(time.Hour))},
		{Email: "bench-over", BenchUntil: tp(now.Add(-time.Hour))},
		{Email: "revoked", RevokedAt: tp(now)},
		{Email: "unknown"}, // no snapshot: servable, as in accountQuotas
	}
	s := classifyPauseSiblings("self", rows, map[string]accountQuota{}, now)
	if strings.Join(s.Usable, ",") != "bench-over,unknown" {
		t.Fatalf("usable = %v, want [bench-over unknown]", s.Usable)
	}
	if strings.Join(s.Paused, ",") != "paused" || strings.Join(s.Benched, ",") != "benched" {
		t.Fatalf("paused=%v benched=%v", s.Paused, s.Benched)
	}
	d := s.describe()
	for _, want := range []string{"usable=2", "paused=paused", "benched=benched"} {
		if !strings.Contains(d, want) {
			t.Fatalf("describe() = %q, missing %q", d, want)
		}
	}
}

func TestPauseEnforcedFollowsTheGrace(t *testing.T) {
	now := time.Now()
	inGrace := models.ClaudeQuotaToken{DrainingSince: tp(now.Add(-drainPinGrace / 2))}
	past := models.ClaudeQuotaToken{DrainingSince: tp(now.Add(-drainPinGrace - time.Second))}
	if pauseEnforced(models.ClaudeQuotaToken{}, now) {
		t.Fatal("an unpaused account reported enforced")
	}
	if drainPinGrace > 0 && pauseEnforced(inGrace, now) {
		t.Fatal("enforced inside the grace: live sessions would be cut off early")
	}
	if !pauseEnforced(past, now) {
		t.Fatal("not enforced after the grace: the proxy would never evict its cached leases")
	}
}

// A lease on a paused account must not outlive the grace (the 30m cache was
// the second half of the 2026-11-25 delay), and a backstop lease must be short.
func TestPauseLeaseTTL(t *testing.T) {
	now := time.Now()
	if got := pauseLeaseTTL(models.ClaudeQuotaToken{}, now, false); got != 0 {
		t.Fatalf("unpaused ttl = %d, want 0 (no cap)", got)
	}
	since := now.Add(-drainPinGrace + 90*time.Second)
	got := pauseLeaseTTL(models.ClaudeQuotaToken{DrainingSince: &since}, now, false)
	if got < 85 || got > 90 {
		t.Fatalf("in-grace ttl = %d, want ~90s (time left in the grace)", got)
	}
	if got := pauseLeaseTTL(models.ClaudeQuotaToken{DrainingSince: &since}, now, true); got != int(backstopLeaseTTL/time.Second) {
		t.Fatalf("backstop ttl = %d, want %v", got, backstopLeaseTTL)
	}
	edge := now.Add(-drainPinGrace + time.Second)
	if got := pauseLeaseTTL(models.ClaudeQuotaToken{DrainingSince: &edge}, now, false); got < 5 {
		t.Fatalf("ttl at the grace edge = %d, want >= 5s floor", got)
	}
}

func TestDrainOverrideShownOnlyForTheCurrentPause(t *testing.T) {
	now := time.Now()
	since := now.Add(-10 * time.Minute)
	if drainOverrideShown(models.ClaudeQuotaToken{DrainOverriddenAt: tp(now)}) != nil {
		t.Fatal("override shown for an unpaused account")
	}
	if drainOverrideShown(models.ClaudeQuotaToken{DrainingSince: &since, DrainOverriddenAt: tp(since.Add(-time.Minute))}) != nil {
		t.Fatal("an override from before this pause leaked onto it")
	}
	if drainOverrideShown(models.ClaudeQuotaToken{DrainingSince: &since, DrainOverriddenAt: tp(now)}) == nil {
		t.Fatal("a current override was hidden — /code would show the pause as holding")
	}
}

func TestAccountStateReportsPauseEnforcementAndOverride(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	over := time.Now()
	var res quotaResult
	applyAccountState(&res, models.ClaudeQuotaToken{Email: "a@x", DrainingSince: &since, DrainOverriddenAt: &over}, time.Now())
	if res.PauseEnforcedAt == nil || !res.PauseEnforcedAt.Equal(since.Add(drainPinGrace)) {
		t.Fatalf("pause_enforced_at = %v, want draining_since + grace", res.PauseEnforcedAt)
	}
	if res.DrainOverriddenAt == nil {
		t.Fatal("drain_overridden_at not reported")
	}
}

// Integration (TEST_MYSQL_DSN): the 2026-11-25 shape through the real
// endpoint. Two siblings exist, but one is exhausted. The old guard counted
// both and accepted the pause. Now it must:
//   - refuse when the only sibling is exhausted;
//   - accept with a warning when exactly one usable sibling is left.
func TestManagerPauseGuardIgnoresAnExhaustedSibling(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-pause-guard"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'G', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "pguard")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, pool, sub)

	target, spent, spare := "cptest-pg-target@acct", "cptest-pg-spent@acct", "cptest-pg-spare@acct"
	for _, e := range []string{target, spent} {
		db.Exec(`INSERT IGNORE INTO claude_quota_tokens (email, value_encrypted, pool_id) VALUES (?, 'x', ?)`, e, pool)
	}
	db.Exec(`INSERT INTO claude_quota_snapshots (email, ts, five_hour_pct, seven_day_pct, severity) VALUES (?, NOW(3), 0, 98, 'warning')`, spent)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM claude_quota_tokens WHERE email IN ?`, []string{target, spent, spare})
		db.Exec(`DELETE FROM claude_quota_snapshots WHERE email IN ?`, []string{target, spent, spare})
	})

	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+target+"/drain",
		`{"draining":true}`, managerPAT(t, sub))
	if w.Code != http.StatusConflict {
		t.Fatalf("pause with only an exhausted sibling returned %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "exhausted="+spent) {
		t.Fatalf("refusal does not name the exhausted sibling: %s", w.Body.String())
	}

	db.Exec(`INSERT IGNORE INTO claude_quota_tokens (email, value_encrypted, pool_id) VALUES (?, 'x', ?)`, spare, pool)
	w = authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+target+"/drain",
		`{"draining":true}`, managerPAT(t, sub))
	if w.Code != http.StatusOK {
		t.Fatalf("pause with one usable sibling returned %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "only one other usable account") {
		t.Fatalf("no single-sibling warning: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"enforced_at"`) {
		t.Fatalf("no enforced_at in the response: %s", w.Body.String())
	}
}
