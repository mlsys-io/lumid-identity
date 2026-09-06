package handler

// Conservative fill order for a SINGLE-FIELD-BOX pool is use-it-or-lose-it:
// nearest 7d reset first. Mixed-box pools keep the fixed add-order, because
// reordering there moves egress between boxes as reset times drift.

import (
	"testing"
	"time"

	"lumid_identity/models"
)

func tok(email, label string, sortOrder int) models.ClaudeQuotaToken {
	return models.ClaudeQuotaToken{Email: email, Label: label, PoolSortOrder: sortOrder}
}

func TestExpiringFirstRequiresOneSharedNonEmptyLabel(t *testing.T) {
	cases := []struct {
		name  string
		rows  []models.ClaudeQuotaToken
		wants bool
	}{
		{"mixed boxes keep the fixed order", []models.ClaudeQuotaToken{
			tok("a@x", "nyc", 0), tok("b@x", "denmark", 1)}, false},
		// The reading that would silently be wrong: an unlabeled account is
		// adopted onto a box by account hash, so all-empty is many boxes.
		{"all-empty labels are NOT one box", []models.ClaudeQuotaToken{
			tok("a@x", "", 0), tok("b@x", "", 1)}, false},
		{"one account has nothing to reorder", []models.ClaudeQuotaToken{
			tok("a@x", "nightly-dk", 0)}, false},
		{"a shared non-empty label qualifies", []models.ClaudeQuotaToken{
			tok("a@x", "nightly-dk", 0), tok("b@x", "nightly-dk", 1)}, true},
		{"whitespace does not create a mismatch", []models.ClaudeQuotaToken{
			tok("a@x", "nightly-dk", 0), tok("b@x", " nightly-dk ", 1)}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := setupClaudePoolTestDB(t)
			_ = db
			_, ok := expiringFirstOrder(tc.rows)
			if ok != tc.wants {
				t.Errorf("expiringFirstOrder applied=%v, want %v", ok, tc.wants)
			}
		})
	}
}

func TestExpiringFirstPutsTheNearestSevenDayResetFirst(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	now := time.Now().UTC()
	// b's weekly budget expires SOONER, but it is second in add-order — the
	// exact case the fixed order gets wrong and wastes.
	for _, s := range []struct {
		email string
		d7    time.Duration
	}{{"cexp-a@x", 60 * time.Hour}, {"cexp-b@x", 12 * time.Hour}} {
		db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, s.email)
		db.Exec(`INSERT INTO claude_quota_snapshots (email, ts, five_hour_pct, seven_day_pct, five_hour_reset, seven_day_reset)
		         VALUES (?, ?, 0, 0, ?, ?)`, s.email, now, now.Add(time.Hour), now.Add(s.d7))
		email := s.email
		t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, email) })
	}
	got, ok := expiringFirstOrder([]models.ClaudeQuotaToken{
		tok("cexp-a@x", "nightly-dk", 0), tok("cexp-b@x", "nightly-dk", 1)})
	if !ok {
		t.Fatal("rule did not apply to a shared-label pool")
	}
	if got[0] != "cexp-b@x" {
		t.Fatalf("order = %v, want the nearest-expiring account (cexp-b@x) first", got)
	}
}

// An unknown reset is not evidence of an imminent one — matching the
// distributed sortKey's "no snapshot -> probe last".
func TestExpiringFirstSortsUnknownResetsLast(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	now := time.Now().UTC()
	db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, "cexp-known@x")
	db.Exec(`INSERT INTO claude_quota_snapshots (email, ts, five_hour_pct, seven_day_pct, five_hour_reset, seven_day_reset)
	         VALUES (?, ?, 0, 0, ?, ?)`, "cexp-known@x", now, now.Add(time.Hour), now.Add(48*time.Hour))
	t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, "cexp-known@x") })
	db.Exec(`DELETE FROM claude_quota_snapshots WHERE email = ?`, "cexp-unknown@x")

	got, ok := expiringFirstOrder([]models.ClaudeQuotaToken{
		tok("cexp-unknown@x", "nightly-dk", 0), tok("cexp-known@x", "nightly-dk", 1)})
	if !ok {
		t.Fatal("rule did not apply")
	}
	if got[0] != "cexp-known@x" {
		t.Fatalf("order = %v, want the account WITH a snapshot first", got)
	}
}
