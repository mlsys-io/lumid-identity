package handler

import (
	"encoding/json"
	"testing"
	"time"

	"lumid_identity/models"
)

func sub(t *testing.T, user, outcome, reason string, ms int, day int) models.AuditLog {
	t.Helper()
	d := map[string]any{"outcome": outcome}
	if reason != "" {
		d["reason"] = reason
	}
	detail := ""
	if outcome != "" {
		j, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		detail = string(j)
	}
	return models.AuditLog{
		UserID:     user,
		Event:      "lqt:strategy.submit",
		Detail:     detail,
		DurationMs: ms,
		CreatedAt:  time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC).AddDate(0, 0, day),
	}
}

// The reject → fix → resubmit curve is the whole point of the funnel, so the
// attempt accounting gets a test with a worked example rather than a smoke check.
func TestSubmissionFunnelAttemptsToFirstDeploy(t *testing.T) {
	rows := []models.AuditLog{
		// alice: rejected, rejected, deployed  → 3 attempts
		sub(t, "alice", "rejected", "expected `when` to start a guard, found identifier `version`", 12, 0),
		sub(t, "alice", "rejected", "expected `when` to start a guard, found identifier `param`", 15, 0),
		sub(t, "alice", "deployed", "", 40, 0),
		// alice submits again after deploying — must NOT change her first-deploy count
		sub(t, "alice", "deployed", "", 33, 1),
		// bob: deployed first try → 1 attempt
		sub(t, "bob", "deployed", "", 22, 0),
		// carol: only ever rejected → never deployed
		sub(t, "carol", "rejected", "expected `when` to start a guard, found identifier `on_signal`", 11, 0),
		sub(t, "carol", "no_verdict", "", 45000, 1),
	}

	f, perDay := computeSubmissionFunnel(rows)

	if f.Total != 7 {
		t.Errorf("Total = %d, want 7", f.Total)
	}
	if f.Users != 3 {
		t.Errorf("Users = %d, want 3", f.Users)
	}
	if f.Attributed.Deployed != 3 {
		t.Errorf("Deployed = %d, want 3", f.Attributed.Deployed)
	}
	if f.Attributed.Rejected != 3 {
		t.Errorf("Rejected = %d, want 3", f.Attributed.Rejected)
	}
	if f.Attributed.NoVerdict != 1 {
		t.Errorf("NoVerdict = %d, want 1", f.Attributed.NoVerdict)
	}
	if f.UsersNeverDeployed != 1 {
		t.Errorf("UsersNeverDeployed = %d, want 1 (carol)", f.UsersNeverDeployed)
	}

	got := map[string]int{}
	for _, c := range f.AttemptsToFirstDeploy {
		got[c.Key] = c.Count
	}
	if got["3"] != 1 {
		t.Errorf("attempts=3 bucket = %d, want 1 (alice)", got["3"])
	}
	if got["1"] != 1 {
		t.Errorf("attempts=1 bucket = %d, want 1 (bob)", got["1"])
	}
	if n := len(f.AttemptsToFirstDeploy); n != 2 {
		t.Errorf("attempts buckets = %d, want 2 (carol never deployed)", n)
	}

	// Distinct compiler messages must stay distinct buckets.
	if len(f.RejectReasons) != 3 {
		t.Errorf("reject reasons = %d, want 3 distinct", len(f.RejectReasons))
	}

	if perDay["2026-08-30"] != 5 || perDay["2026-08-31"] != 2 {
		t.Errorf("perDay = %v, want 5 then 2", perDay)
	}
}

// The 70 rows that predate verdict recording must be counted as unknown, never
// folded into an outcome — that inference is exactly what the change exists to
// stop us doing.
func TestSubmissionFunnelLegacyRowsAreUnknownNotInferred(t *testing.T) {
	rows := []models.AuditLog{
		sub(t, "dana", "", "", 0, 0),
		sub(t, "dana", "", "", 0, 0),
		sub(t, "erin", "deployed", "", 30, 0),
	}
	f, _ := computeSubmissionFunnel(rows)

	if f.UnknownOutcome != 2 {
		t.Errorf("UnknownOutcome = %d, want 2", f.UnknownOutcome)
	}
	if f.Attributed.Deployed != 1 {
		t.Errorf("Deployed = %d, want 1 — legacy rows must not be counted as deploys", f.Attributed.Deployed)
	}
	if f.UsersNeverDeployed != 1 {
		t.Errorf("UsersNeverDeployed = %d, want 1 (dana)", f.UsersNeverDeployed)
	}
	// A user with only unknown rows must not land in the attempts histogram at
	// all; a "0 attempts" bucket would read as an instant success.
	for _, c := range f.AttemptsToFirstDeploy {
		if c.Key == "0" {
			t.Errorf("unknown-only user produced a 0-attempt bucket: %+v", f.AttemptsToFirstDeploy)
		}
	}
}

func TestFirstLineGroupsDiagnostics(t *testing.T) {
	in := "expected `when` to start a guard, found identifier `version`\n  --> line 3:5\n   |"
	if got := firstLine(in); got != "expected `when` to start a guard, found identifier `version`" {
		t.Errorf("firstLine = %q", got)
	}
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	if got := firstLine(string(long)); len([]rune(got)) != 161 {
		t.Errorf("firstLine long = %d runes, want 161 (160 + ellipsis)", len([]rune(got)))
	}
}

func TestPctl(t *testing.T) {
	if got := pctl(nil, 0.5); got != 0 {
		t.Errorf("pctl(nil) = %d, want 0", got)
	}
	s := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if got := pctl(s, 0.50); got != 5 {
		t.Errorf("p50 = %d, want 5", got)
	}
	if got := pctl(s, 0.95); got != 10 {
		t.Errorf("p95 = %d, want 10", got)
	}
}
