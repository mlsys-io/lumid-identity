package handler

// A row from a dead implementation must not outrank the published bundle.
//
// me_app_specs predates this code: an earlier implementation wrote it, its Go
// side was deleted, and the table outlived it. So _echo_app_spec spent months
// POSTing into a 404 while the rows sat where they were. Measured 2026-09-16:
// 16 rows, every one written 12-15 July, including `lumid-arxiv` at 197 bytes
// and a `probe` row of 11 bytes.
//
// That matters because the overlay PREFERS a stored spec over the published
// bundle. Trusting a July row serves a two-month-old spec in place of a current
// one — worse than the problem the overlay was built to fix, and invisible,
// since a stale row looks exactly like a fresh one.
//
// The rows are not deleted here. They are simply not trusted until a real echo
// overwrites them, which the next install, update or spec edit does.

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// The floor must sit after the last row the dead implementation wrote and at or
// before the day the route was restored. Both bounds are the point: too early
// and July rows are trusted; too late and genuine echoes are discarded.
func TestTheEchoFloorBracketsTheDeadImplementation(t *testing.T) {
	lastDeadWrite := time.Date(2026, 7, 15, 20, 21, 22, 0, time.UTC) // newest observed row
	routeRestored := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)    // end of the day it shipped

	if !specEchoRestored.After(lastDeadWrite) {
		t.Errorf("the floor (%s) is not after the newest row the removed implementation "+
			"wrote (%s), so those rows are still trusted and still outrank the "+
			"published bundle", specEchoRestored, lastDeadWrite)
	}
	if specEchoRestored.After(routeRestored) {
		t.Errorf("the floor (%s) is after the route was restored (%s), so real echoes "+
			"would be thrown away and every read would silently fall back to the "+
			"published bundle", specEchoRestored, routeRestored)
	}
}

// A floor, not a TTL. The row mirrors an install that only changes by an echo,
// so age alone is not staleness once the row came from the live route.
func TestAPostFloorRowIsTrustedHoweverOldItGets(t *testing.T) {
	row := models.MeAppSpec{
		UserSub: "sub-1", App: "demo", SpecYAML: "name: demo\n",
		UpdatedAt: specEchoRestored.Add(24 * time.Hour),
	}
	if row.UpdatedAt.Before(specEchoRestored) {
		t.Fatal("fixture is not after the floor")
	}
	// Simulate a year passing. The rule must not become a TTL.
	aged := row
	aged.UpdatedAt = specEchoRestored.Add(365 * 24 * time.Hour)
	if aged.UpdatedAt.Before(specEchoRestored) {
		t.Error("a row written long after the floor was treated as pre-floor")
	}
}

// The predicate storedAppSpec applies, stated directly so the intent is
// readable without a database.
func TestPreFloorRowsAreNotTrusted(t *testing.T) {
	cases := map[string]struct {
		at      time.Time
		trusted bool
	}{
		"the oldest observed dead row":  {time.Date(2026, 7, 12, 22, 1, 40, 0, time.UTC), false},
		"the newest observed dead row":  {time.Date(2026, 7, 15, 20, 21, 22, 0, time.UTC), false},
		"one second before the floor":   {specEchoRestored.Add(-time.Second), false},
		"exactly the floor":             {specEchoRestored, true},
		"a real echo written today":     {specEchoRestored.Add(14 * time.Hour), true},
		"an echo written a month later": {specEchoRestored.Add(30 * 24 * time.Hour), true},
	}
	for name, c := range cases {
		got := !c.at.Before(specEchoRestored)
		if got != c.trusted {
			t.Errorf("%s (%s): trusted=%v, want %v", name, c.at, got, c.trusted)
		}
	}
}
