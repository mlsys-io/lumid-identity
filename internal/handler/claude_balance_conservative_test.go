package handler

import "testing"

func allServable(accounts []string) map[string]bool {
	m := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		m[a] = true
	}
	return m
}

// Newcomers fill the ordered accounts one at a time, respecting the ceiling,
// never spreading across accounts the way distributed mode's LPT would.
func TestConservativeAssignment_FillsInOrder(t *testing.T) {
	ordered := []string{"acct-1", "acct-2", "acct-3"}
	loads := []userLoad{{"u1", 0}, {"u2", 0}, {"u3", 0}, {"u4", 0}, {"u5", 0}}
	got := computeConservativeAssignment(loads, ordered, map[string]string{}, allServable(ordered), nil, 2)

	cnt := map[string]int{}
	for _, acct := range got {
		cnt[acct]++
	}
	if cnt["acct-1"] != 2 || cnt["acct-2"] != 2 || cnt["acct-3"] != 1 {
		t.Fatalf("fill order wrong: %v (want acct-1=2 acct-2=2 acct-3=1)", cnt)
	}
}

// The ceiling defers a newcomer to the next account but never evicts an
// already-seated incumbent — re-running with a growing newcomer set must
// never change where an existing user landed.
func TestConservativeAssignment_CeilingNeverEvictsIncumbent(t *testing.T) {
	ordered := []string{"acct-1", "acct-2"}
	cur := map[string]string{"u1": "acct-1", "u2": "acct-1"} // acct-1 already at the ceiling of 2
	loads := []userLoad{{"u1", 0}, {"u2", 0}, {"u3", 0}}     // u3 is the newcomer
	got := computeConservativeAssignment(loads, ordered, cur, allServable(ordered), nil, 2)

	if got["u1"] != "acct-1" || got["u2"] != "acct-1" {
		t.Fatalf("incumbents moved: u1=%s u2=%s, want both acct-1", got["u1"], got["u2"])
	}
	if got["u3"] != "acct-2" {
		t.Fatalf("newcomer u3=%s, want acct-2 (acct-1 is at the ceiling)", got["u3"])
	}
}

// Rollover on exhaustion: an unservable current account is not sticky —
// affected users re-place onto the next account in order, exactly like a
// newcomer would.
func TestConservativeAssignment_RollsOverOnExhaustion(t *testing.T) {
	ordered := []string{"acct-1", "acct-2"}
	cur := map[string]string{"u1": "acct-1"}
	loads := []userLoad{{"u1", 0}}
	servable := map[string]bool{"acct-1": false, "acct-2": true} // acct-1 exhausted
	got := computeConservativeAssignment(loads, ordered, cur, servable, nil, 0)

	if got["u1"] != "acct-2" {
		t.Fatalf("u1=%s, want acct-2 (acct-1 is unservable)", got["u1"])
	}
}

// Rollover on drain behaves identically to rollover on exhaustion —
// draining is a distinct signal from !servable but must have the same
// effect on conservative-mode fill order.
func TestConservativeAssignment_RollsOverOnDrain(t *testing.T) {
	ordered := []string{"acct-1", "acct-2"}
	cur := map[string]string{"u1": "acct-1"}
	loads := []userLoad{{"u1", 0}}
	servable := allServable(ordered)
	draining := map[string]bool{"acct-1": true}
	got := computeConservativeAssignment(loads, ordered, cur, servable, draining, 0)

	if got["u1"] != "acct-2" {
		t.Fatalf("u1=%s, want acct-2 (acct-1 is draining)", got["u1"])
	}
}

// Zero ceiling disables the backstop entirely: unlimited intake onto the
// current account, rolling only on health/exhaustion — never on headcount.
func TestConservativeAssignment_ZeroCeilingDisablesBackstop(t *testing.T) {
	ordered := []string{"acct-1", "acct-2"}
	var loads []userLoad
	for i := 0; i < 20; i++ {
		loads = append(loads, userLoad{UserSub: string(rune('a' + i)), Tokens: 0})
	}
	got := computeConservativeAssignment(loads, ordered, map[string]string{}, allServable(ordered), nil, 0)
	for _, acct := range got {
		if acct != "acct-1" {
			t.Fatalf("with ceiling=0 every user should land on acct-1, got one on %q", acct)
		}
	}
	if len(got) != 20 {
		t.Fatalf("placed %d/20 users, want all 20", len(got))
	}
}

// A user with no usable account at all (everything full or unservable) is
// left unplaced rather than forced somewhere — same HRW-fallback contract
// distributed mode's cap gate already has.
func TestConservativeAssignment_UnplaceableWhenPoolIsFull(t *testing.T) {
	ordered := []string{"acct-1"}
	cur := map[string]string{"u1": "acct-1"}
	loads := []userLoad{{"u1", 0}, {"u2", 0}}
	got := computeConservativeAssignment(loads, ordered, cur, allServable(ordered), nil, 1)

	if _, placed := got["u2"]; placed {
		t.Fatalf("u2 should be unplaced (acct-1 is at ceiling 1 and is the only account), got %q", got["u2"])
	}
	if got["u1"] != "acct-1" {
		t.Fatalf("incumbent u1 should keep its seat, got %q", got["u1"])
	}
}
