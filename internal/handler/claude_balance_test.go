package handler

import (
	"testing"

	"lumid_identity/models"
)

// Real weighted loads measured 2026-08-09 (sonnet-equivalent tokens, millions).
// Ordering here is deliberately NOT the raw-token ordering: eyuansu71 ran only
// 5,279 turns but almost entirely on Opus, so its quota draw (31.3M) is nearly
// double `user`'s (18.1M) despite `user` running 17,727 turns of Sonnet. That
// inversion is the whole reason loadByUser weights by model.
var observed = []userLoad{
	{"suzhengy", 36_900_000},
	{"eyuansu71", 31_300_000},
	{"admin", 19_700_000},
	{"user", 18_100_000},
	{"wuxinle2020", 7_300_000},
	{"noppanat.wad", 6_300_000},
	{"yuncongliu0703", 5_100_000},
	{"chiquanji", 4_700_000},
	{"jyshen44", 4_000_000},
	{"ylu", 2_700_000},
	{"cccx2303", 1_800_000},
	{"qiruixuan7", 1_100_000},
	{"njcuvngncjb", 0},
	{"zhurong878", 0},
	{"hayshn05", 0},
}

func totals(loads []userLoad, assign map[string]string, accounts []string) map[string]int64 {
	out := map[string]int64{}
	for _, a := range accounts {
		out[a] = 0
	}
	for _, l := range loads {
		out[assign[l.UserSub]] += l.Tokens
	}
	return out
}

// On the weighted metric the three accounts must come out close. Before the fix
// the live split was 66.0M / 46.9M / 26.1M — a 60% spread — because the balancer
// equalised raw tokens instead of quota draw.
func TestAssignmentBalancesWeightedLoad(t *testing.T) {
	accounts := []string{"i", "yao@yao.lu", "ytb"}
	got := totals(observed, computeAssignment(observed, accounts, 0), accounts)

	var lo, hi int64 = 1<<62 - 1, 0
	for _, v := range got {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	if hi == 0 {
		t.Fatal("no load assigned")
	}
	spread := float64(hi-lo) / float64(hi) * 100
	if spread > 10 {
		t.Errorf("weighted spread %.1f%% exceeds 10%% (totals %v)", spread, got)
	}
}

// The two dominant Opus users must not share an account: together they are
// 68.2M of the fleet's ~139M weekly draw, which is more than a single
// subscription's allowance. Co-locating them is what put ytb on track for ~95%.
func TestHeavyUsersAreSeparated(t *testing.T) {
	accounts := []string{"i", "yao@yao.lu", "ytb"}
	assign := computeAssignment(observed, accounts, 0)
	if a, b := assign["suzhengy"], assign["eyuansu71"]; a == b {
		t.Errorf("the two heaviest users both landed on %q", a)
	}
}

// Every user must be placed, including zero-load ones — an unassigned user has
// no home box and would fall through to whatever the lease picks.
func TestAllUsersAssigned(t *testing.T) {
	accounts := []string{"i", "yao@yao.lu", "ytb"}
	assign := computeAssignment(observed, accounts, 0)
	for _, l := range observed {
		if assign[l.UserSub] == "" {
			t.Errorf("user %q was not assigned an account", l.UserSub)
		}
	}
}

// Assignment must be identical across replicas: both proxy pods compute it
// independently, and disagreement means a user's account flaps between pods.
func TestAssignmentIsDeterministic(t *testing.T) {
	accounts := []string{"ytb", "i", "yao@yao.lu"} // deliberately unsorted
	first := computeAssignment(observed, accounts, 0)
	for i := 0; i < 8; i++ {
		again := computeAssignment(observed, accounts, 0)
		for sub, acct := range first {
			if again[sub] != acct {
				t.Fatalf("run %d moved %q: %q -> %q", i, sub, acct, again[sub])
			}
		}
	}
}

// counts is users-per-account, the quantity the cap bounds.
func counts(assign map[string]string) map[string]int {
	out := map[string]int{}
	for _, a := range assign {
		out[a]++
	}
	return out
}

// The concentration that got accounts suspended was 6-7 distinct people on one
// consumer subscription. With enough accounts to honour it, the cap must hold —
// load balancing alone does not bound this axis at all.
func TestUserCapBoundsFanOut(t *testing.T) {
	accounts := []string{"a1", "a2", "a3", "a4", "a5"}
	maxPer := effectiveUserCap(len(observed), len(accounts), 3)
	if maxPer != 3 {
		t.Fatalf("effectiveUserCap = %d, want 3 (15 users / 5 accounts is feasible at 3)", maxPer)
	}
	for acct, n := range counts(computeAssignment(observed, accounts, maxPer)) {
		if n > maxPer {
			t.Errorf("account %s homes %d users, cap is %d", acct, n, maxPer)
		}
	}
}

// The live pool: 15 users, 3 accounts, target 3. The cap is a GATE (2026-08-10):
// it must NOT widen to ceil(15/3)=5 just because the pool is undersized. The
// surplus is left unhomed and falls back to HRW at lease time.
func TestUserCapDoesNotWidenWhenPoolTooSmall(t *testing.T) {
	accounts := []string{"i", "sail@mlsys.io", "ytb"}
	maxPer := effectiveUserCap(len(observed), len(accounts), 3)
	if maxPer != 3 {
		t.Fatalf("effectiveUserCap = %d, want 3 — the cap is a gate, not a target", maxPer)
	}
	got := counts(computeAssignment(observed, accounts, maxPer))
	for acct, n := range got {
		if n > maxPer {
			t.Errorf("account %s homes %d users, gate is %d", acct, n, maxPer)
		}
	}
	total := 0
	for _, n := range got {
		total += n
	}
	if want := len(accounts) * 3; total != want {
		t.Errorf("homed %d users, want exactly %d (3 accounts x gate 3)", total, want)
	}
	if total >= len(observed) {
		t.Errorf("expected a surplus to be left unhomed, homed all %d", total)
	}
}

// The gate deliberately leaves a surplus unplaced when the pool is too small.
// An unhomed user is NOT denied access — assignedAccount returns "" and the
// lease falls through to HRW — but they lose a stable egress box, which is the
// pressure that should drive adding an account.
func TestUserCapLeavesSurplusUnplaced(t *testing.T) {
	accounts := []string{"only"}
	for _, maxPer := range []int{1, 3} {
		assign := computeAssignment(observed, accounts, maxPer)
		if len(assign) != maxPer {
			t.Errorf("maxPer=%d homed %d users, want exactly %d", maxPer, len(assign), maxPer)
		}
	}
	// 0 still means "cap disabled" — everyone gets a home.
	if assign := computeAssignment(observed, accounts, 0); len(assign) != len(observed) {
		t.Errorf("maxPer=0 (disabled) homed %d of %d", len(assign), len(observed))
	}
}

// 0 disables the cap — behaviour must be exactly the pre-cap load balancing.
func TestUserCapDisabledMatchesPureLoadBalancing(t *testing.T) {
	if got := effectiveUserCap(15, 3, 0); got != 0 {
		t.Errorf("effectiveUserCap with cap disabled = %d, want 0", got)
	}
	accounts := []string{"i", "sail@mlsys.io", "ytb"}
	a := computeAssignment(observed, accounts, 0)
	for _, n := range counts(a) {
		if n == 0 {
			t.Error("an account went unused with the cap disabled")
		}
	}
}

// loadByUser only sees 7 days of activity, but the cap counts everyone homed.
// If the counted population were wider than the placeable one, overCap could
// report a violation computeAssignment cannot fix — pinning `rebalance` true
// forever, which disables the skew hysteresis and churns people's egress IPs.
func TestPlacementIncludesHomedButIdleUsers(t *testing.T) {
	loads := []userLoad{{"active1", 900}, {"active2", 100}}
	existing := []models.ClaudeUserAssignment{
		{UserSub: "active1", Account: "i"},     // already counted
		{UserSub: "idle1", Account: "i"},       // quiet, still homed
		{UserSub: "idle2", Account: "gone@ex"}, // quiet AND account removed
	}
	got := placementPopulation(loads, existing)
	if len(got) != 4 {
		t.Fatalf("population = %d, want 4 (2 active + 2 idle, no duplicate)", len(got))
	}
	byUser := map[string]int64{}
	for _, u := range got {
		if _, dup := byUser[u.UserSub]; dup {
			t.Errorf("%s appears twice", u.UserSub)
		}
		byUser[u.UserSub] = u.Tokens
	}
	if byUser["active1"] != 900 {
		t.Errorf("active1 load = %d, want 900 (must not be zeroed)", byUser["active1"])
	}
	for _, q := range []string{"idle1", "idle2"} {
		if _, ok := byUser[q]; !ok {
			t.Errorf("%s was not placed, so it is counted but unplaceable", q)
		}
		if byUser[q] != 0 {
			t.Errorf("%s joined with load %d, want 0 so it cannot perturb balancing", q, byUser[q])
		}
	}
}

// An over-shared pool can sit well inside the skew threshold — that is exactly
// what balancing on load produces. Without this trigger, hysteresis would keep
// an existing 7/6/2 split frozen and the cap would never take effect.
func TestOverCapForcesARebalance(t *testing.T) {
	valid := map[string]bool{"i": true, "ytb": true}
	cur := map[string]string{
		"u1": "i", "u2": "i", "u3": "i", "u4": "i",
		"u5": "ytb", "u6": "ytb",
	}
	if !overCap(cur, valid, 3) {
		t.Error("4 users on one account did not trip the 3-user cap")
	}
	if overCap(cur, valid, 4) {
		t.Error("a distribution inside the cap reported over-cap")
	}
	if overCap(cur, valid, 0) {
		t.Error("a disabled cap reported over-cap")
	}
	// Users pinned to a removed account must not count toward a live one.
	cur["u7"] = "gone@example.com"
	if overCap(cur, valid, 4) {
		t.Error("a user on a removed account was counted against a live account")
	}
}
