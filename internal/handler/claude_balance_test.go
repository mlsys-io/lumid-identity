package handler

import "testing"

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

// The live pool: 15 users, 3 accounts, target 3. That needs 5 accounts, so the
// target is infeasible and must degrade to the tightest feasible ceiling — an
// even 5 per account — rather than refusing to place anyone.
func TestUserCapDegradesToEvenSpreadWhenPoolTooSmall(t *testing.T) {
	accounts := []string{"i", "sail@mlsys.io", "ytb"}
	maxPer := effectiveUserCap(len(observed), len(accounts), 3)
	if maxPer != 5 {
		t.Fatalf("effectiveUserCap = %d, want 5 = ceil(15/3)", maxPer)
	}
	got := counts(computeAssignment(observed, accounts, maxPer))
	if len(got) != len(accounts) {
		t.Fatalf("used %d accounts, want %d", len(got), len(accounts))
	}
	for acct, n := range got {
		if n != 5 {
			t.Errorf("account %s homes %d users, want an even 5", acct, n)
		}
	}
}

// Availability outranks the target: every user must still get a home, even when
// the cap cannot be met. An unplaced user drops to the HRW fallback at lease
// time, which silently undoes the pinning the cap exists to enforce.
func TestUserCapNeverLeavesAUserUnplaced(t *testing.T) {
	accounts := []string{"only"}
	for _, maxPer := range []int{0, 1, 3, effectiveUserCap(len(observed), 1, 1)} {
		assign := computeAssignment(observed, accounts, maxPer)
		if len(assign) != len(observed) {
			t.Errorf("maxPer=%d placed %d of %d users", maxPer, len(assign), len(observed))
		}
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
