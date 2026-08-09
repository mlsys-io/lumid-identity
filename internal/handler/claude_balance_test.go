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
	got := totals(observed, computeAssignment(observed, accounts), accounts)

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
	assign := computeAssignment(observed, accounts)
	if a, b := assign["suzhengy"], assign["eyuansu71"]; a == b {
		t.Errorf("the two heaviest users both landed on %q", a)
	}
}

// Every user must be placed, including zero-load ones — an unassigned user has
// no home box and would fall through to whatever the lease picks.
func TestAllUsersAssigned(t *testing.T) {
	accounts := []string{"i", "yao@yao.lu", "ytb"}
	assign := computeAssignment(observed, accounts)
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
	first := computeAssignment(observed, accounts)
	for i := 0; i < 8; i++ {
		again := computeAssignment(observed, accounts)
		for sub, acct := range first {
			if again[sub] != acct {
				t.Fatalf("run %d moved %q: %q -> %q", i, sub, acct, again[sub])
			}
		}
	}
}
