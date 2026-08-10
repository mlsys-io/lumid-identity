package handler

import "testing"

// The core fix: an account the lease-time valve will always refuse must not be
// given users, or they are homed to a field box they can never egress from.
func TestServableAccountsDropsExhausted(t *testing.T) {
	accounts := []string{"a", "b", "ytb"}
	q := map[string]accountQuota{
		"a":   {pct5: 10, pct7: 20, known: true},
		"b":   {pct5: 50, pct7: 60, known: true},
		"ytb": {pct5: 30, pct7: 96, known: true}, // over on the 7d window only
	}
	got := servableAccounts(accounts, q)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("servableAccounts = %v, want [a b]", got)
	}
}

// Either window independently disqualifies — 5h exhaustion is just as fatal to
// selection as 7d, and the valve checks both.
func TestServableAccountsHonoursEitherWindow(t *testing.T) {
	q := map[string]accountQuota{
		"five": {pct5: nearExhaustCeiling, pct7: 1, known: true},
		"week": {pct5: 1, pct7: nearExhaustCeiling, known: true},
		"ok":   {pct5: nearExhaustCeiling - 0.1, pct7: nearExhaustCeiling - 0.1, known: true},
	}
	got := servableAccounts([]string{"five", "week", "ok"}, q)
	if len(got) != 1 || got[0] != "ok" {
		t.Fatalf("servableAccounts = %v, want [ok]", got)
	}
}

// A missing or stale snapshot must NEVER read as exhausted: lease-time
// re-probes those, and treating unknown as exhausted would empty the pool the
// moment the snapshot refresher fell behind.
func TestUnknownQuotaIsServable(t *testing.T) {
	q := map[string]accountQuota{
		"nosnap": {},                                // no snapshot at all
		"stale":  {},                                // stale -> recorded as unknown
		"hot":    {pct5: 99, pct7: 99, known: true}, // genuinely exhausted
	}
	got := servableAccounts([]string{"hot", "nosnap", "stale"}, q)
	if len(got) != 2 {
		t.Fatalf("servableAccounts = %v, want the two unknown accounts", got)
	}
	for _, a := range got {
		if a == "hot" {
			t.Errorf("exhausted account survived: %v", got)
		}
	}
}

// The dangerous edge: if EVERY account is exhausted, dropping them all would
// leave every user unhomed — strictly worse than an imperfect home. Fall back
// to the full list instead.
func TestAllExhaustedFallsBackToFullList(t *testing.T) {
	accounts := []string{"a", "b"}
	q := map[string]accountQuota{
		"a": {pct5: 99, pct7: 99, known: true},
		"b": {pct5: 95, pct7: 97, known: true},
	}
	got := servableAccounts(accounts, q)
	if len(got) != 2 {
		t.Fatalf("servableAccounts = %v, want the full list as fallback", got)
	}
}

// Placement must then actually route around the exhausted account rather than
// merely knowing about it.
func TestComputeAssignmentAvoidsExhaustedTarget(t *testing.T) {
	accounts := []string{"a", "b", "ytb"}
	q := map[string]accountQuota{
		"a":   {pct5: 5, pct7: 5, known: true},
		"b":   {pct5: 5, pct7: 5, known: true},
		"ytb": {pct5: 5, pct7: 93, known: true},
	}
	loads := []userLoad{
		{UserSub: "u1", Tokens: 500},
		{UserSub: "u2", Tokens: 400},
		{UserSub: "u3", Tokens: 300},
		{UserSub: "u4", Tokens: 200},
	}
	got := computeAssignment(loads, servableAccounts(accounts, q), 5)
	if len(got) != len(loads) {
		t.Fatalf("placed %d of %d users", len(got), len(loads))
	}
	for sub, acct := range got {
		if acct == "ytb" {
			t.Errorf("%s placed on the exhausted account", sub)
		}
	}
}

func TestExhaustedPredicate(t *testing.T) {
	cases := []struct {
		name string
		q    accountQuota
		want bool
	}{
		{"unknown", accountQuota{pct5: 100, pct7: 100}, false}, // known=false wins
		{"below", accountQuota{pct5: 91.9, pct7: 91.9, known: true}, false},
		{"at ceiling", accountQuota{pct5: nearExhaustCeiling, pct7: 0, known: true}, true},
		{"above", accountQuota{pct5: 0, pct7: 99, known: true}, true},
	}
	for _, c := range cases {
		if got := c.q.exhausted(); got != c.want {
			t.Errorf("%s: exhausted() = %v, want %v", c.name, got, c.want)
		}
	}
}
