package common

import (
	"os"
	"testing"
	"time"
)

// Role-tiered Claude pool caps exist because the pool is shared between a large
// cohort and the operators running the platform, and a single global number
// cannot serve both: sized for the operators it is no limit at all for 20
// students, and sized for the students it throttles the heaviest legitimate work
// on the cluster.

func clearRoleTierEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LUMID_QUOTA_CLAUDE_5H_TOKENS", "LUMID_QUOTA_CLAUDE_7D_TOKENS",
		"LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", "LUMID_QUOTA_CLAUDE_USER_7D_TOKENS",
	} {
		old := os.Getenv(k)
		os.Unsetenv(k)
		t.Cleanup(func() {
			if old != "" {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// For ORDINARY users the change must be INERT until an operator opts in. Shipping
// a binary that silently retiers everyone's quota is how a deploy becomes
// indistinguishable from an outage for whoever was over the new line. Admins are
// different: they are unconditionally UNCAPPED (sentinel), never bound by a
// user-tier cap. Their usage is still COUNTED (event + anchor) — the caps are
// what they're exempt from, not the accounting.
func TestRoleTierDefaultsToGlobalForEveryone(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "450000000")

	// Ordinary users default to the global cap (opt-in via LUMID_QUOTA_CLAUDE_USER_*).
	for _, role := range []string{"user", "", "nonsense"} {
		short, seven := ClaudePoolLimitsForRole(role)
		if short != 35000000 || seven != 450000000 {
			t.Errorf("role %q with no user-tier env set got (%d, %d), want the global (35000000, 450000000) — "+
				"the user tier must be opt-in", role, short, seven)
		}
	}
	// role=admin is on the GLOBAL tier (uncapped until 2026-08-24 — see
	// ClaudePoolLimitsForRole for why the exemption ended).
	if short, seven := ClaudePoolLimitsForRole("admin"); short != 35000000 || seven != 450000000 {
		t.Errorf("role admin got (%d, %d), want the global (35000000, 450000000) — "+
			"admins are capped at the global tier, not exempt", short, seven)
	}
	// super_admin remains the ONE exemption, kept as an escape hatch.
	if short, seven := ClaudePoolLimitsForRole("super_admin"); short != claudePoolUnlimitedSentinel || seven != claudePoolUnlimitedSentinel {
		t.Errorf("role super_admin got (%d, %d), want the unlimited sentinel (%d, %d) — "+
			"the escape hatch must survive, or a mis-sized cap locks out every operator",
			short, seven, claudePoolUnlimitedSentinel, claudePoolUnlimitedSentinel)
	}
}

// Once set, the user tier applies to role="user" and NOT to operators (who stay
// uncapped).
func TestUserTierAppliesOnlyToOrdinaryUsers(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "450000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", "2000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_7D_TOKENS", "40000000")

	cases := []struct {
		role        string
		wantShort   int
		wantSevenD  int
		description string
	}{
		{"user", 2000000, 40000000, "a student gets the cohort budget"},
		{"", 2000000, 40000000, "an unset role is NOT privileged — default to the tighter tier"},
		{"admin", 35000000, 450000000, "an admin gets the global tier — larger than a user, not unlimited"},
		{"super_admin", claudePoolUnlimitedSentinel, claudePoolUnlimitedSentinel, "super_admin is the one remaining exemption (escape hatch)"},
	}
	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			short, seven := ClaudePoolLimitsForRole(c.role)
			if short != c.wantShort || seven != c.wantSevenD {
				t.Errorf("role %q got (%d, %d), want (%d, %d)",
					c.role, short, seven, c.wantShort, c.wantSevenD)
			}
		})
	}
}

// An unrecognised role must fall to the TIGHTER tier, not the looser one. A typo
// in a role string, or a role added later that this code has not been taught
// about, must not silently hand someone operator-sized quota on a shared pool.
func TestUnknownRoleGetsTheTighterTier(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", "2000000")

	short, _ := ClaudePoolLimitsForRole("stuent") // deliberate typo
	if short != 2000000 {
		t.Errorf("unknown role got the %d cap, want the tighter user tier (2000000) — "+
			"an unrecognised role must never be treated as privileged", short)
	}
}

// A nil DB (or empty sub) must FAIL OPEN to the global caps.
//
// Failing closed here would be actively misleading: a transient lookup failure
// would start denying quota to admins, which surfaces as
// "quota_exceeded_claude_5h" — indistinguishable from the pool genuinely being
// exhausted, and it would send an operator hunting a capacity problem that does
// not exist.
func TestLookupFailureFallsOpenToGlobalCaps(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", "2000000")

	if short, _ := ClaudePoolLimitsForUser(nil, "some-sub"); short != 35000000 {
		t.Errorf("nil db got short cap %d, want the global 35000000 (fail open)", short)
	}
	if short, _ := ClaudePoolLimitsForUser(nil, ""); short != 35000000 {
		t.Errorf("empty sub got short cap %d, want the global 35000000 (fail open)", short)
	}
}

// The cache must actually expire, or a role change never takes effect and an
// operator who demotes someone sees no result until the process restarts.
func TestRoleCacheEntriesExpire(t *testing.T) {
	roleCacheMu.Lock()
	roleCache["expiry-probe"] = roleCacheEntry{role: "admin", exp: time.Now().Add(-time.Second)}
	roleCacheMu.Unlock()

	roleCacheMu.Lock()
	e, ok := roleCache["expiry-probe"]
	roleCacheMu.Unlock()
	if !ok {
		t.Fatal("probe entry missing")
	}
	if time.Now().Before(e.exp) {
		t.Fatal("probe entry is not actually expired — test is not exercising expiry")
	}
	// An expired entry must not be served: ClaudePoolLimitsForUser re-queries,
	// and with a nil db that means the global caps rather than the cached admin
	// tier. Both are the same number here, so assert the TTL is sane instead —
	// the behavioural path is covered by the fail-open test above.
	if roleCacheTTL <= 0 || roleCacheTTL > 15*time.Minute {
		t.Errorf("roleCacheTTL = %v, want a short positive TTL — a long TTL means a "+
			"role change silently does not take effect", roleCacheTTL)
	}

	roleCacheMu.Lock()
	delete(roleCache, "expiry-probe")
	roleCacheMu.Unlock()
}

// Display surfaces must be able to tell "uncapped" from "a very large budget".
//
// The sentinel is deliberately a huge positive number so enforcement needs no
// special case, but that same property makes it unreadable on screen: /me/claude-usage
// and the /code dashboard would render an admin as "0% of 2147483647" — which looks
// like a bug and hides the fact that the row has no budget at all. Enforcement must
// keep treating it as an ordinary number; only rendering branches on this.
func TestClaudePoolIsUnlimitedDistinguishesTheSentinel(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "450000000")

	// super_admin is the only exempt role since 2026-08-24.
	if short, seven := ClaudePoolLimitsForRole("super_admin"); !ClaudePoolIsUnlimited(short) || !ClaudePoolIsUnlimited(seven) {
		t.Errorf("super_admin caps (%d, %d) must report as unlimited", short, seven)
	}

	// A real budget — however generous — must NOT report as unlimited, or an
	// operator loses the one signal that says "this row is exempt". `admin` is
	// in this set now: its global-tier cap is large, and a large number is
	// exactly what must not be mistaken for no number at all.
	for _, role := range []string{"admin", "user", ""} {
		short, seven := ClaudePoolLimitsForRole(role)
		if ClaudePoolIsUnlimited(short) || ClaudePoolIsUnlimited(seven) {
			t.Errorf("role %q: real caps (%d, %d) must not report as unlimited", role, short, seven)
		}
	}
}

// The cohort budget is what an operator actually sets on the manifest; pin that
// the tier applies to role `user` and leaves admins exempt, so arming it cannot
// silently throttle the operators.
func TestCohortBudgetKeepsTheTierOrdering(t *testing.T) {
	clearRoleTierEnv(t)
	os.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "35000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "450000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", "2000000")
	os.Setenv("LUMID_QUOTA_CLAUDE_USER_7D_TOKENS", "20000000")

	short, seven := ClaudePoolLimitsForRole("user")
	if short != 2000000 || seven != 20000000 {
		t.Errorf("role user got (%d, %d), want the cohort tier (2000000, 20000000)", short, seven)
	}
	// Arming the cohort budget must not drag the admin tier down with it: an
	// admin is on the GLOBAL cap, which is strictly larger than the cohort's.
	// That ordering is the property this tiering exists to guarantee — the
	// original inversion was throttling operators as hard as students.
	aShort, aSeven := ClaudePoolLimitsForRole("admin")
	if aShort != 35000000 || aSeven != 450000000 {
		t.Errorf("admin got (%d, %d), want the global tier (35000000, 450000000)", aShort, aSeven)
	}
	if aShort <= short || aSeven <= seven {
		t.Errorf("admin (%d, %d) must be strictly larger than user (%d, %d)", aShort, aSeven, short, seven)
	}
	// ...and an admin cap must be a REAL budget, not the sentinel. Since
	// 2026-08-24 only super_admin is exempt; if this ever reports unlimited the
	// admin tier has silently stopped being enforced.
	if ClaudePoolIsUnlimited(aShort) || ClaudePoolIsUnlimited(aSeven) {
		t.Errorf("admin caps (%d, %d) report as unlimited — the admin tier is not being enforced", aShort, aSeven)
	}
	if sShort, sSeven := ClaudePoolLimitsForRole("super_admin"); !ClaudePoolIsUnlimited(sShort) || !ClaudePoolIsUnlimited(sSeven) {
		t.Errorf("super_admin got (%d, %d), want the escape-hatch exemption", sShort, sSeven)
	}
}
