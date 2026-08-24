package common

// Tier-1 quota enforcement — the dogfood gate.
//
// Five caps, all per-tenant, all rolled at midnight UTC:
//   1. cycles/day                                   (kind=cycle_start)
//   2. LLM input+output tokens/day                  (kind=cycle_llm)
//   3. Gmail sends/day                              (kind=external_api, endpoint=gmail.send)
//   4. Slack posts/day                              (kind=external_api, endpoint=slack.post)
//   5. Wall-time per cycle (10 min)                 — enforced by the picker, not here
//   6. Concurrent cycles per tenant (5)             — enforced by an in-mem semaphore in
//                                                     the scheduler process, not here
//
// CPU + memory caps are deferred to Phase D1 (per-cycle Docker isolation).
//
// Records flow into the existing usage_events table (models/usage_event.go).
// CheckAndCharge is a non-transactional COUNT-then-INSERT — the race window
// can let one extra event slip past the cap. Acceptable for dogfood; Phase D
// upgrades to SERIALIZABLE transactions if it matters.

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"lumid_identity/models"
)

const (
	DefaultCyclesDaily     = 100
	DefaultLLMTokensDaily  = 500_000
	DefaultGmailSendsDaily = 200
	DefaultSlackPostsDaily = 100

	// Claude account-pool per-user caps (uncached input + output tokens).
	//
	// The short window was 4M/5h; it is now 2M/4h (operator decision
	// 2026-08-11). The 5h originally mirrored Anthropic's own window so a
	// user's lumid budget reset at the same moment their upstream one did.
	// 4h deliberately breaks that alignment: this is a FAIRNESS cap between
	// lumid users sharing a pooled subscription, not a mirror of Anthropic's
	// accounting, and a shorter window bounds how much of a shared account one
	// person can absorb before the others get a turn.
	//
	// Consequence worth knowing: the two windows now drift out of phase, so a
	// user can hit their lumid cap while Anthropic still shows headroom (and
	// vice versa). That is intended — the pool-side ceiling is the binding one.
	DefaultClaudeShortTokens = 2_000_000
	DefaultClaude7dTokens    = 40_000_000
	// Target ceiling on DISTINCT end-users homed on one pooled account.
	//
	// The pooled accounts are individual consumer Claude subscriptions, and the
	// shape that got them suspended — twice — was many unrelated people sharing
	// one: 8 accounts each serving 4-6 users on 2026-08-04, and 6-7 users per
	// account when yao@yao.lu was suspended on 2026-08-09. Balancing purely on
	// token load equalises the wrong thing; it will happily pile seven people
	// onto one subscription as long as their combined draw is even.
	//
	// 5 is a HARD GATE, not a target: the balancer will not home a 6th user on
	// an account, even when the pool is too small to place everyone. Overflow
	// users are left unhomed and fall back to HRW rendezvous placement at lease
	// time (see admin_claude_quota.go) — they are still SERVED, they just have
	// no stable egress box. Operator decision 2026-08-10, replacing the earlier
	// soft-target semantics where an undersized pool silently widened the cap.
	DefaultClaudeMaxUsersPerAccount = 5

	// DefaultClaudeAssignmentIdle is how long a homed user may go without using
	// the pool before their slot is released.
	//
	// Nothing else ever deletes a ClaudeUserAssignment, so before this existed a
	// single turn months ago held a subscription slot forever. Harmless while
	// the user cap was a soft target (it just widened); under a hard gate a
	// dormant user directly blocks an active one from being homed.
	//
	// 30m is deliberately aggressive: with more users than slots, a slot should
	// belong to whoever is actually working, not to whoever claimed it first.
	// The cost is egress-IP churn — the assignment IS the user's public egress
	// box — so a user returning after a break may come back on a different box.
	// That is an accepted trade here, not an oversight. 0 disables.
	//
	// It is also shorter than a typical Claude Code session's think/read gaps
	// are long, which is fine: reclamation only frees the slot, and the next
	// request re-homes the user immediately. The window bounds how long a
	// walked-away user holds a slot, not how long a working one keeps it.
	DefaultClaudeAssignmentIdle = 30 * time.Minute
)

// Limits captures the headline numbers the UI surfaces alongside today's totals.
type Limits struct {
	CyclesDaily     int `json:"cycles_daily"`
	LLMTokensDaily  int `json:"llm_tokens_daily"`
	GmailSendsDaily int `json:"gmail_sends_daily"`
	SlackPostsDaily int `json:"slack_posts_daily"`
}

// DefaultLimits reads env overrides; falls back to the constants above.
func DefaultLimits() Limits {
	return Limits{
		CyclesDaily:     envIntPos("LUMID_QUOTA_CYCLES_DAILY", DefaultCyclesDaily),
		LLMTokensDaily:  envIntPos("LUMID_QUOTA_LLM_TOKENS_DAILY", DefaultLLMTokensDaily),
		GmailSendsDaily: envIntPos("LUMID_QUOTA_GMAIL_DAILY", DefaultGmailSendsDaily),
		SlackPostsDaily: envIntPos("LUMID_QUOTA_SLACK_DAILY", DefaultSlackPostsDaily),
	}
}

func envIntPos(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Totals captures usage so far today across the four gated kinds.
type Totals struct {
	Cycles     int `json:"cycles"`
	LLMTokens  int `json:"llm_tokens"`
	GmailSends int `json:"gmail_sends"`
	SlackPosts int `json:"slack_posts"`
}

// TodayBound returns midnight-UTC at the start of today.
func TodayBound() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// NextResetAt is when the per-day counters roll back to zero.
func NextResetAt() time.Time {
	return TodayBound().Add(24 * time.Hour)
}

// FetchTodayTotals aggregates usage_events for one user from midnight UTC.
// One grouped query — keeps the hot path off N round-trips.
func FetchTodayTotals(db *gorm.DB, userSub string) (Totals, error) {
	var t Totals
	rows := []struct {
		Kind     string
		Endpoint string
		Tokens   int
		Cnt      int
	}{}
	err := db.Raw(`
		SELECT kind                              AS kind,
		       COALESCE(endpoint, '')            AS endpoint,
		       COALESCE(SUM(input_tokens + output_tokens), 0) AS tokens,
		       COUNT(*)                          AS cnt
		FROM   usage_events
		WHERE  user_sub = ? AND ts >= ?
		GROUP  BY kind, endpoint`, userSub, TodayBound()).Scan(&rows).Error
	if err != nil {
		return t, err
	}
	for _, r := range rows {
		switch r.Kind {
		case "cycle_start":
			t.Cycles += r.Cnt
		case "cycle_llm":
			t.LLMTokens += r.Tokens
		case "external_api":
			switch r.Endpoint {
			case "gmail.send":
				t.GmailSends += r.Cnt
			case "slack.post":
				t.SlackPosts += r.Cnt
			}
		}
	}
	return t, nil
}

// ChargeReq is the input shape for CheckAndCharge.
type ChargeReq struct {
	UserSub      string
	Kind         string // cycle_start | cycle_llm | external_api | chat | ...
	Endpoint     string // for cycle_llm: "<app>.<loop>"; for external_api: "gmail.send" | "slack.post"
	Model        string
	InputTokens  int
	OutputTokens int
	// RAW cached-input counts as Anthropic reported them. claude-proxy sends
	// these unweighted; the quota weighting happens here so usage_events stays a
	// faithful record that reconciles against Anthropic's own numbers.
	CacheReadTokens     int
	CacheCreationTokens int
	// 1-hour-TTL share of CacheCreationTokens (a subset of it).
	CacheCreation1hTokens int
	Count                 int // for cycle_start / external_api; defaults to 1 when 0
	CostCents             int
	DryRun                bool
	Meta                  string // optional JSON blob
}

// ChargeRes is the output. Same shape served by /internal/usage/charge.
type ChargeRes struct {
	Allowed    bool   `json:"allowed"`
	DenyReason string `json:"deny_reason,omitempty"`
	Today      Totals `json:"today"`
	Limits     Limits `json:"limits"`
	ResetAt    string `json:"reset_at"`
	// kind=claude_proxy only: the user's pool utilization after this charge,
	// as a percentage of the fixed-window 5h/7d token caps.
	FiveHourPct *float64 `json:"five_hour_pct,omitempty"`
	SevenDayPct *float64 `json:"seven_day_pct,omitempty"`
	// kind=claude_proxy only: when each window fully resets (RFC3339), or
	// empty when that window is idle (no anchor, or its window has expired
	// with no charge yet to open a fresh one).
	FiveHourReset string `json:"five_hour_reset,omitempty"`
	SevenDayReset string `json:"seven_day_reset,omitempty"`
}

// poolCapApplies reports whether a model's usage counts against the per-user
// pool 5h/7d windows.
//
// Every named model — Claude or not — draws on the SAME shared window. Non-Anthropic
// models (deepseek-v4-flash, kimi-k3, z-ai/glm-5.2) were previously excluded so their
// usage never counted and could never deny; that metering gap is closed (the cost-model
// difference is handled by the weight, not by skipping the window).
//
// "" is claude-proxy's PRE-REQUEST dry-run gate (no model, zero tokens). It MUST remain
// gated: treating "" as non-Anthropic is the regression that silently disabled ALL pool
// quota enforcement (see quota_gate_test.go). Only claude-proxy's gate sends ""; a real
// charge always carries a model.
func poolCapApplies(model string) bool { return true }

// Model weighting for the pool quota.
//
// The cap counts COST, not raw tokens. Anthropic list rates per MTok in/out
// (verified 2026-08-12): Opus $5/$25, Sonnet $3/$15, Haiku $1/$5 — so Opus is
// ~1.67x Sonnet and Sonnet 3x Haiku. The gate summed tokens flat, so a Sonnet
// token cost exactly as much quota as an Opus token despite being cheaper
// (measured 2026-08-12: one user's Sonnet work was 31% of their tokens and 9%
// of their spend).
//
// NOTE: an earlier revision of this comment cited Opus at $15/$75, and the
// weights below were normalised against that wrong figure — which under-charged
// Sonnet 3x and Haiku ~3.8x. The rates above are the corrected ones; the test
// in claude_model_weight_test.go pins each weight to its list-price ratio so a
// future price change fails an assertion instead of silently persisting.
//
// Flat counting doesn't just misprice, it inverts the incentive: under a binding
// cap, Sonnet costs the same quota as Opus while delivering less, so the
// rational move is to route everything to the most expensive model. Weighting
// removes that.
//
// Normalised to OPUS = 1.0 rather than to Sonnet, so the operator-set caps keep
// the meaning they were measured against (an Opus-dominated workload) and adding
// weights doesn't silently re-scale them.
//
// Applied at READ time, never at write time: usage_events keeps TRUE token
// counts so cost reporting and the per-model breakdown stay honest, the weights
// apply retroactively, and changing them doesn't require rewriting history.
const (
	// Price ratios to Opus, from Anthropic list rates verified 2026-08-12:
	// Opus $5/$25 per MTok, Sonnet $3/$15, Haiku $1/$5. Both the input and the
	// output ratio give the same number, so one weight per model is exact.
	//
	// These were 0.2 / 0.053, derived by normalising against an Opus rate of
	// $15 — which was itself wrong (see modelCostCents in claude-proxy). The
	// effect was to under-charge Sonnet work 3x and Haiku ~3.8x relative to
	// Opus, overstating how much cheaper they are and skewing the incentive
	// further toward them than the real price gap justifies.
	claudeWeightOpus   = 1.0
	claudeWeightSonnet = 0.6
	claudeWeightHaiku  = 0.2

	// Non-Anthropic models (deepseek-v4-flash, kimi-k3, z-ai/glm-5.2) now draw on the
	// SAME per-user window as Claude, so they need a price-ratio weight of their own.
	// Ratio to Opus: DeepSeek ~$0.27/$1.10, GLM ~$0.14/$0.14 per MTok vs Opus $5/$25
	// → true ratio ≈ 0.05. 0.1 keeps a 2x margin so no single non-Claude model silently
	// drains a week's budget, but stays BELOW the Haiku floor (0.2) so the free
	// self-hosted model isn't over-counted. Env-tunable; the value is a policy call.
	claudeWeightNonClaude = 0.1

	// Cached input is charged at a fraction of fresh input, so the quota weights
	// it the same way it weights models — by price ratio. A cache READ is a tenth
	// of fresh input; a 5-minute cache WRITE is 1.25x.
	//
	// These live here, not in claude-proxy, because the proxy now reports RAW
	// counts and identity owns every quota weighting. Keeping the arithmetic in
	// one service is what lets usage_events stay a faithful record: the stored
	// numbers are what Anthropic reported, and the quota is a view over them.
	claudeCacheReadWeight  = 0.1
	claudeCacheWriteWeight = 1.25
	// A 1-HOUR cache write costs 2x base input, not 1.25x. Pricing every write at
	// the 5-minute rate under-charges 1-hour writes by 37.5%.
	claudeCacheWrite1hWeight = 2.0
)

// ClaudeWeightedTokensSQL is the full quota unit as a SQL expression: raw token
// columns folded together by price ratio, then scaled by the model weight.
//
// `pfx` qualifies the columns for joined queries ("ue." or ""). This is the ONE
// definition of the quota unit — the gate, the admin table and the /me surface
// all interpolate it, because a dashboard that disagrees with the gate about how
// much someone has drawn is the bug class that produced the 5h/4h window skew.
//
// Old rows (pre-2026-08-12) carry a pre-weighted total in input_tokens with both
// cache columns at 0, so they pass through this expression unchanged. No backfill
// is needed and no row is double-counted.
func ClaudeWeightedTokensSQL(pfx string) string {
	// GREATEST(...,0) mirrors the Go clamp: cache_creation_1h_tokens is a subset
	// of cache_creation_tokens, and a malformed row must not subtract past zero.
	return fmt.Sprintf(`ROUND((%[1]sinput_tokens + %[1]soutput_tokens
	   + %[1]scache_read_tokens * %[2]v
	   + GREATEST(%[1]scache_creation_tokens - %[1]scache_creation_1h_tokens, 0) * %[3]v
	   + LEAST(%[1]scache_creation_1h_tokens, %[1]scache_creation_tokens) * %[4]v) * (%[5]s))`,
		pfx, claudeCacheReadWeight, claudeCacheWriteWeight, claudeCacheWrite1hWeight,
		ClaudeModelWeightSQL(pfx+"model"))
}

// ClaudeWeightedTokens is the Go twin of ClaudeWeightedTokensSQL, for weighting
// the single in-flight request the gate is deciding on. Keep the two in step.
func ClaudeWeightedTokens(model string, in, out, cacheRead, cacheWrite, cacheWrite1h int) int {
	// cacheWrite1h is a SUBSET of cacheWrite, so the 5-minute share is the
	// remainder. Clamp: a malformed report claiming more 1h than total must not
	// make the 5-minute term negative.
	if cacheWrite1h > cacheWrite {
		cacheWrite1h = cacheWrite
	}
	if cacheWrite1h < 0 {
		cacheWrite1h = 0
	}
	write5m := cacheWrite - cacheWrite1h
	raw := float64(in) + float64(out) +
		float64(cacheRead)*claudeCacheReadWeight +
		float64(write5m)*claudeCacheWriteWeight +
		float64(cacheWrite1h)*claudeCacheWrite1hWeight
	return int(math.Round(raw * ClaudeModelWeight(model)))
}

// ClaudeModelWeightSQL is the weight as a SQL expression over a `model` column.
//
// It is a shared constant because the weighted sum happens in SQL in more than
// one place (the gate's ClaudePoolUsage and the admin usage table), and those
// MUST agree — a dashboard that disagrees with the gate about how much someone
// has used is the same class of bug as the 5h/4h window skew. `col` lets a
// caller qualify the column (e.g. "ue.model") for joined queries.
func ClaudeModelWeightSQL(col string) string {
	return fmt.Sprintf(`CASE
	  WHEN LOWER(%[1]s) LIKE 'claude-opus%%'   THEN %[2]v
	  WHEN LOWER(%[1]s) LIKE 'claude-sonnet%%' THEN %[3]v
	  WHEN LOWER(%[1]s) LIKE 'claude-haiku%%'  THEN %[4]v
	  ELSE %[5]v
	END`, col, claudeWeightOpus, claudeWeightSonnet, claudeWeightHaiku, claudeWeightNonClaude)
}

// ClaudeModelWeight is the Go-side twin of ClaudeModelWeightSQL, for weighting
// the increment a single in-flight request would add. Keep the two in step.
func ClaudeModelWeight(model string) float64 {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "claude-opus"):
		return claudeWeightOpus
	case strings.HasPrefix(m, "claude-sonnet"):
		return claudeWeightSonnet
	case strings.HasPrefix(m, "claude-haiku"):
		return claudeWeightHaiku
	default:
		// Any other model — an unknown Claude variant OR a non-Anthropic model
		// (deepseek-v4-flash, kimi-k3, z-ai/glm-5.2) — is counted at the cheap
		// non-Claude weight. Non-Claude models now share the window, so they must
		// not fall through to the Sonnet-rate default.
		return claudeWeightNonClaude
	}
}

// LlmProvider classifies a model id by its serving route, so the dashboard can
// distinguish pooled Claude (subscription, 4h/7d-constrained) from OpenRouter
// (metered pay-per-use) from on-prem (self-hosted GB10, free at the margin).
// Mirrors claude-proxy's isSelfHostedModel/isDeepseekFamily semantics; keep the
// two in step (the frontend modelRoute() duplicates this — see claude-quota.tsx).
type LlmProvider string

const (
	ProviderClaude     LlmProvider = "claude"
	ProviderOpenRouter LlmProvider = "openrouter"
	ProviderOnPrem     LlmProvider = "onprem"
)

// ClassifyProvider maps a model id to its serving provider.
//
// Rules (matched to the gate's own classification):
//   - claude-*            → pooled Claude (draws the Anthropic subscription)
//   - deepseek-v4-flash   → on-prem (self-hosted GB10 pair, free at the margin)
//   - everything else     → OpenRouter (metered pay-per-use: kimi-*, z-ai/*,
//     deepseek/deepseek-*, any unlisted id)
func ClassifyProvider(model string) LlmProvider {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.IndexByte(m, '['); i >= 0 {
		m = m[:i] // strip Claude Code's [N] context-length marker
	}
	if strings.HasPrefix(m, "claude-") {
		return ProviderClaude
	}
	if m == "deepseek-v4-flash" {
		return ProviderOnPrem
	}
	return ProviderOpenRouter
}

// claudePoolUnlimitedSentinel is the "uncapped" cap for admins/super_admins: a
// weighted-token budget so large it can never bind (~2.1B units).
//
// Deliberately NOT 0 ("0 = unlimited"). 0 would break three things at once:
// envIntPos rejects non-positive values when reading env caps, the percentage
// math divides by the cap (divide-by-zero), and `used > 0` would hard-deny
// immediately. A huge positive sentinel keeps every downstream arithmetic valid
// (admin pct computes to ~0) and lets the same gate handle all roles uniformly.
const claudePoolUnlimitedSentinel = math.MaxInt32

// ClaudePoolIsUnlimited reports whether a cap returned by ClaudePoolLimitsForUser
// / ClaudePoolLimitsForRole is the admin uncapped sentinel rather than a real
// budget.
//
// Display surfaces need this: the sentinel keeps the arithmetic valid (pct
// computes to ~0), but rendering "2147483647 tokens, 0%" tells an operator
// nothing and looks like a bug. Enforcement must NOT branch on it — the whole
// point of a huge positive sentinel is that one code path handles every role.
func ClaudePoolIsUnlimited(cap int) bool { return cap >= claudePoolUnlimitedSentinel }

// ClaudePoolLimits reads the env-tunable per-user pool caps.
// LUMID_QUOTA_CLAUDE_5H_TOKENS keeps its name for continuity with any existing
// deployment env; it now sets the SHORT-window budget whatever that window's
// length is (see ClaudePoolShortWindow).
func ClaudePoolLimits() (short, sevenD int) {
	return envIntPos("LUMID_QUOTA_CLAUDE_5H_TOKENS", DefaultClaudeShortTokens),
		envIntPos("LUMID_QUOTA_CLAUDE_7D_TOKENS", DefaultClaude7dTokens)
}

// ── role-tiered caps ────────────────────────────────────────────────────────
//
// The caps above are GLOBAL: one number for everyone. That was fine for a small
// team, and breaks as soon as a large cohort shares the pool with its operators.
// The live values (35M short / 450M 7d) are ~17x the code defaults because they
// were sized for a handful of heavy users; applied to ~20 students on 2 pooled
// accounts they are not a limit at all, since the org's own Anthropic quota is
// exhausted long before any individual reaches 35M.
//
// Simply lowering the global number is the obvious move and the wrong one: it
// throttles the operators doing the heaviest legitimate work by exactly as much
// as it throttles a student. So the budget is tiered by role instead.
//
// Three tiers, tightest-first when in doubt:
//
//	role=user (and anything unrecognised) → LUMID_QUOTA_CLAUDE_USER_{5H,7D}_TOKENS
//	role=admin, role=super_admin          → the GLOBAL cap (LUMID_QUOTA_CLAUDE_{5H,7D}_TOKENS)
//
// NOBODY IS EXEMPT as of 2026-08-24. super_admin kept the sentinel for one day
// as an escape hatch against a mis-sized cap; it was removed once the tier had
// been observed in production, because the exemption covered the single
// largest consumer on the platform and so bounded everyone except the account
// that mattered most. The recovery path if a cap does misfire is the
// per-user window reset on /code (RequireSuperAdmin), not an uncapped role.
//
// ADMINS WERE UNCAPPED UNTIL 2026-08-24 and are now on the global tier. The
// original reasoning — operators doing the heaviest work should never be
// throttled by the budget that protects the pool from a cohort — assumed the
// pool had headroom to give them. It does not: three of the four pooled
// accounts were revoked on 2026-08-21, leaving ONE, and ~25% of all Claude
// requests were being denied. Measured the same day, the two largest consumers
// were both admins at ~820M weighted units each over 7 days, drawing against a
// budget that did not exist. An exemption is only defensible while the resource
// is not scarce.
//
// The sentinel and ClaudePoolIsUnlimited are retained deliberately even though
// no role returns them now: an operator can still set a tier to an enormous
// value, and the display surfaces must keep being able to tell "no budget"
// from "a very large one" rather than rendering a fraction of a sentinel.
//
// The user cap DEFAULTS to the global values, so the user tier changes nothing
// until an operator sets LUMID_QUOTA_CLAUDE_USER_* — setting them is the policy,
// and is MANDATORY for enforcement (see the deploy manifest). The admin tier
// needs no new env: it is the global cap, which is already set everywhere.
func ClaudePoolLimitsForRole(role string) (short, sevenD int) {
	gShort, gSeven := ClaudePoolLimits()
	if role == "admin" || role == "super_admin" {
		return gShort, gSeven
	}
	return envIntPos("LUMID_QUOTA_CLAUDE_USER_5H_TOKENS", gShort),
		envIntPos("LUMID_QUOTA_CLAUDE_USER_7D_TOKENS", gSeven)
}

// roleCache memoises the users lookup on the charge path.
//
// Every charge would otherwise add a SELECT to a hot path that already runs the
// window aggregate. A short TTL is the right trade: the only thing a stale entry
// can do is bill one user at the wrong tier for under a minute, and role changes
// are rare and administrative.
var (
	roleCacheMu  sync.Mutex
	roleCache    = map[string]roleCacheEntry{}
	roleCacheTTL = time.Minute
)

type roleCacheEntry struct {
	role string
	exp  time.Time
}

// ClaudePoolLimitsForUser resolves userSub's role and returns that tier's caps.
//
// On ANY lookup failure it falls back to the global caps rather than the
// (possibly tighter) user tier. Failing open matters here: a transient DB error
// must not silently start denying quota to admins, which would look exactly like
// the pool being exhausted and send someone hunting a nonexistent capacity
// problem. Under-charging for a moment is the cheaper failure.
func ClaudePoolLimitsForUser(db *gorm.DB, userSub string) (short, sevenD int) {
	if db == nil || userSub == "" {
		return ClaudePoolLimits()
	}
	roleCacheMu.Lock()
	e, ok := roleCache[userSub]
	roleCacheMu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return ClaudePoolLimitsForRole(e.role)
	}
	var role string
	// users.id IS the sub (see models.User — every downstream service FKs it).
	// Selecting the single column rather than loading the User row: this runs on
	// the charge path, and the row carries an avatar mediumtext.
	if err := db.Raw(`SELECT role FROM users WHERE id = ?`, userSub).
		Scan(&role).Error; err != nil || role == "" {
		return ClaudePoolLimits()
	}
	roleCacheMu.Lock()
	roleCache[userSub] = roleCacheEntry{role: role, exp: time.Now().Add(roleCacheTTL)}
	roleCacheMu.Unlock()
	return ClaudePoolLimitsForRole(role)
}

// DefaultClaudeShortWindow is the length of the per-user short window.
//
// The DB column is still `five_hour_anchor`: renaming it needs a migration for
// no functional gain, and the column only ever meant "when the short window
// started". Read it as shortAnchor.
const DefaultClaudeShortWindow = 4 * time.Hour

// ClaudePoolShortWindow is the env-tunable short-window length
// (LUMID_QUOTA_CLAUDE_SHORT_WINDOW, e.g. "4h", "90m").
//
// It is read in THREE places that must never disagree — the usage read
// (ClaudePoolUsage), the anchor roll (ClaudePoolCommit) and the admin usage
// query. If they diverge, a user's window appears to reset at one length while
// their budget is measured over another, which reads as quota vanishing or
// never resetting.
func ClaudePoolShortWindow() time.Duration {
	v := strings.TrimSpace(os.Getenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW"))
	if v == "" {
		return DefaultClaudeShortWindow
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return DefaultClaudeShortWindow
	}
	return d
}

// ClaudeMaxUsersPerAccount is the env-tunable ceiling on distinct users homed on
// one pooled account. 0 disables the cap and restores pure load balancing.
//
// Uses envIntNonNeg rather than envIntPos precisely so that an explicit "0" is
// honoured as "disabled" instead of silently falling back to the default.
func ClaudeMaxUsersPerAccount() int {
	return envIntNonNeg("LUMID_CLAUDE_MAX_USERS_PER_ACCOUNT", DefaultClaudeMaxUsersPerAccount)
}

// ClaudeAssignmentIdle is the env-tunable dormancy window after which a homed
// user's slot is released. Accepts a Go duration ("90m", "24h"); "0" disables
// reclamation entirely. An unparseable value falls back to the default rather
// than silently disabling reclamation.
func ClaudeAssignmentIdle() time.Duration {
	v := strings.TrimSpace(os.Getenv("LUMID_CLAUDE_ASSIGNMENT_IDLE"))
	if v == "" {
		return DefaultClaudeAssignmentIdle
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return DefaultClaudeAssignmentIdle
	}
	return d
}

// envIntNonNeg is envIntPos but admits 0, for knobs where 0 means "off".
func envIntNonNeg(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// ClaudeWindowLive reports whether a fixed window anchored at `anchor` with
// length `windowLen` is still live at `now`, and the instant it resets. A
// zero anchor (window never opened) is never live. The boundary is
// expired-inclusive: now == anchor+windowLen is NOT live — that instant is
// exactly when the window is fully spent and a fresh one may open.
func ClaudeWindowLive(anchor time.Time, windowLen time.Duration, now time.Time) (live bool, resetAt time.Time) {
	if anchor.IsZero() {
		return false, time.Time{}
	}
	resetAt = anchor.Add(windowLen)
	return now.Before(resetAt), resetAt
}

// claudePoolFarFuture is a sentinel bound used in place of a non-live
// window's anchor, so a SQL "ts >= sentinel" branch always contributes zero
// rows instead of risking a zero-value time.Time (year 1) hitting the MySQL
// DATETIME range.
func claudePoolFarFuture(now time.Time) time.Time {
	return now.AddDate(100, 0, 0)
}

// ClaudePoolStatus is one user's claude_proxy pool usage under the
// fixed-window (anchor-based) accounting. A zero Reset means that window is
// idle: no anchor yet, or its window fully expired with no charge since to
// open a fresh one — in both cases Used is 0.
type ClaudePoolStatus struct {
	FiveHourUsed  int
	SevenDayUsed  int
	FiveHourReset time.Time
	SevenDayReset time.Time
}

// formatPoolReset renders a ClaudePoolStatus reset instant for ChargeRes —
// RFC3339, or empty when the window is idle. Matches ResetAt's existing
// string convention and exactly what claude-proxy's chargeRes already
// expects on the wire.
func formatPoolReset(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ClaudePoolUsage returns one user's claude_proxy token usage under the
// fixed 5h/7d windows anchored in claude_pool_windows. Read-only and
// side-effect-free — safe to call from a dry-run gate check or a display
// handler with no risk of starting anyone's clock; only ClaudePoolCommit
// opens or rolls an anchor.
//
// Every claude_proxy row — Claude or not — counts toward the shared window.
// Non-Anthropic models (deepseek-v4-flash, kimi-k3, z-ai/glm-5.2) draw on the
// SAME per-user 5h/7d window as Claude; their cost difference is handled by the
// model weight (claudeWeightNonClaude), not by excluding them. This closure is
// what makes the shared-window design work end-to-end: the gate (poolCapApplies),
// this SUM, and the admin table all agree, so a dashboard never disagrees with
// the gate about how much a user has drawn.
func ClaudePoolUsage(db *gorm.DB, userSub string, now time.Time) (ClaudePoolStatus, error) {
	var status ClaudePoolStatus
	var win models.ClaudePoolWindow
	if err := db.Where("user_sub = ?", userSub).First(&win).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return status, nil
		}
		return status, err
	}

	fiveLive, fiveReset := ClaudeWindowLive(win.FiveHourAnchor, ClaudePoolShortWindow(), now)
	sevenLive, sevenReset := ClaudeWindowLive(win.SevenDayAnchor, 7*24*time.Hour, now)
	if !fiveLive && !sevenLive {
		return status, nil
	}
	if fiveLive {
		status.FiveHourReset = fiveReset
	}
	if sevenLive {
		status.SevenDayReset = sevenReset
	}

	far := claudePoolFarFuture(now)
	fiveBound, sevenBound := far, far
	if fiveLive {
		fiveBound = win.FiveHourAnchor
	}
	if sevenLive {
		sevenBound = win.SevenDayAnchor
	}
	scanBound := fiveBound
	if sevenBound.Before(scanBound) {
		scanBound = sevenBound
	}

	var row struct {
		FiveTokens  int
		SevenTokens int
	}
	w := ClaudeWeightedTokensSQL("")
	if err := db.Raw(fmt.Sprintf(`
		SELECT
		  COALESCE(SUM(CASE WHEN ts >= ? THEN %[1]s ELSE 0 END), 0) AS five_tokens,
		  COALESCE(SUM(CASE WHEN ts >= ? THEN %[1]s ELSE 0 END), 0) AS seven_tokens
		FROM   usage_events
		WHERE  user_sub = ? AND kind = 'claude_proxy' AND ts >= ?`, w),
		fiveBound, sevenBound, userSub, scanBound).Scan(&row).Error; err != nil {
		return status, err
	}
	status.FiveHourUsed = row.FiveTokens
	status.SevenDayUsed = row.SevenTokens
	return status, nil
}

// ClaudePoolCommit opens or rolls forward userSub's pool window anchors as of
// `now`. Call this ONLY when a claude_proxy charge is about to be recorded
// (allowed && !DryRun) — never from a dry-run gate check, and never on a
// denied charge; a rejected, unrecorded request must not be able to start or
// roll someone's clock.
//
// Each anchor column is only overwritten if the STORED anchor's window has
// already fully elapsed as of `now`; otherwise the upsert is a no-op
// re-affirming the existing (still-open) anchor. That makes concurrent
// commits near a boundary converge safely without row locking — whichever
// commits first wins, the other harmlessly re-affirms the fresh anchor.
func ClaudePoolCommit(db *gorm.DB, userSub string, now time.Time) error {
	return db.Exec(`
		INSERT INTO claude_pool_windows (user_sub, five_hour_anchor, seven_day_anchor, updated_at)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
		  five_hour_anchor = IF(five_hour_anchor + INTERVAL ? SECOND <= VALUES(five_hour_anchor), VALUES(five_hour_anchor), five_hour_anchor),
		  seven_day_anchor = IF(seven_day_anchor + INTERVAL 7 DAY <= VALUES(seven_day_anchor), VALUES(seven_day_anchor), seven_day_anchor),
		  updated_at       = VALUES(updated_at)`,
		userSub, now, now, now, int(ClaudePoolShortWindow().Seconds())).Error
}

// CheckAndCharge enforces the four daily caps and (on allowed && !DryRun)
// writes a usage_events row. Unknown kinds are recorded but ungated.
func CheckAndCharge(db *gorm.DB, req ChargeReq) (ChargeRes, error) {
	now := time.Now().UTC()
	limits := DefaultLimits()
	totals, err := FetchTodayTotals(db, req.UserSub)
	if err != nil {
		return ChargeRes{}, err
	}

	after := totals
	deny := ""
	var fivePct, sevenPct *float64
	var fiveReset, sevenReset time.Time
	switch req.Kind {
	case "claude_proxy":
		// Fixed 5h/7d windows (not midnight-daily) — mirrors the Anthropic
		// account quota shape the pool itself is subject to.
		//
		// Every named model — Claude or non-Claude — runs this cap check against the
		// SAME shared 5h/7d window. Non-Anthropic models (deepseek-v4-flash,
		// kimi-k3, z-ai/glm-5.2) used to bypass here entirely (an explicit
		// `if !poolCapApplies(req.Model) { break }`), so a user could draw
		// unlimited LLM usage at /lum.id/code. poolCapApplies is now constant-true
		// precisely so no named model skips this gate; the historical `""` dry-run
		// bug (see quota_gate_test.go) is preserved by the fact that the "" gate
		// request runs THIS same path, not a bypass.
		//
		// Role-tiered: a student on the shared pool and an operator doing the
		// heaviest work on it should not get the same budget. Defaults to the
		// global caps unless LUMID_QUOTA_CLAUDE_USER_* is set.
		cap5, cap7 := ClaudePoolLimitsForUser(db, req.UserSub)
		status, werr := ClaudePoolUsage(db, req.UserSub, now)
		if werr != nil {
			return ChargeRes{}, werr
		}
		used5, used7 := status.FiveHourUsed, status.SevenDayUsed
		fiveReset, sevenReset = status.FiveHourReset, status.SevenDayReset
		// Weighted by the SAME formula as the stored history this is being added
		// to. Note the pre-request gate is a dry run with model="" and zero
		// tokens, so this is 0 there either way; it matters on the real
		// post-response charge.
		tok := ClaudeWeightedTokens(req.Model, req.InputTokens, req.OutputTokens,
			req.CacheReadTokens, req.CacheCreationTokens, req.CacheCreation1hTokens)
		if used5+tok > cap5 {
			deny = "quota_exceeded_claude_5h"
		} else if used7+tok > cap7 {
			deny = "quota_exceeded_claude_7d"
		}
		p5 := float64(used5+tok) / float64(cap5) * 100
		p7 := float64(used7+tok) / float64(cap7) * 100
		fivePct, sevenPct = &p5, &p7
	case "cycle_start":
		n := req.Count
		if n <= 0 {
			n = 1
		}
		after.Cycles += n
		if after.Cycles > limits.CyclesDaily {
			deny = "quota_exceeded_cycles_daily"
		}
	case "cycle_llm":
		tok := req.InputTokens + req.OutputTokens
		after.LLMTokens += tok
		if after.LLMTokens > limits.LLMTokensDaily {
			deny = "quota_exceeded_llm_tokens_daily"
		}
	case "external_api":
		n := req.Count
		if n <= 0 {
			n = 1
		}
		switch req.Endpoint {
		case "gmail.send":
			after.GmailSends += n
			if after.GmailSends > limits.GmailSendsDaily {
				deny = "quota_exceeded_gmail_daily"
			}
		case "slack.post":
			after.SlackPosts += n
			if after.SlackPosts > limits.SlackPostsDaily {
				deny = "quota_exceeded_slack_daily"
			}
		}
	}

	res := ChargeRes{
		Allowed:       deny == "",
		DenyReason:    deny,
		Limits:        limits,
		ResetAt:       NextResetAt().Format(time.RFC3339),
		FiveHourPct:   fivePct,
		SevenDayPct:   sevenPct,
		FiveHourReset: formatPoolReset(fiveReset),
		SevenDayReset: formatPoolReset(sevenReset),
	}
	// OVERSPEND: a non-dry-run claude_proxy charge reporting tokens Anthropic has
	// ALREADY served. It must be recorded even though it breaches the cap.
	//
	// The distinction is authorization vs accounting. For every other kind
	// (cycle_start, cycle_llm, external_api) CheckAndCharge is called BEFORE the
	// work happens, so a denial means it never happened and recording nothing is
	// right. claude-proxy is the opposite: it gates on a DRY RUN carrying zero
	// tokens, then charges for real once the response has been served. By then
	// the tokens are spent and a denial cannot un-spend them.
	//
	// Dropping that record was a self-perpetuating deadlock that made the cap
	// unenforceable:
	//
	//   pre-gate:  used(4,998,408) + 0       > cap(5,000,000)?  no  -> ALLOW
	//   request runs, really burns ~300k
	//   post-charge: used(4,998,408) + 300k  > cap?             yes -> deny,
	//                                                            NOT recorded
	//   counter still 4,998,408 -> next request allowed -> forever.
	//
	// The counter froze one request short of the cap and stayed there while the
	// user consumed without limit. Observed live 2026-08-12: two users pinned at
	// 4,998,408 and 4,982,885 against a 5,000,000 cap, still serving traffic,
	// zero 429s ever issued. The cap could only deny someone ALREADY over it
	// (i.e. who crossed while it was set higher) — it could never push anyone
	// over itself, so for everyone else it was a no-op.
	//
	// Recording an overspend is also what makes the NEXT dry-run gate deny: the
	// stored total finally exceeds the cap. res.Allowed stays false either way.
	// poolCapApplies is constant-true, so it is omitted (a claude_proxy overspend
	// is recorded for any model, Claude or non-Claude).
	overspend := deny != "" && !req.DryRun && req.Kind == "claude_proxy" &&
		(req.InputTokens > 0 || req.OutputTokens > 0)

	if !res.Allowed {
		// Report current state, not the would-be after-state.
		res.Today = totals
		// A REFUSED request (the dry-run gate, or any other kind) must not write
		// an event or start anyone's clock — it never consumed anything.
		if !overspend {
			return res, nil
		}
		// An overspend falls through to be recorded. Its tokens were real.
	} else {
		res.Today = after
	}

	if req.DryRun {
		return res, nil
	}
	ev := models.UsageEvent{
		UserSub:               req.UserSub,
		Ts:                    now,
		Kind:                  req.Kind,
		Endpoint:              req.Endpoint,
		Model:                 req.Model,
		InputTokens:           req.InputTokens,
		OutputTokens:          req.OutputTokens,
		CacheReadTokens:       req.CacheReadTokens,
		CacheCreationTokens:   req.CacheCreationTokens,
		CacheCreation1hTokens: req.CacheCreation1hTokens,
		CostCents:             req.CostCents,
		Meta:                  req.Meta,
	}
	if err := db.Create(&ev).Error; err != nil {
		return ChargeRes{}, err
	}

	if req.Kind == "claude_proxy" {
		if cerr := ClaudePoolCommit(db, req.UserSub, now); cerr != nil {
			return ChargeRes{}, cerr
		}
		status, serr := ClaudePoolUsage(db, req.UserSub, now)
		if serr != nil {
			return ChargeRes{}, serr
		}
		res.FiveHourReset = formatPoolReset(status.FiveHourReset)
		res.SevenDayReset = formatPoolReset(status.SevenDayReset)
	}
	return res, nil
}
