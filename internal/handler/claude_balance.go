package handler

// Balanced user->account assignment for the Claude pool.
//
// Supersedes per-user rendezvous hashing. HRW was stable but distributed users
// RANDOMLY and was blind to load: on the live pool it produced 3/1/1 across
// three accounts, with the single heaviest user (12.6M tokens/7d) alone on one
// box outweighing the other four combined.
//
// Placement now balances LOAD first and user COUNT as a tie-break, via greedy
// LPT (longest-processing-time): rank users by 7d tokens descending, and give
// each to the account carrying the least so far. LPT is the standard heuristic
// here and lands within 4/3 of optimal, which is far more than good enough for
// single-digit accounts.
//
// A USER-COUNT CAP bounds the other axis. Load balancing alone equalises the
// wrong quantity for this risk: it will happily home seven unrelated people on
// one consumer subscription so long as their combined draw matches the others,
// and that concentration — not volume — is what got accounts suspended on
// 2026-08-04 and again on 2026-08-09. computeAssignment therefore refuses to
// exceed effectiveUserCap users per account, with load still the primary
// objective among accounts that have room. The cap is a GATE (2026-08-10): when
// the pool is too small it does NOT widen — the surplus is left unhomed and
// falls back to HRW at lease time, so the shortfall stays visible instead of
// being absorbed by over-sharing a subscription.
//
// HYSTERESIS is the important part. The assignment IS a user's public egress
// IP, so churning it would defeat the field boxes. An existing placement is
// therefore KEPT unless the pool is clearly skewed — only when the busiest
// account carries more than rebalanceSkewFactor x the least does anyone move.
// Quiet drift is tolerated on purpose; only genuine imbalance is corrected.
// An over-cap distribution is the one other thing that forces a move, since it
// can sit within the skew threshold indefinitely and would otherwise be frozen
// in place by that same hysteresis.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	// How long a computed assignment is trusted before it is reconsidered.
	assignmentTTL = 10 * time.Minute
	// Only rebalance when busiest/least exceeds this. Below it, an uneven but
	// working distribution is left alone rather than migrating people's origins
	// for a marginal gain.
	rebalanceSkewFactor = 2.0
	// Accounts with no load still need a denominator for the skew ratio.
	skewFloor = 1.0
	// How long after a user's last pooled request they are treated as mid-session
	// and shielded from DISCRETIONARY moves. Long enough to span the pauses inside
	// a real conversation (reading a diff, running a build), short enough that the
	// user cap is still enforced within an hour of a busy pool going quiet.
	activeSessionWindow = 30 * time.Minute
)

// lastAssignmentRun is keyed per pool so one pool's TTL/skip decision never
// affects another's — see EnsureAssignments.
var (
	lastAssignmentRunMu sync.Mutex
	lastAssignmentRun   = map[string]time.Time{}
)

// userLoad is one user's 7d QUOTA DRAW, expressed in sonnet-equivalent tokens —
// the quantity being balanced. Not raw tokens: see loadByUser.
type userLoad struct {
	UserSub string
	Tokens  int64
}

// loadByUser reads each user's 7d draw on the Claude subscription pool.
//
// Two corrections over raw token volume, both measured live 2026-08-09:
//
//  1. MODEL WEIGHT. A subscription's 7-day allowance is model-weighted — Opus
//     costs roughly 5× Sonnet per token. Balancing raw tokens therefore
//     equalises the wrong quantity. Observed: the three accounts were balanced
//     to within 0.33% on raw tokens (21.43M / 21.45M / 21.38M), yet `ytb` was
//     tracking to ~95% of its weekly quota while `i` tracked to ~45%, because
//     ytb's users run Opus (8,037 Opus turns vs 5,477 Sonnet) and i's run
//     Sonnet (19,286 vs 830). Perfectly balanced tokens, badly imbalanced quota.
//
//  2. NON-CLAUDE MODELS DRAW NOTHING. kimi-k3, glm and other OpenAI-compat
//     models are served by lumid-llm/OpenRouter and never touch the pooled
//     subscription, so they must not influence placement. They also skew badly
//     when counted — kimi averages ~57k tokens/turn, an order of magnitude above
//     Claude traffic.
//
// Weights are relative, so only their ratio matters; the result stays in
// sonnet-equivalent tokens to keep load_7d human-readable on the /code panel.
//
// Scoped to poolID's MEMBERS (claude_pool_members), not the whole user base —
// each pool balances only the load of the users who may actually be placed
// on its own accounts. ACCEPTED APPROXIMATION for a user in more than one
// pool: usage_events carries no account/pool column, so their TOTAL 7d draw
// is counted toward balance in EVERY pool they belong to, not the share
// attributable to this pool specifically. This biases placement
// conservatively (a multi-pool user reads "heavier" than their true per-pool
// share, never lighter) rather than unsafely; exact attribution would need
// usage_events to record which account served each request.
func loadByUser(poolID string) ([]userLoad, error) {
	var rows []userLoad
	err := common.DB.Raw(`
		SELECT ue.user_sub AS user_sub,
		       CAST(COALESCE(SUM(
		           (ue.input_tokens + ue.output_tokens) *
		           CASE
		               WHEN ue.model LIKE 'claude-opus%'  THEN 5.0
		               WHEN ue.model LIKE 'claude-haiku%' THEN 0.2
		               WHEN ue.model LIKE 'claude-%'      THEN 1.0
		               ELSE 0.0
		           END
		       ), 0) AS SIGNED) AS tokens
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.ts >= ?
		  AND  ue.user_sub IN (SELECT user_sub FROM claude_pool_members WHERE pool_id = ?)
		GROUP  BY ue.user_sub`, time.Now().UTC().Add(-7*24*time.Hour), poolID).Scan(&rows).Error
	return rows, err
}

// activeSubsSince returns the users who have drawn on the pool since `cutoff`.
//
// MEMBERSHIP and WEIGHT are different questions and must use different windows.
// loadByUser's 7d window answers "how much does this user draw" — the right
// horizon for a balance objective. It is the WRONG horizon for "does this user
// still deserve a slot": using it meant pruneIdleAssignments deleted an idle
// user and the very next placement re-homed them from the same 7d list, so the
// reclamation was a no-op that only churned egress IPs.
func activeSubsSince(cutoff time.Time) (map[string]bool, error) {
	var subs []string
	if err := common.DB.Raw(
		`SELECT DISTINCT user_sub FROM usage_events WHERE kind = 'claude_proxy' AND ts >= ?`,
		cutoff,
	).Scan(&subs).Error; err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(subs))
	for _, s := range subs {
		out[s] = true
	}
	return out, nil
}

// pruneIdleAssignments releases slots held by users who have not touched the
// pool within the idle window, and reports how many it freed.
//
// This is the only code path that deletes a ClaudeUserAssignment. Without it
// the pool is monotonic: placement deliberately re-adds quiet homed users (see
// placementPopulation) so the cap counts them, which is correct for accounting
// but means a single turn months ago holds a subscription slot forever. That
// was harmless while the cap was a soft target — it simply widened — but under
// a hard gate a dormant user blocks an active one from ever being homed.
//
// Grace: a user placed within the window keeps their slot even with no traffic
// yet, so a freshly-added human is never evicted before they have had a chance
// to use the pool.
//
//nolint:gocyclo
func pruneIdleAssignments(poolID string, idle time.Duration) (int, error) {
	if idle <= 0 {
		return 0, nil // reclamation disabled
	}
	cutoff := time.Now().UTC().Add(-idle)
	var rows []models.ClaudeUserAssignment
	if err := common.DB.Where("pool_id = ?", poolID).Find(&rows).Error; err != nil {
		return 0, err
	}
	freed := 0
	for _, r := range rows {
		if r.AssignedAt.After(cutoff) {
			continue // placed recently — grace period
		}
		var last sql.NullTime
		if err := common.DB.Raw(
			`SELECT MAX(ts) FROM usage_events WHERE kind = 'claude_proxy' AND user_sub = ?`,
			r.UserSub,
		).Scan(&last).Error; err != nil {
			continue // a lookup failure must never evict
		}
		if last.Valid && last.Time.After(cutoff) {
			continue // active within the window
		}
		if err := common.DB.Where("pool_id = ? AND user_sub = ?", poolID, r.UserSub).
			Delete(&models.ClaudeUserAssignment{}).Error; err == nil {
			freed++
			log.Printf("claude-pool[%s]: released %s's slot on %s — idle since %v", poolID, r.UserSub, r.Account, r.AssignedAt.UTC().Format(time.RFC3339))
		}
	}
	return freed, nil
}

// assignableAccounts returns poolID's accounts eligible to host users:
// present, not quarantined. Quota state is deliberately NOT consulted here —
// that is a moment-to-moment concern handled at lease time, whereas this is a
// durable placement decision. Scoped to ONE pool: an account belongs to
// exactly one ClaudePool (ClaudeQuotaToken.PoolID), so this is the query that
// actually partitions the account table between pools.
func assignableAccounts(poolID string) ([]string, error) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Where("pool_id = ?", poolID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	labels := make(map[string]string, len(rows))
	for _, r := range rows {
		if r.RevokedAt == nil {
			out = append(out, r.Email)
			labels[r.Email] = r.Label
		}
	}
	sort.Strings(out) // deterministic across replicas
	setAccountLabels(labels)
	return out, nil
}

// accountQuota is the placement-relevant slice of an account's quota state.
// `known` is false when there is no snapshot or it has gone stale — in that
// case the account is treated as SERVABLE, because lease-time will re-probe it
// and a missing snapshot must never be read as "exhausted".
type accountQuota struct {
	pct5, pct7 float64
	known      bool
}

func (q accountQuota) exhausted() bool {
	return q.known && (q.pct5 >= nearExhaustCeiling || q.pct7 >= nearExhaustCeiling)
}

// accountQuotas reads the latest snapshot for each account.
func accountQuotas(accounts []string) map[string]accountQuota {
	out := make(map[string]accountQuota, len(accounts))
	for _, a := range accounts {
		var snap models.ClaudeQuotaSnapshot
		if err := common.DB.Where("email = ?", a).Order("ts DESC").First(&snap).Error; err != nil {
			out[a] = accountQuota{} // unknown -> servable
			continue
		}
		if time.Since(snap.Ts) >= quotaCacheTTL {
			out[a] = accountQuota{} // stale -> unknown -> servable
			continue
		}
		out[a] = accountQuota{pct5: snap.FiveHourPct, pct7: snap.SevenDayPct, known: true}
	}
	return out
}

// servableAccounts drops accounts the lease-time exhaustion valve would refuse.
//
// Placement used to be deliberately quota-blind, on the reasoning that quota is
// a moment-to-moment concern and placement is durable. That reasoning breaks at
// the ceiling: an account at >=nearExhaustCeiling is not momentarily busy, it is
// unselectable, and homing users there gives them a field box they can never
// egress from. Observed 2026-08-10: ytb(chicago) held 5 of 8 users and served 0
// of ~1770 requests, so all five silently spilled onto other accounts — the
// interleaved fan-out the whole design exists to prevent.
//
// If NOTHING is servable the full list is returned unchanged: leaving everyone
// unhomed would be strictly worse than an imperfect home.
func servableAccounts(accounts []string, q map[string]accountQuota) []string {
	out := make([]string, 0, len(accounts))
	for _, a := range accounts {
		if !q[a].exhausted() {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return accounts
	}
	return out
}

// drainingAccounts reports which of `accounts` an operator has PAUSED.
//
// Separate query rather than threading the rows down from assignableAccounts:
// that function returns emails only, and widening its contract to carry drain
// state would put a display concern into the one place that decides pool
// membership.
func drainingAccounts(accounts []string) map[string]bool {
	out := make(map[string]bool, len(accounts))
	if len(accounts) == 0 {
		return out
	}
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Where("email IN ? AND draining_since IS NOT NULL", accounts).
		Find(&rows).Error; err != nil {
		// Fail OPEN: on a query error nothing is treated as draining, so
		// placement behaves exactly as it did before this feature. The opposite
		// default would let a transient DB blip empty the target list and strand
		// the whole pool.
		log.Printf("claude-pool: draining lookup failed, treating no account as paused: %v", err)
		return out
	}
	for _, r := range rows {
		out[r.Email] = true
	}
	return out
}

// excludeDraining removes paused accounts from the placement TARGET list.
//
// Mirrors servableAccounts' "never return empty" contract, and for the same
// reason: an empty target list places nobody, which is an outage rather than a
// pause. The admin endpoint refuses to pause the last servable account, so this
// is a backstop for a pool that became fully paused some other way (every other
// account exhausted or quarantined while one was already draining).
func excludeDraining(canServe []string, draining map[string]bool) []string {
	if len(draining) == 0 {
		return canServe
	}
	out := make([]string, 0, len(canServe))
	for _, a := range canServe {
		if !draining[a] {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		log.Printf("claude-pool: every servable account is paused — ignoring the drain for placement, "+
			"since placing nobody is an outage, not a pause (accounts=%d)", len(canServe))
		return canServe
	}
	return out
}

// accountLabels caches account -> field-box Label purely so the placement log
// can print it. Without it, "account ytb has 5 users" and "field box chicago
// has no traffic" are two facts with no way to connect them — you cannot tell
// a silent box whose account is idle from a box no account is labelled for.
var (
	accountLabelMu sync.RWMutex
	accountLabels  = map[string]string{}
)

func setAccountLabels(m map[string]string) {
	accountLabelMu.Lock()
	accountLabels = m
	accountLabelMu.Unlock()
}

// accountWithLabel renders "ytb(chicago)", or bare "ytb" when unlabelled —
// and an unlabelled account is itself worth seeing, since its users egress
// through an adopted sibling box rather than one of their own.
func accountWithLabel(email string) string {
	accountLabelMu.RLock()
	l := accountLabels[email]
	accountLabelMu.RUnlock()
	if l == "" {
		return email
	}
	return email + "(" + l + ")"
}

// effectiveUserCap resolves the configured per-account user ceiling against what
// the pool can physically hold.
//
// The cap is a GATE. It used to be a target that widened to ceil(users/accounts)
// when the pool was undersized, which meant a subscription silently absorbed
// more humans than policy allowed — the exact concentration that got accounts
// suspended. It no longer widens. An unplaced user is NOT denied access:
// assignedAccount returns "" and the lease falls through to HRW, so they are
// served but without a stable egress box, which is the pressure that should
// drive adding an account.
//
// Returns 0 when the cap is disabled or there is nothing to bound.
func effectiveUserCap(nUsers, nAccounts, configured int) int {
	if configured <= 0 || nAccounts <= 0 || nUsers <= 0 {
		return 0
	}
	// The cap is a GATE (operator decision 2026-08-10). It no longer widens to
	// ceil(nUsers/nAccounts) when the pool is undersized — widening meant an
	// account silently absorbed more humans than the policy allowed, which is
	// the suspension risk the cap exists to bound. An undersized pool now
	// leaves the surplus unhomed (computeAssignment skips them) and they fall
	// back to HRW at lease time, so nobody loses access.
	return configured
}

// logPlacement reports the outcome of one placement pass: how many users
// landed where, and how many did not land at all.
//
// This replaces the old "cannot meet the N-user/account target" line, which
// became unreachable the moment the cap stopped widening (effectiveUserCap
// now returns `configured`, so maxPer > configured is never true). Losing it
// meant an undersized pool was completely silent: surplus users fell through
// to HRW with nothing written down, and "why is field box X getting no
// traffic?" had no answer in the logs. The per-account breakdown is the point
// — an account with 0 users is exactly why its field relay goes quiet.
func logPlacement(poolID string, loads []userLoad, accounts []string, ideal map[string]string, configured int, quotas map[string]accountQuota) {
	if len(loads) == 0 {
		return
	}
	per := make(map[string]int, len(accounts))
	for _, a := range accounts {
		per[a] = 0 // account with no users must still appear — that's the signal
	}
	for _, acct := range ideal {
		per[acct]++
	}
	parts := make([]string, 0, len(accounts))
	for _, a := range accounts { // accounts is already sorted, so this is stable
		// An exhausted account reads "=0 EXHAUSTED(7d=96%)" rather than a bare
		// zero, so a silent field box explains itself instead of looking like
		// an account nobody happened to be assigned to.
		suffix := ""
		if q := quotas[a]; q.exhausted() {
			suffix = fmt.Sprintf(" EXHAUSTED(5h=%.0f%% 7d=%.0f%%)", q.pct5, q.pct7)
		}
		parts = append(parts, fmt.Sprintf("%s=%d%s", accountWithLabel(a), per[a], suffix))
	}
	unplaced := len(loads) - len(ideal)
	msg := fmt.Sprintf("claude-pool[%s]: placed %d/%d users across %d accounts (cap %d/account): %s",
		poolID, len(ideal), len(loads), len(accounts), configured, strings.Join(parts, " "))
	if unplaced > 0 {
		// The remediation is more accounts, not more rebalancing — say so.
		need := len(loads)
		if configured > 0 {
			need = (len(loads) + configured - 1) / configured
		}
		msg += fmt.Sprintf("; %d unplaced -> HRW fallback (no stable egress box). %d accounts would home everyone.",
			unplaced, need)
	}
	log.Print(msg)
}

// computeAssignment runs greedy LPT over the given loads and accounts, refusing
// to home more than cap users on any one account (cap <= 0 disables that).
//
// Load remains the primary objective; the cap only removes full accounts from
// consideration. Because callers pass a cap from effectiveUserCap, capacity is
// guaranteed by the pigeonhole principle and the fallback below is unreachable
// in practice — it exists so a bad cap can never leave a user unplaced.
func computeAssignment(loads []userLoad, accounts []string, maxPer int) map[string]string {
	out := make(map[string]string, len(loads))
	if len(accounts) == 0 {
		return out
	}
	sort.Slice(loads, func(i, j int) bool {
		if loads[i].Tokens != loads[j].Tokens {
			return loads[i].Tokens > loads[j].Tokens // heaviest first
		}
		return loads[i].UserSub < loads[j].UserSub // stable
	})
	tot := make(map[string]int64, len(accounts))
	cnt := make(map[string]int, len(accounts))
	// lighter reports whether a beats the incumbent on load, then user count.
	lighter := func(a, best string) bool {
		return tot[a] < tot[best] || (tot[a] == tot[best] && cnt[a] < cnt[best])
	}
	for _, u := range loads {
		best := ""
		for _, a := range accounts {
			if maxPer > 0 && cnt[a] >= maxPer {
				continue
			}
			if best == "" || lighter(a, best) {
				best = a
			}
		}
		if best == "" {
			// Every account is at the cap. The cap is a GATE, so we do NOT
			// over-home: leave this user unplaced and let the lease fall back
			// to HRW rendezvous placement. They stay served; what they lose is
			// a stable egress box, which is the correct pressure — the fix is
			// another account, not a quietly over-shared subscription.
			continue
		}
		out[u.UserSub] = best
		tot[best] += u.Tokens
		cnt[best]++
	}
	return out
}

// placementInputs is everything the per-user placement decision reads. Grouped
// into a struct so the decision itself stays a pure function that a test can
// drive without a database.
type placementInputs struct {
	ideal    map[string]string // where each user should be
	cur      map[string]string // where each user is now
	load     map[string]int64
	valid    map[string]bool // account still in the pool at all
	servable map[string]bool // account can currently take traffic
	// draining — operator has PAUSED this account. Distinct from !servable on
	// purpose: a draining account CAN still take traffic (lease-time keeps
	// serving whoever is already homed on it), it just must not receive anyone
	// new. Conflating the two would send its active users down the evacuation
	// arm below and teleport live conversations, which is what a pause exists
	// to prevent.
	draining       map[string]bool
	active         map[string]bool // user made a pooled request very recently
	rebalance      bool
	sharingTooWide bool
	curSkew        float64
}

// placementWrites decides which users to move, and reports how many moves were
// deferred because the user is mid-conversation.
//
// A DISCRETIONARY move (load skew, user-cap de-sharing) changes which
// subscription serves someone RIGHT NOW, so a conversation already in flight
// continues on a different account: subscription B receives turn N of a session
// it has never seen, with no prompt-cache history, carrying content that
// references context it never got.
//
// Measured 2026-08-16: ac5 was added at 14:53:07; four minutes later a
// `rebalance` moved 2 users — including the heaviest at 218M — off ac7
// mid-conversation, and ac7 was dead at 15:06:59. The user cap that fired it
// exists to REDUCE suspension risk by bounding how many humans share one
// subscription, so satisfying it that way trades one suspension signal for
// another.
//
// Deferring is not cancelling: `sharingTooWide` stays true, EnsureAssignments
// re-runs on its 10-minute cadence, and the move lands as soon as the user goes
// quiet. Only the TIMING changes.
//
// `initial`, `account-gone` and `exhausted` are deliberately NOT deferred —
// those users have no stable origin to protect, because lease-time is already
// sending them elsewhere on every request. Moving them is placement catching up
// to reality, not new churn.
func placementWrites(poolID string, in placementInputs) ([]models.ClaudeUserAssignment, int) {
	var writes []models.ClaudeUserAssignment
	deferred := 0
	for sub, want := range in.ideal {
		have, placed := in.cur[sub]
		reason := ""
		switch {
		case !placed:
			reason = "initial"
		case !in.valid[have]:
			reason = "account-gone"
		// Both drain arms require in.servable[have]. A paused account that is ALSO
		// exhausted cannot serve anyone, so deferring there would strand the user
		// rather than protect them — the protection only makes sense while the
		// origin still works. Falling through lets the evacuation arms below move
		// them and, correctly, call it "exhausted": that is the more urgent fact
		// and the one with a different remedy.
		case in.draining[have] && in.servable[have] && in.active[sub]:
			// Operator paused this account and the user is mid-conversation.
			// Their origin STILL WORKS — lease-time keeps serving whoever is
			// already pinned here — so there is nothing to protect them from
			// and everything to lose by moving them. Deliberately not gated on
			// `rebalance`: a drain must progress on its own without switching
			// off hysteresis for the rest of the pool.
			//
			// (If activeUsers' query fails it returns an empty set by design,
			// so a DB hiccup degrades to moving everyone at once. Documented
			// at :499 — noted here because this is the one arm where that
			// degradation costs a split session rather than an egress change.)
			deferred++
			continue
		case in.draining[have] && in.servable[have] && have != want:
			// Idle on a paused account: this is the drain doing its work. `want`
			// can never name a draining account (they are not placement
			// targets), so the guard is structural — kept explicit so the
			// all-paused fallback cannot produce a self-move.
			reason = "drain"
		case in.rebalance && have != want && in.servable[have] && in.active[sub]:
			// Mid-session, and their current origin still works — leave them.
			deferred++
			continue
		case in.rebalance && have != want:
			// Distinguish the triggers: an operator reading the table should be
			// able to tell a load correction from a deliberate de-sharing from an
			// evacuation, since they mean different things — only de-sharing is
			// about suspension risk, and only evacuation says the old account had
			// run out of quota.
			reason = "rebalance"
			switch {
			case !in.servable[have]:
				reason = "exhausted"
			case in.sharingTooWide && in.curSkew <= rebalanceSkewFactor:
				reason = "user-cap"
			}
		default:
			continue // keep the existing origin
		}
		writes = append(writes, models.ClaudeUserAssignment{
			PoolID: poolID, UserSub: sub, Account: want, Load7d: in.load[sub], Reason: reason,
		})
	}
	return writes, deferred
}

// activeUsers reports who has made a pooled request within `window`, i.e. who is
// plausibly mid-conversation right now.
//
// On any query failure it returns an EMPTY set, not an error. The caller uses
// this only to defer discretionary moves, so an empty set degrades to the old
// always-move behaviour. Failing the other way — treating everyone as active
// because the lookup broke — would silently stop the balancer from ever placing
// anyone, which is a far worse failure than churn.
func activeUsers(window time.Duration) map[string]bool {
	active := map[string]bool{}
	if window <= 0 {
		return active
	}
	rows, err := common.DB.Raw(
		`SELECT user_sub FROM usage_events WHERE kind = 'claude_proxy' GROUP BY user_sub HAVING MAX(ts) > ?`,
		time.Now().UTC().Add(-window),
	).Rows()
	if err != nil {
		log.Printf("claude-pool: active-user lookup failed, treating all as idle: %v", err)
		return active
	}
	defer rows.Close()
	for rows.Next() {
		var sub string
		if rows.Scan(&sub) == nil {
			active[sub] = true
		}
	}
	return active
}

// placementPopulation is everyone the balancer must place: users with recent
// load, plus anyone already homed who has gone quiet.
//
// loadByUser only returns users active in the last 7 days, but the cap bounds
// distinct humans HOMED on a subscription — an idle user still occupies their
// account and still routes there the moment they come back. Two things break if
// the counted population is wider than the placeable one:
//
//   - the cap under-protects, because dormant sharers are invisible to it; and
//   - worse, overCap can then report a violation that computeAssignment is
//     structurally unable to fix, stranding `rebalance` at true forever. That
//     silently disables the skew hysteresis, and users' egress IPs start moving
//     on every load fluctuation — the exact churn this file exists to prevent.
//
// Quiet users join with zero load, so they do not perturb the load objective;
// they only occupy a slot. Users pinned to a removed account are included too,
// so a dormant user whose account disappeared still gets re-placed.
func placementPopulation(loads []userLoad, existing []models.ClaudeUserAssignment) []userLoad {
	seen := make(map[string]bool, len(loads)+len(existing))
	for _, u := range loads {
		seen[u.UserSub] = true
	}
	out := loads
	for _, e := range existing {
		if !seen[e.UserSub] {
			out = append(out, userLoad{UserSub: e.UserSub})
			seen[e.UserSub] = true
		}
	}
	return out
}

// overCap reports whether any account currently hosts more than cap users.
//
// Load skew alone is not enough to trigger a rebalance here: an over-shared
// account can sit perfectly within the skew threshold (that is exactly what
// balancing on load produces), and hysteresis would then keep the cap from ever
// taking effect on an existing pool.
func overCap(cur map[string]string, valid map[string]bool, maxPer int) bool {
	if maxPer <= 0 {
		return false
	}
	cnt := make(map[string]int, len(valid))
	for _, acct := range cur {
		if valid[acct] {
			cnt[acct]++
		}
	}
	for _, n := range cnt {
		if n > maxPer {
			return true
		}
	}
	return false
}

// skew reports busiest/least loaded across accounts under an assignment.
func skew(loads []userLoad, accounts []string, assign map[string]string) float64 {
	if len(accounts) < 2 {
		return 1
	}
	tot := make(map[string]float64, len(accounts))
	for _, a := range accounts {
		tot[a] = 0
	}
	for _, u := range loads {
		if a, ok := assign[u.UserSub]; ok {
			tot[a] += float64(u.Tokens)
		}
	}
	hi, lo := 0.0, -1.0
	for _, v := range tot {
		if v > hi {
			hi = v
		}
		if lo < 0 || v < lo {
			lo = v
		}
	}
	if lo < skewFloor {
		lo = skewFloor
	}
	return hi / lo
}

// EnsureAssignments refreshes the user->account table if it is stale.
//
// Applies three rules, in order:
//   - a user with no placement is placed immediately (no hysteresis to respect)
//   - a user whose account has disappeared or been quarantined is re-placed
//   - everyone else moves ONLY if the current distribution exceeds the skew
//     threshold, because moving a user changes their public egress IP
//
// Serialised across replicas by a MySQL named lock; a replica that cannot get
// the lock simply skips, since another is already doing the work.
// StartAssignmentReclaimLoop drives placement on a timer.
//
// EnsureAssignments' only other caller is the admin claude-quota endpoint, so
// before this loop existed reclamation ran only when a human happened to open
// lum.id/code. That was tolerable for a 30-day window; for a 1-hour one it is
// not — a slot freed at 02:00 would sit unusable until someone looked at a
// dashboard. The loop is multi-replica-safe for free: EnsureAssignments takes
// the `claude_assign` GET_LOCK and no-ops when another replica holds it.
//
// Cadence tracks the idle window (quarter of it, clamped) so the reclaim
// latency stays proportional to the policy rather than being a second
// independent number to keep in sync.
func StartAssignmentReclaimLoop() {
	interval := common.ClaudeAssignmentIdle() / 4
	if interval < 5*time.Minute {
		interval = 5 * time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}
	go func() {
		for {
			time.Sleep(interval)
			if err := EnsureAssignments(true); err != nil {
				log.Printf("claude-pool: scheduled reclaim/placement failed: %v", err)
			}
		}
	}()
	log.Printf("claude-pool: assignment reclaim loop every %v (idle window %v)", interval, common.ClaudeAssignmentIdle())
}

// EnsureAssignments iterates every non-deleted ClaudePool and runs placement
// for each independently. Errors are collected, not short-circuited — one
// broken pool must not stall every other pool's reclaim loop.
func EnsureAssignments(force bool) error {
	var pools []models.ClaudePool
	if err := common.DB.Find(&pools).Error; err != nil {
		return err
	}
	var errs []error
	for _, p := range pools {
		if err := ensurePoolAssignments(p, force); err != nil {
			errs = append(errs, fmt.Errorf("pool %s: %w", p.ID, err))
		}
	}
	return errors.Join(errs...)
}

// ensurePoolAssignments is EnsureAssignments' body for a single pool,
// serialised across replicas by a PER-POOL MySQL named lock
// ("claude_assign:<poolID>", bound as a parameter since pool.ID is
// admin-supplied) — a replica that cannot get the lock simply skips, since
// another is already doing the work, and pools never serialise against each
// other's locks.
func ensurePoolAssignments(pool models.ClaudePool, force bool) error {
	lastAssignmentRunMu.Lock()
	last := lastAssignmentRun[pool.ID]
	lastAssignmentRunMu.Unlock()
	if !force && time.Since(last) < assignmentTTL {
		return nil
	}
	poolID := pool.ID
	lockName := "claude_assign:" + poolID
	return common.DB.Connection(func(tx *gorm.DB) error {
		var got int
		if err := tx.Raw("SELECT GET_LOCK(?, 2)", lockName).Scan(&got).Error; err != nil || got != 1 {
			return nil // another replica is on it
		}
		defer tx.Exec("DO RELEASE_LOCK(?)", lockName)
		lastAssignmentRunMu.Lock()
		lastAssignmentRun[poolID] = time.Now()
		lastAssignmentRunMu.Unlock()

		accounts, err := assignableAccounts(poolID)
		if err != nil || len(accounts) == 0 {
			return err
		}
		// Reclaim dormant slots BEFORE reading `existing`, so freed slots are
		// available to this same placement pass rather than a later one.
		idle := common.ClaudeAssignmentIdle()
		if freed, perr := pruneIdleAssignments(poolID, idle); perr != nil {
			log.Printf("claude-pool[%s]: idle-slot reclamation failed: %v", poolID, perr)
		} else if freed > 0 {
			log.Printf("claude-pool[%s]: reclaimed %d idle slot(s)", poolID, freed)
		}
		loads, err := loadByUser(poolID)
		if err != nil {
			return err
		}
		// Placement membership must honour the SAME window the prune used.
		// loadByUser's 7d horizon is the load WEIGHT; using it for membership
		// would re-home the user we just reclaimed, in this very pass, making
		// reclamation a no-op that only churns egress IPs. Keep a user if they
		// are active within the idle window, or still homed (i.e. they survived
		// the prune, i.e. active or inside their grace period).
		if idle > 0 {
			active, aerr := activeSubsSince(time.Now().UTC().Add(-idle))
			if aerr != nil {
				return aerr // never silently fall back to the wider population
			}
			var surviving []models.ClaudeUserAssignment
			common.DB.Where("pool_id = ?", poolID).Find(&surviving)
			homed := make(map[string]bool, len(surviving))
			for _, s := range surviving {
				homed[s.UserSub] = true
			}
			kept := loads[:0]
			for _, u := range loads {
				if active[u.UserSub] || homed[u.UserSub] {
					kept = append(kept, u)
				}
			}
			loads = kept
		}
		var existing []models.ClaudeUserAssignment
		common.DB.Where("pool_id = ?", poolID).Find(&existing)
		cur := make(map[string]string, len(existing))
		for _, e := range existing {
			cur[e.UserSub] = e.Account
		}
		valid := make(map[string]bool, len(accounts))
		for _, a := range accounts {
			valid[a] = true
		}

		// Place everyone HOMED, not just everyone recently active — see
		// placementPopulation for why the two populations must match.
		loads = placementPopulation(loads, existing)

		// Place only onto accounts lease-time can actually select. `accounts`
		// stays the full list for reporting and for skew, so an exhausted
		// account still shows in the log — it just stops receiving people.
		quotas := accountQuotas(accounts)
		// TWO DIFFERENT QUESTIONS, DELIBERATELY TWO SETS.
		//
		//   canServe — "could this account carry traffic right now?"  Used to
		//              decide whether a mid-session user must be evacuated.
		//   targets  — "may someone be newly homed here?"  canServe minus the
		//              accounts an operator has paused.
		//
		// These were one set. Folding a paused account out of canServe as well
		// would send its ACTIVE users down placementWrites' evacuation arm and
		// move them mid-conversation — handing subscription B turn N of a
		// session it never saw, which is the 2026-08-16 ac7 failure and the
		// precise thing a pause is meant to avoid. A paused account keeps
		// serving whoever is already on it and simply stops accepting newcomers.
		canServe := servableAccounts(accounts, quotas)
		draining := drainingAccounts(accounts)
		targets := excludeDraining(canServe, draining)

		servable := make(map[string]bool, len(canServe))
		for _, a := range canServe {
			servable[a] = true
		}

		// DISTRIBUTED vs CONSERVATIVE only changes how `ideal` is computed —
		// everything downstream (hysteresis, evacuation, logging, persistence)
		// is identical for both modes.
		var (
			ideal      map[string]string
			configured int
			maxPer     int
		)
		if pool.Mode == models.ClaudePoolModeConservative {
			ordered, oerr := conservativeOrder(poolID)
			if oerr != nil {
				return oerr
			}
			ceiling := conservativeCeiling(pool)
			ideal = computeConservativeAssignment(loads, ordered, cur, servable, draining, ceiling)
			configured = ceiling // for logPlacement's display only
		} else {
			configured = common.ClaudeMaxUsersPerAccount()
			maxPer = effectiveUserCap(len(loads), len(targets), configured)
			ideal = computeAssignment(loads, targets, maxPer)
		}
		logPlacement(poolID, loads, accounts, ideal, configured, quotas)
		// Skew must ignore users still sitting on a paused account. skew() sums
		// into tot[assign[u]] for EVERY user, and Go creates the map entry even
		// for an account absent from `targets` — so a heavy user deferred on a
		// draining account would inflate `hi`, push curSkew past the factor and
		// flip the global rebalance the comment below is careful not to flip.
		curForSkew := make(map[string]string, len(cur))
		for sub, acct := range cur {
			if !draining[acct] {
				curForSkew[sub] = acct
			}
		}
		curSkew := skew(loads, targets, curForSkew)
		// overCap (the distributed-mode headcount gate) is meaningless in
		// conservative mode, which concentrates BY DESIGN and enforces its own
		// ceiling inside computeConservativeAssignment on INTAKE only, never as
		// a rebalance trigger — see that function's doc comment.
		sharingTooWide := pool.Mode != models.ClaudePoolModeConservative && overCap(cur, valid, maxPer)

		// Users sitting on an exhausted account are ALREADY displaced: the valve
		// sends every one of their requests to a sibling, so their egress IP is
		// unstable today. Moving them is not new churn — it is placement catching
		// up to what lease-time is doing anyway, and it restores a stable box.
		stranded := 0
		for _, acct := range cur {
			if !servable[acct] {
				stranded++
			}
		}
		// NOTE a drain deliberately does NOT appear here. `rebalance` is a
		// POOL-GLOBAL switch: turning it on disables skew hysteresis for every
		// user, so on each tick any unrelated idle person whose greedy-LPT
		// `ideal` drifted (loads are a rolling 7d window, so it drifts
		// constantly) gets re-homed and their public egress box changes. An
		// exhausted account can get away with that because it self-clears in
		// hours; a pause has no deadline, so it would churn the whole pool for
		// as long as the operator left it on. placementWrites handles drainees
		// directly instead, which touches only them.
		rebalance := curSkew > rebalanceSkewFactor || sharingTooWide || stranded > 0

		load := make(map[string]int64, len(loads))
		for _, u := range loads {
			load[u.UserSub] = u.Tokens
		}
		writes, deferred := placementWrites(poolID, placementInputs{
			ideal: ideal, cur: cur, load: load,
			valid: valid, servable: servable, draining: draining,
			active:         activeUsers(activeSessionWindow),
			rebalance:      rebalance,
			sharingTooWide: sharingTooWide,
			curSkew:        curSkew,
		})
		if deferred > 0 {
			// Visible on purpose: while this is non-zero the cap may read as
			// violated on the dashboard and that is the intended state, not a
			// stuck balancer. It clears on its own as those users go quiet.
			log.Printf("claude-pool[%s]: deferred %d mid-session move(s) to the next tick (skew %.2f, cap-wide %v)", poolID, deferred, curSkew, sharingTooWide)
		}
		if len(writes) == 0 {
			return nil
		}
		if err := common.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "pool_id"}, {Name: "user_sub"}},
			DoUpdates: clause.AssignmentColumns([]string{"account", "load_7d", "assigned_at", "reason"}),
		}).Create(&writes).Error; err != nil {
			return fmt.Errorf("persist assignments: %w", err)
		}
		return nil
	})
}

// assignedAccount returns a user's pinned account within poolID, if any. A
// user homed in a DIFFERENT pool has no row here — home accounts are per
// (pool, user), never shared across a multi-pool user's memberships.
func assignedAccount(poolID, userSub string) string {
	if userSub == "" {
		return ""
	}
	var row models.ClaudeUserAssignment
	if common.DB.Where("pool_id = ? AND user_sub = ?", poolID, userSub).First(&row).Error != nil {
		return ""
	}
	return row.Account
}
