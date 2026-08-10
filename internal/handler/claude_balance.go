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
)

var lastAssignmentRun time.Time

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
func loadByUser() ([]userLoad, error) {
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
		GROUP  BY ue.user_sub`, time.Now().UTC().Add(-7*24*time.Hour)).Scan(&rows).Error
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
func pruneIdleAssignments(idle time.Duration) (int, error) {
	if idle <= 0 {
		return 0, nil // reclamation disabled
	}
	cutoff := time.Now().UTC().Add(-idle)
	var rows []models.ClaudeUserAssignment
	if err := common.DB.Find(&rows).Error; err != nil {
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
		if err := common.DB.Where("user_sub = ?", r.UserSub).
			Delete(&models.ClaudeUserAssignment{}).Error; err == nil {
			freed++
			log.Printf("claude-pool: released %s's slot on %s — idle since %v", r.UserSub, r.Account, r.AssignedAt.UTC().Format(time.RFC3339))
		}
	}
	return freed, nil
}

// assignableAccounts returns pooled accounts eligible to host users: present,
// not quarantined. Quota state is deliberately NOT consulted here — that is a
// moment-to-moment concern handled at lease time, whereas this is a durable
// placement decision.
func assignableAccounts() ([]string, error) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Find(&rows).Error; err != nil {
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
func logPlacement(loads []userLoad, accounts []string, ideal map[string]string, configured int) {
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
		parts = append(parts, fmt.Sprintf("%s=%d", accountWithLabel(a), per[a]))
	}
	unplaced := len(loads) - len(ideal)
	msg := fmt.Sprintf("claude-pool: placed %d/%d users across %d accounts (cap %d/account): %s",
		len(ideal), len(loads), len(accounts), configured, strings.Join(parts, " "))
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

func EnsureAssignments(force bool) error {
	if !force && time.Since(lastAssignmentRun) < assignmentTTL {
		return nil
	}
	return common.DB.Connection(func(tx *gorm.DB) error {
		var got int
		if err := tx.Raw("SELECT GET_LOCK('claude_assign', 2)").Scan(&got).Error; err != nil || got != 1 {
			return nil // another replica is on it
		}
		defer tx.Exec("DO RELEASE_LOCK('claude_assign')")
		lastAssignmentRun = time.Now()

		accounts, err := assignableAccounts()
		if err != nil || len(accounts) == 0 {
			return err
		}
		// Reclaim dormant slots BEFORE reading `existing`, so freed slots are
		// available to this same placement pass rather than a later one.
		idle := common.ClaudeAssignmentIdle()
		if freed, perr := pruneIdleAssignments(idle); perr != nil {
			log.Printf("claude-pool: idle-slot reclamation failed: %v", perr)
		} else if freed > 0 {
			log.Printf("claude-pool: reclaimed %d idle slot(s)", freed)
		}
		loads, err := loadByUser()
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
			common.DB.Find(&surviving)
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
		common.DB.Find(&existing)
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

		configured := common.ClaudeMaxUsersPerAccount()
		maxPer := effectiveUserCap(len(loads), len(accounts), configured)

		ideal := computeAssignment(loads, accounts, maxPer)
		logPlacement(loads, accounts, ideal, configured)
		curSkew := skew(loads, accounts, cur)
		sharingTooWide := overCap(cur, valid, maxPer)
		rebalance := curSkew > rebalanceSkewFactor || sharingTooWide

		var writes []models.ClaudeUserAssignment
		load := make(map[string]int64, len(loads))
		for _, u := range loads {
			load[u.UserSub] = u.Tokens
		}
		for sub, want := range ideal {
			have, placed := cur[sub]
			reason := ""
			switch {
			case !placed:
				reason = "initial"
			case !valid[have]:
				reason = "account-gone"
			case rebalance && have != want:
				// Distinguish the two triggers: an operator reading the table
				// should be able to tell a load correction from a deliberate
				// de-sharing, since only the latter is about suspension risk.
				reason = "rebalance"
				if sharingTooWide && curSkew <= rebalanceSkewFactor {
					reason = "user-cap"
				}
			default:
				continue // keep the existing origin
			}
			writes = append(writes, models.ClaudeUserAssignment{
				UserSub: sub, Account: want, Load7d: load[sub], Reason: reason,
			})
		}
		if len(writes) == 0 {
			return nil
		}
		if err := common.DB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_sub"}},
			DoUpdates: clause.AssignmentColumns([]string{"account", "load_7d", "assigned_at", "reason"}),
		}).Create(&writes).Error; err != nil {
			return fmt.Errorf("persist assignments: %w", err)
		}
		return nil
	})
}

// assignedAccount returns a user's pinned account, if any.
func assignedAccount(userSub string) string {
	if userSub == "" {
		return ""
	}
	var row models.ClaudeUserAssignment
	if common.DB.Where("user_sub = ?", userSub).First(&row).Error != nil {
		return ""
	}
	return row.Account
}
