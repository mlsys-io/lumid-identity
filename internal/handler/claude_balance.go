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
// objective among accounts that have room. The cap is a target: when the pool is
// too small it degrades to an even spread rather than leaving anyone unplaced.
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
	"fmt"
	"log"
	"sort"
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
	for _, r := range rows {
		if r.RevokedAt == nil {
			out = append(out, r.Email)
		}
	}
	sort.Strings(out) // deterministic across replicas
	return out, nil
}

// effectiveUserCap resolves the configured per-account user ceiling against what
// the pool can physically hold.
//
// The cap is a TARGET, not a limit. If it were enforced strictly, a pool with
// fewer than ceil(users/cap) accounts would have users it could not place at
// all — and an unplaced user still needs Claude access, so refusing to place is
// never the right answer. When the cap is infeasible we fall back to the
// tightest ceiling that IS feasible, ceil(users/accounts), which still bounds
// the fan-out (it is what forces an even split instead of letting pure load
// balancing pile 6-7 people onto one subscription) and leaves the caller to
// report the shortfall.
//
// Returns 0 when the cap is disabled or there is nothing to bound.
func effectiveUserCap(nUsers, nAccounts, configured int) int {
	if configured <= 0 || nAccounts <= 0 || nUsers <= 0 {
		return 0
	}
	if nUsers <= nAccounts*configured {
		return configured
	}
	return (nUsers + nAccounts - 1) / nAccounts // ceil
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
			// Every account is at the cap. Availability wins over the target:
			// place on the least-loaded account rather than leaving the user
			// homeless (which would drop them to the HRW fallback at lease time).
			best = accounts[0]
			for _, a := range accounts[1:] {
				if lighter(a, best) {
					best = a
				}
			}
		}
		out[u.UserSub] = best
		tot[best] += u.Tokens
		cnt[best]++
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
		loads, err := loadByUser()
		if err != nil {
			return err
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

		configured := common.ClaudeMaxUsersPerAccount()
		maxPer := effectiveUserCap(len(loads), len(accounts), configured)
		if configured > 0 && maxPer > configured {
			// The pool cannot honour the target. Say so with the number of
			// accounts it would take, because that is the actual remediation —
			// the cap is a proxy for "one subscription per human", and no
			// amount of rebalancing substitutes for having enough accounts.
			need := (len(loads) + configured - 1) / configured
			log.Printf("claude-pool: %d users across %d accounts cannot meet the %d-user/account target; "+
				"spreading %d per account instead. %d accounts would be needed.",
				len(loads), len(accounts), configured, maxPer, need)
		}

		ideal := computeAssignment(loads, accounts, maxPer)
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
