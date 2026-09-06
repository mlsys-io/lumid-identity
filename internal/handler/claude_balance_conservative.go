package handler

// Conservative-mode placement for a ClaudePool.
//
// Distributed mode (claude_balance.go) balances LOAD across every servable
// account in the pool simultaneously. Conservative mode does the opposite on
// purpose: concentrate all traffic on ONE account, in a fixed order, and only
// advance to the next once the current one is genuinely unhealthy or quota-
// exhausted — "use the subscriptions one by one" rather than spreading them.
//
// This file only computes `ideal` (which account each user SHOULD be on).
// Everything downstream — hysteresis, mid-session deferral, evacuation,
// persistence — is the SAME placementWrites/EnsureAssignments pipeline
// distributed mode uses; conservative mode is a different `ideal`, not a
// parallel decision path.

import (
	"sort"
	"strings"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// conservativeOrder returns poolID's accounts in CONSERVATIVE fill order:
// ClaudeQuotaToken.PoolSortOrder ascending, tied broken by CreatedAt
// ascending. An untouched pool (every account at the default PoolSortOrder
// of 0) therefore orders itself by add-order for free — no admin input
// needed to get a sane default.
func conservativeOrder(poolID string) ([]string, error) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Where("pool_id = ? AND revoked_at IS NULL", poolID).
		Order("pool_sort_order ASC, created_at ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Email)
	}
	// SINGLE-FIELD-BOX POOLS get a better order than add-order. See
	// expiringFirstOrder; falls through to the fixed order otherwise.
	if reordered, ok := expiringFirstOrder(rows); ok {
		return reordered, nil
	}
	return out, nil
}

// expiringFirstOrder re-orders a conservative pool's accounts USE-IT-OR-LOSE-IT:
// the account whose 7d window resets soonest goes first, 5h reset breaking ties.
//
// WHY ONLY FOR ONE-BOX POOLS. The fixed add-order this replaces is not
// arbitrary — where a pool's accounts sit on DIFFERENT field boxes, reordering
// by reset time moves egress between boxes (and countries) as those times
// drift, which is exactly the "one machine running several clients" shape the
// relay design exists to avoid. When every account shares ONE box they already
// share an egress IP and client fingerprint, so that objection disappears and
// only the upside is left: an unused weekly allocation is WIPED at its reset
// and can never be reclaimed, so the nearest-due budget should be spent first.
// Same reasoning the distributed-mode sortKey already documents.
//
// "Same box" means the same NON-EMPTY label. All-empty is NOT one box: an
// unlabeled account is adopted onto a box deterministically by account hash
// (see pickRelay/relayPinHome in claude-proxy), so two unlabeled accounts
// generally egress from DIFFERENT boxes — treating them as co-located is the
// one reading of "same field box" that would silently be wrong.
//
// Accounts with no snapshot sort LAST rather than first: an unknown reset is
// not evidence of an imminent one, and the distributed sortKey makes the same
// call ("no snapshot → probe last").
//
// Returns ok=false when the rule does not apply, leaving the caller's fixed
// order untouched.
func expiringFirstOrder(rows []models.ClaudeQuotaToken) ([]string, bool) {
	if len(rows) < 2 {
		return nil, false // nothing to reorder
	}
	label := strings.TrimSpace(rows[0].Label)
	if label == "" {
		return nil, false
	}
	emails := make([]string, 0, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.Label) != label {
			return nil, false // mixed boxes — keep the fixed order
		}
		emails = append(emails, r.Email)
	}

	// Latest snapshot per account. Ordered ASC so the last write per email wins.
	var snaps []models.ClaudeQuotaSnapshot
	if err := common.DB.Where("email IN ?", emails).Order("ts ASC").Find(&snaps).Error; err != nil {
		return nil, false // a lookup failure must not reshuffle live routing
	}
	latest := make(map[string]models.ClaudeQuotaSnapshot, len(snaps))
	for _, s := range snaps {
		latest[s.Email] = s
	}

	// Stable base: preserve the incoming fixed order as the final tiebreak, so
	// two accounts sharing a reset instant do not swap places run to run.
	pos := make(map[string]int, len(emails))
	for i, e := range emails {
		pos[e] = i
	}
	out := append([]string(nil), emails...)
	sort.SliceStable(out, func(i, j int) bool {
		si, oki := latest[out[i]]
		sj, okj := latest[out[j]]
		switch {
		case !oki && !okj:
			return pos[out[i]] < pos[out[j]]
		case !oki:
			return false // unknown sorts last
		case !okj:
			return true
		}
		if !si.SevenDayReset.Equal(sj.SevenDayReset) {
			return si.SevenDayReset.Before(sj.SevenDayReset)
		}
		if !si.FiveHourReset.Equal(sj.FiveHourReset) {
			return si.FiveHourReset.Before(sj.FiveHourReset)
		}
		return pos[out[i]] < pos[out[j]]
	})
	return out, true
}

// conservativeCeiling resolves the anti-concentration safety backstop for
// pool: its own ConservativeCeiling override if set, else the env-tunable
// global default (common.ClaudeConservativeCeiling, default 6). This is
// INDEPENDENT of LUMID_CLAUDE_MAX_USERS_PER_ACCOUNT, which only governs
// distributed-mode pools' hard headcount gate.
//
// Three-way sentinel, not two — ConservativeCeiling's zero value (every
// pool's default at creation) means "inherit the global default," which
// collides with "explicitly disable the backstop" if 0 meant both. A
// negative value (by convention -1, validated in AdminClaudePoolCreate/
// AdminClaudePoolUpdate) means the LATTER: an admin who deliberately wants
// unlimited intake for this one pool, distinct from "never configured."
// Without this distinction, PATCHing a pool to {conservative_ceiling: 0}
// intending "no limit" silently fell back to the global default instead.
func conservativeCeiling(pool models.ClaudePool) int {
	switch {
	case pool.ConservativeCeiling > 0:
		return pool.ConservativeCeiling
	case pool.ConservativeCeiling < 0:
		return 0 // explicitly unlimited — computeConservativeAssignment treats <=0 as disabled
	default:
		return common.ClaudeConservativeCeiling()
	}
}

// computeConservativeAssignment fills `ordered` accounts IN ORDER rather than
// balancing load, and is STICKY: an existing placement on a still-servable,
// non-draining account is NEVER recomputed away purely because fill order
// changed underneath it — a user who has already been placed keeps their
// account for as long as it keeps working, exactly like distributed mode's
// hysteresis, just expressed differently because there is no load objective
// to re-optimise against.
//
// `ceiling` is consulted ONLY when placing a user with NO usable existing
// slot (a newcomer, or someone whose account just became unhealthy) — an
// anti-concentration backstop on INTAKE, never a trigger to evict an
// already-seated user. This matches "roll to the next account only on
// exhaustion, not on headcount" while still bounding how many new arrivals
// can pile onto the current account before intake itself defers to the next
// one in line. A ceiling of 0 disables the backstop (unlimited intake per
// account, rolling purely on health/exhaustion).
func computeConservativeAssignment(
	loads []userLoad, ordered []string, cur map[string]string,
	servable, draining map[string]bool, ceiling int,
) map[string]string {
	out := make(map[string]string, len(loads))
	if len(ordered) == 0 {
		return out
	}
	cnt := make(map[string]int, len(ordered))
	var newcomers []userLoad
	for _, u := range loads {
		if have, placed := cur[u.UserSub]; placed && servable[have] && !draining[have] {
			out[u.UserSub] = have // sticky — incumbent keeps their seat
			cnt[have]++
			continue
		}
		newcomers = append(newcomers, u)
	}
	// Deterministic order for newcomers — this list isn't a load objective
	// (there is none in this mode), just a stable tie-break so re-running the
	// pass twice with the same inputs produces the same placement.
	sort.Slice(newcomers, func(i, j int) bool { return newcomers[i].UserSub < newcomers[j].UserSub })
	for _, u := range newcomers {
		for _, a := range ordered {
			if !servable[a] || draining[a] {
				continue // exhaustion/drain — roll to the next account in order
			}
			if ceiling > 0 && cnt[a] >= ceiling {
				continue // safety backstop on intake, not the fill signal
			}
			out[u.UserSub] = a
			cnt[a]++
			break
		}
		// No account found for this newcomer -> left unplaced, same HRW-fallback
		// contract distributed mode's cap gate already has: still served, just
		// without a stable egress box, at lease time.
	}
	return out
}
