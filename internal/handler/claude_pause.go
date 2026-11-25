package handler

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Operator pause (drain) helpers shared by the admin and pool-manager pause
// endpoints, the lease path, and the quota-report path.
//
// Measured 2026-11-25: ac5 was paused at 03:53:50Z. Placement moved its users
// within five minutes, but ac5 kept carrying 70-90% of requests for about
// 50 minutes. The delay had three parts:
//
//  1. drainPinGrace, then 30m, still served live sessions on the paused
//     account.
//  2. claude-proxy cached each session's lease for up to 30 minutes and never
//     asked whether the account was paused.
//  3. When a session finally re-leased, the proxy treated the paused home as
//     BUSY and refused the user for sessionPinMaxWait (2 min) before moving
//     the session.
//
// Separately, the availability backstop served ac5 anyway whenever ylu, the
// only other usable account, was at its in-flight ceiling, and /code showed
// none of this.
//
// The fixes in this file:
//   - pauseEnforced tells claude-proxy, on the quota report it already sends
//     about once a minute per account, that the grace is over. The proxy then
//     drops its cached leases for that account.
//   - The lease response says when prefer_email was refused because it is
//     paused, so the proxy moves the session at once instead of retrying.
//   - pauseLeaseTTL caps how long the proxy may cache a lease on a paused
//     account.
//   - noteDrainOverride records the backstop so /code can show it.
//   - pauseGuard refuses a pause that would leave no usable account in the
//     pool, using the same notion of "usable" as placement.

// pauseEnforced reports whether a paused account's pin grace has run out, so
// that lease-time refuses it even to sessions already running on it.
func pauseEnforced(row models.ClaudeQuotaToken, now time.Time) bool {
	return row.DrainingSince != nil && now.Sub(*row.DrainingSince) >= drainPinGrace
}

// pauseEnforcedAt is when the grace ends. Nil for an account that is not
// paused.
func pauseEnforcedAt(row models.ClaudeQuotaToken) *time.Time {
	if row.DrainingSince == nil {
		return nil
	}
	t := row.DrainingSince.Add(drainPinGrace)
	return &t
}

// backstopLeaseTTL caps a lease on a paused account handed out by the
// availability backstop. It is short because the backstop exists only for
// moments when no other candidate is free. A sibling slot frees in seconds, and
// the proxy should come back and try for it instead of holding the paused
// account for its usual 30 minutes.
const backstopLeaseTTL = 60 * time.Second

// pauseLeaseTTL is the lease_ttl_sec hint for a lease on row, or 0 for no cap.
//   - Paused and inside the grace: cap the lease at the end of the grace, so
//     the cache cannot hold the session past it.
//   - Served by the backstop: backstopLeaseTTL.
func pauseLeaseTTL(row models.ClaudeQuotaToken, now time.Time, backstop bool) int {
	if row.DrainingSince == nil {
		return 0
	}
	if backstop {
		return int(backstopLeaseTTL / time.Second)
	}
	left := row.DrainingSince.Add(drainPinGrace).Sub(now)
	if left <= 0 {
		return int(backstopLeaseTTL / time.Second)
	}
	// Floor of 5s, so a lease issued a moment before the grace ends is not
	// already expired when it arrives.
	if left < 5*time.Second {
		left = 5 * time.Second
	}
	return int(left / time.Second)
}

var (
	drainOverrideMu   sync.Mutex
	drainOverrideLast = map[string]time.Time{}
)

// drainOverrideThrottle bounds the backstop's write rate. A busy backstop fires
// on many leases a minute, and the column is a display hint, not a counter.
const drainOverrideThrottle = time.Minute

// noteDrainOverride records that the backstop served a paused account. It is
// best-effort: a failed write costs only the /code hint, never the lease.
func noteDrainOverride(email string, now time.Time) {
	drainOverrideMu.Lock()
	if last, ok := drainOverrideLast[email]; ok && now.Sub(last) < drainOverrideThrottle {
		drainOverrideMu.Unlock()
		return
	}
	drainOverrideLast[email] = now
	drainOverrideMu.Unlock()
	if err := common.DB.Model(&models.ClaudeQuotaToken{}).
		Where("email = ? AND draining_since IS NOT NULL", email).
		Update("drain_overridden_at", now).Error; err != nil {
		log.Printf("claude-pool: could not record pause override for %s: %v", email, err)
	}
}

// pauseSiblingState says, for one account about to be paused, which other
// accounts in the same pool could take its users. The fields are kept apart so
// the refusal can name exactly why each sibling does not count.
type pauseSiblingState struct {
	Usable    []string
	Paused    []string
	Benched   []string
	Exhausted []string
}

func (s pauseSiblingState) describe() string {
	parts := []string{fmt.Sprintf("usable=%d", len(s.Usable))}
	if len(s.Paused) > 0 {
		parts = append(parts, "paused="+strings.Join(s.Paused, ","))
	}
	if len(s.Benched) > 0 {
		parts = append(parts, "benched="+strings.Join(s.Benched, ","))
	}
	if len(s.Exhausted) > 0 {
		parts = append(parts, "exhausted="+strings.Join(s.Exhausted, ","))
	}
	return strings.Join(parts, " ")
}

// classifyPauseSiblings sorts siblings with the same rules placement and
// lease-time use. An account counts as usable when it is not quarantined, not
// paused, not benched, and not at or above nearExhaustCeiling on a fresh
// snapshot. A stale or missing snapshot counts as usable, which matches
// accountQuotas: lease-time re-probes it rather than assuming it is spent.
//
// Pure, so it can be tested without a DB.
func classifyPauseSiblings(self string, rows []models.ClaudeQuotaToken,
	quotas map[string]accountQuota, now time.Time) pauseSiblingState {
	var s pauseSiblingState
	for _, r := range rows {
		if r.Email == self || r.RevokedAt != nil {
			continue
		}
		switch {
		case r.DrainingSince != nil:
			s.Paused = append(s.Paused, r.Email)
		case r.BenchUntil != nil && now.Before(*r.BenchUntil):
			s.Benched = append(s.Benched, r.Email)
		case quotas[r.Email].exhausted():
			s.Exhausted = append(s.Exhausted, r.Email)
		default:
			s.Usable = append(s.Usable, r.Email)
		}
	}
	return s
}

func pauseSiblings(poolID, self string) (pauseSiblingState, error) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Where("pool_id = ?", poolID).Find(&rows).Error; err != nil {
		return pauseSiblingState{}, err
	}
	// Legacy rows hold "" for the default pool. Include them, as
	// poolIDOrDefault does everywhere else.
	if poolID == models.DefaultClaudePoolID {
		var legacy []models.ClaudeQuotaToken
		if err := common.DB.Where("pool_id = ''").Find(&legacy).Error; err == nil {
			rows = append(rows, legacy...)
		}
	}
	emails := make([]string, 0, len(rows))
	for _, r := range rows {
		emails = append(emails, r.Email)
	}
	return classifyPauseSiblings(self, rows, accountQuotas(emails), time.Now()), nil
}

// pauseGuard decides whether pausing row is allowed.
//   - Refuses (non-empty refuse) when no other account in the pool is usable.
//     Lease-time would serve the paused account through the backstop anyway,
//     so the pause would quietly do nothing. The old check counted every
//     non-revoked account in every pool, so an exhausted sibling (ac4 at 98%)
//     let the pause through.
//   - Warns (non-empty warn) when exactly one usable sibling is left. Its
//     in-flight ceiling then decides whether the pause holds.
func pauseGuard(row models.ClaudeQuotaToken) (refuse, warn string, err error) {
	s, err := pauseSiblings(poolIDOrDefault(row.PoolID), row.Email)
	if err != nil {
		return "", "", err
	}
	switch len(s.Usable) {
	case 0:
		return fmt.Sprintf("refusing to pause %s: no other account in this pool can take its users (%s). "+
			"It would keep serving anyway, through the availability backstop. Add, resume, or wait for another account first.",
			row.Email, s.describe()), "", nil
	case 1:
		return "", fmt.Sprintf("only one other usable account (%s) is left in this pool. Whenever it is full, "+
			"%s will still be served through the availability backstop, and /code will show that as an override.",
			s.Usable[0], row.Email), nil
	}
	return "", "", nil
}

// drainOverrideShown is the override timestamp to display. It is nil unless
// the account is paused now and the override happened during this pause. The
// column is cleared on pause and resume, but an override write racing a
// resume could leave a value behind, and that value must not show up on a
// later, unrelated pause.
func drainOverrideShown(row models.ClaudeQuotaToken) *time.Time {
	if row.DrainingSince == nil || row.DrainOverriddenAt == nil ||
		row.DrainOverriddenAt.Before(*row.DrainingSince) {
		return nil
	}
	return row.DrainOverriddenAt
}
