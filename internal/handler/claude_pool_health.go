package handler

// Claude account-pool health, for external monitoring.
//
// WHY THIS EXISTS: on 2026-08-13 all four pooled accounts were quarantined one
// at a time over twelve hours (each `invalid_grant` — the refresh-token family
// had been rotated out from under us). The pool sat at ZERO refreshable
// accounts and lum.id/claude was down for a day before anyone noticed, because
// the only signal was a log line inside the token-refresh sweep and a generic
// "out of quota" message shown to users. Nothing polled, nothing alerted.
//
// This endpoint is that missing signal, in the cheapest form that can be
// scraped on a schedule: pure DB reads, no Anthropic round-trips. It is
// deliberately NOT GET /api/v1/admin/claude-quota — that dashboard endpoint
// live-probes every account against api.anthropic.com in parallel, which is
// both slow and a needless draw on the very quota it reports.
//
// Consumer: opsagent's `claude_pool` dimension (*/15 sweep).

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type quarantinedAccount struct {
	Email  string `json:"email"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
	Since  string `json:"since"`
}

// atRiskAccount is an account that is still SERVING but carries an unresolved
// lost rotation — i.e. we are one exchange away from quarantining it.
//
// WHY: refreshTokenLocked already detects the fatal case precisely. Anthropic
// rotates the token family on RECEIPT of a refresh, so a request we know was
// written but never answered leaves the stored refresh token possibly already
// superseded — and the NEXT exchange is what discovers it, as invalid_grant,
// as a quarantine, as a human doing `claude auth login`. markIndeterminate
// records exactly that moment.
//
// But it recorded it into a column nothing read. Every consumer — this
// endpoint, the sweep's warning line, opsagent's claude_pool dimension — keyed
// on RevokedAt, which is the OUTCOME. So the pool's one true leading indicator
// was available only to a human running a forensic query after the account was
// already dead, which is the same shape as the 2026-08-13 incident this file
// was written for: the signal existed, nothing read it.
//
// The window between the two is real and usable. The account keeps working on
// the access token it already holds, so an operator told NOW can mint and swap
// a replacement before anything fails; told at quarantine, they are restoring
// an outage instead of avoiding one.
type atRiskAccount struct {
	Email  string `json:"email"`
	Label  string `json:"label"`
	Signal string `json:"signal"`
	Detail string `json:"detail"`
	Since  string `json:"since"`
}

// lostRotationUnresolved reports whether an account carries an indeterminate
// exchange that no later success has cleared.
//
// Self-clearing by construction, and deliberately not on a timer. A successful
// exchange AFTER the indeterminate is proof the family survived — we presented
// the stored refresh token and Anthropic accepted it, which it would not have
// done had the lost rotation superseded it. Until that proof arrives the risk
// is live, however long ago the indeterminate was.
//
// A time window would get this wrong in both directions: too short and it
// silences a real risk on an account the sweep has not reached yet, too long
// and it alerts forever on an account that recovered — and markIndeterminate
// never clears the marker on purpose, because it is an evidence trail. Reading
// it against LastExchange makes the alert self-clearing without touching that
// trail.
func lostRotationUnresolved(row *models.ClaudeQuotaToken) bool {
	if row.IndeterminateAt == nil {
		return false
	}
	provenSince := row.LastExchangeOutcome == "ok" &&
		row.LastExchangeAt != nil &&
		row.LastExchangeAt.After(*row.IndeterminateAt)
	return !provenSince
}

// InternalClaudePoolHealth — GET /api/v1/internal/claude-pool/health (RequireBridge)
//
// Reports the pool's leasability in the same terms the lease path uses, so a
// monitor and a user hitting the proxy cannot disagree about whether the pool
// is up:
//
//	refreshable — has a refresh token AND is not quarantined. This is the
//	              sweep's own definition (sweepAllTokens), and the population
//	              that can still be kept alive without a human.
//	exhausted   — refreshable but currently excluded from a lease by
//	              snapshotIsExhausted (≥98% on the 5h or 7d window) — the same
//	              check InternalClaudeTokenLease applies to its own candidates.
//	              Recovers on its own window reset, not on a re-add, but until
//	              then it cannot take traffic — a fixed 5h wait for the 5h
//	              window, or the rest of the week for the 7d window.
//	servable    — refreshable minus exhausted: accounts that would actually be
//	              picked if a lease came in right now. This, not refreshable,
//	              is what `healthy` is judged against.
//	benched     — pool-wide 401/403 cooldown; recovers on a timer (seconds to a
//	              few minutes), so — like the sweep's own accounting — it is
//	              reported but does NOT subtract from servable.
//	quarantined — family revoked; recovers ONLY via a fresh `claude auth login`
//	              plus a re-add. This is the one worth waking someone for.
//
// `healthy` is false as soon as SERVABLE drops below the floor the sweep warns
// at. Before `servable` existed this compared `refreshable` to the floor, so a
// pool sitting on one genuinely usable account (the rest quarantined or spent)
// with one merely-refreshable-but-98%-spent account alongside it still read
// `healthy:true` — floor satisfied on paper, one account actually able to
// serve. opsagent's P0 alert trusts this field verbatim, so that gap meant no
// page while lum.id/claude was already effectively down to a single account.
func InternalClaudePoolHealth(c *gin.Context) {
	var rows []models.ClaudeQuotaToken
	if err := common.DB.Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query tokens: "+err.Error())
		return
	}

	now := time.Now()
	var refreshable, exhausted, benched, quarantined int
	quarantinedList := make([]quarantinedAccount, 0, len(rows))
	atRiskList := make([]atRiskAccount, 0, len(rows))

	for _, row := range rows {
		switch {
		case row.RevokedAt != nil:
			quarantined++
			quarantinedList = append(quarantinedList, quarantinedAccount{
				Email:  row.Email,
				Label:  row.Label,
				Reason: row.RevokeReason,
				Since:  row.RevokedAt.UTC().Format(time.RFC3339),
			})
		default:
			// Benched and refreshable are not exclusive: a benched account still
			// has a live family and is counted as refreshable, because it comes
			// back on its own. Only the quarantine branch above removes an
			// account from the population that can recover unattended.
			if row.RefreshTokenEncrypted != "" {
				refreshable++
				var snap models.ClaudeQuotaSnapshot
				if common.DB.Where("email = ?", row.Email).Order("ts DESC").First(&snap).Error == nil &&
					snapshotIsExhausted(&snap, now) {
					exhausted++
				}
			}
			if row.BenchUntil != nil && now.Before(*row.BenchUntil) {
				benched++
			}
			// Only for accounts that are still alive — a quarantined one is
			// already the loudest thing in this payload, and listing it twice
			// would just dilute the alert that matters.
			if lostRotationUnresolved(&row) {
				atRiskList = append(atRiskList, atRiskAccount{
					Email:  row.Email,
					Label:  row.Label,
					Signal: "lost-rotation",
					Detail: row.IndeterminateReason,
					Since:  row.IndeterminateAt.UTC().Format(time.RFC3339),
				})
			}
		}
	}

	servable := refreshable - exhausted
	if servable < 0 { // defensive only; refreshable/exhausted share the same population
		servable = 0
	}

	// Stable order — a monitor diffing this payload between sweeps should see a
	// change only when the pool actually changed, not because Go reordered rows.
	sort.Slice(quarantinedList, func(i, j int) bool {
		return quarantinedList[i].Email < quarantinedList[j].Email
	})
	sort.Slice(atRiskList, func(i, j int) bool {
		return atRiskList[i].Email < atRiskList[j].Email
	})

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"total":                len(rows),
			"refreshable":          refreshable,
			"exhausted":            exhausted,
			"servable":             servable,
			"benched":              benched,
			"quarantined":          quarantined,
			"floor":                minHealthyPoolAccounts,
			"healthy":              servable >= minHealthyPoolAccounts,
			"quarantined_accounts": quarantinedList,
			// at_risk does NOT subtract from servable or flip `healthy`: these
			// accounts are serving normally right now. It is a separate,
			// forward-looking signal — "this one is likely to quarantine on its
			// next exchange" — and conflating it with current capacity would
			// make the pool read as degraded while it is fully up.
			"at_risk":          len(atRiskList),
			"at_risk_accounts": atRiskList,
		},
	})
}
