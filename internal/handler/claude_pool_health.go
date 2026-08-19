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
		},
	})
}
