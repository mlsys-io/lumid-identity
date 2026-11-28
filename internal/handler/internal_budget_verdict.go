package handler

// POST /api/v1/internal/budget-verdict (round-11 addendum, 2026-11-28).
//
// The question a spender asks before it spends: would this take the user's
// app over its declared `compute.budget`? claude-proxy asks it in its pre-call
// gate for app-bound credentials (hard stop at zero: it sends no estimate); a
// cycle may ask it with an estimate before a $-spending stage.
//
// Same auth as /internal/usage/charge: the bridge secret, or a run credential
// that may only ask about its own user and app.
//
//	→ {"user_sub": "...", "app": "mbb-consultant", "estimate": {"usd": 0.12, "gpu_s": 0, "cpu_s": 0}}
//	← {"ok": false, "words": "Your mbb-consultant budget has $0.40 of $40 left; this would take about $0.12",
//	   "left": {"usd": 0.4}, "budget": {"usd": 40, "per": "total"}}
//
// ok=true with no words and budget null when the app declares none. The app's
// budget and spend are cached per (user, app) for budgetVerdictTTL, in memory;
// a charge for that (user, app) landing on THIS replica drops the entry. The
// other identity replica can be up to the TTL stale, which is fine for a gate
// whose hard stop is "already spent".

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type budgetVerdictBody struct {
	UserSub  string `json:"user_sub" binding:"required"`
	App      string `json:"app"      binding:"required"`
	Estimate *struct {
		USD  *float64 `json:"usd"`
		GPUS *float64 `json:"gpu_s"`
		CPUS *float64 `json:"cpu_s"`
	} `json:"estimate,omitempty"`
}

// budgetVerdict is the response's data.
type budgetVerdict struct {
	OK     bool           `json:"ok"`
	Words  string         `json:"words,omitempty"`
	Left   map[string]any `json:"left,omitempty"`
	Budget *computeBudget `json:"budget"`
}

var (
	budgetVerdictTTL = 30 * time.Second
	budgetVerdictNow = time.Now
	budgetCacheMu    sync.Mutex
	budgetCache      = map[string]budgetCacheEntry{}
)

const budgetCacheMax = 4096

type budgetCacheEntry struct {
	budget computeBudget
	spend  budgetSpend
	at     time.Time
}

func budgetCacheKey(sub, app string) string { return sub + "\x00" + app }

// budgetState: the app-level budget and what has been spent in its window,
// from the cache when fresh.
func budgetState(sub, app string) (computeBudget, budgetSpend) {
	key, now := budgetCacheKey(sub, app), budgetVerdictNow()
	budgetCacheMu.Lock()
	e, hit := budgetCache[key]
	budgetCacheMu.Unlock()
	if hit && now.Sub(e.at) < budgetVerdictTTL {
		return e.budget, e.spend
	}
	b := appBudgets(sub, app).App
	var sp budgetSpend
	if !b.empty() {
		s := usageSpent(sub, app, "", b.since(now))
		sp = budgetSpend{GPUS: s.GPUS, CPUS: s.CPUS, USD: s.USD}
	}
	budgetCacheMu.Lock()
	if len(budgetCache) >= budgetCacheMax {
		for k, v := range budgetCache {
			if now.Sub(v.at) >= budgetVerdictTTL {
				delete(budgetCache, k)
			}
		}
	}
	budgetCache[key] = budgetCacheEntry{budget: b, spend: sp, at: now}
	budgetCacheMu.Unlock()
	return b, sp
}

// invalidateBudgetVerdict drops the cached state for (sub, app); called when
// a charge for it lands.
func invalidateBudgetVerdict(sub, app string) {
	if sub == "" || app == "" {
		return
	}
	budgetCacheMu.Lock()
	delete(budgetCache, budgetCacheKey(sub, app))
	budgetCacheMu.Unlock()
}

func verdictFor(sub, app string, est budgetEstimate) budgetVerdict {
	b, sp := budgetState(sub, app)
	if b.empty() {
		return budgetVerdict{OK: true}
	}
	left := map[string]any{}
	if b.USD > 0 {
		left["usd"] = math.Round(math.Max(0, b.USD-sp.USD)*1e6) / 1e6
	}
	if b.GPUMinutes > 0 {
		left["gpu_minutes"] = round3(math.Max(0, b.GPUMinutes-sp.GPUS/60))
	}
	if b.CPUMinutes > 0 {
		left["cpu_minutes"] = round3(math.Max(0, b.CPUMinutes-sp.CPUS/60))
	}
	words := budgetWords(b, sp, est, budgetScope(app))
	return budgetVerdict{OK: words == "", Words: words, Left: left, Budget: &b}
}

// InternalBudgetVerdict: POST /api/v1/internal/budget-verdict.
func InternalBudgetVerdict(c *gin.Context) {
	var body budgetVerdictBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	body.App = strings.TrimSpace(body.App)
	if !fleetLabelRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if !allowRunAppWrite(c, body.UserSub, body.App) {
		return
	}
	var est budgetEstimate
	if e := body.Estimate; e != nil {
		for _, f := range []struct {
			src *float64
			dst *float64
		}{{e.USD, &est.USD}, {e.GPUS, &est.GPUS}, {e.CPUS, &est.CPUS}} {
			if f.src == nil {
				continue
			}
			if *f.src < 0 || math.IsNaN(*f.src) || math.IsInf(*f.src, 0) {
				fail(c, http.StatusBadRequest, 1400, "estimate must be a non-negative number")
				return
			}
			*f.dst = *f.src
		}
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": verdictFor(body.UserSub, body.App, est)})
}
