package handler

// Claude-proxy field-box fingerprint adoption.
//
// claude-proxy rewrites the client identity (User-Agent + x-stainless-*) on
// every request it relays through a field box, so all users behind one box
// look like one machine. Those version numbers go stale — Claude Code
// auto-updates every few days — and a box presenting a nearly-abandoned
// release is the exact "frozen client" tell the rewrite exists to avoid.
//
// This pair of endpoints closes that loop WITHOUT letting the two proxy
// replicas disagree:
//
//	POST /api/v1/internal/claude-fingerprint/observe  — a replica reports the
//	     triples it counted since its last flush
//	GET  /api/v1/internal/claude-fingerprint/pool     — the adopted pool, one
//	     answer for every caller
//
// THE INVARIANT: every replica must present the same identity for a given box.
// Two things deliver that here, and both matter:
//
//  1. Aggregation is central. The pool is computed from ALL replicas' counts,
//     not from whatever one pod happened to see.
//  2. The answer is derived from the PREVIOUS COMPLETE window, never the
//     in-progress one. That makes it a pure function of closed data, so it is
//     byte-identical no matter when in the window a replica asks, and it
//     changes only at a window boundary that every replica computes from the
//     same clock. Deriving from the live window would make the answer drift
//     between two callers seconds apart — reintroducing the split identity
//     this design exists to prevent.
//
// Nothing here is authoritative over the proxy: an empty or errored response
// means the proxy keeps its own compiled-in pool, so identity being down
// degrades to today's behaviour rather than breaking egress.

import (
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

	"github.com/gin-gonic/gin"
)

// fingerprintWindow is the aggregation bucket. Claude Code patches land every
// few days and a fleet can move most of the way to a new release inside a day
// (measured 2026-08-12: one SDK line went ~30% -> ~67% of sampled requests in
// six hours), so a day-long window tracks reality without reacting to an hour
// of unrepresentative traffic.
func fingerprintWindow() time.Duration {
	if v := os.Getenv("LUMID_CLAUDE_FINGERPRINT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 24 * time.Hour
}

// fingerprintMinSamples is the floor below which we decline to have an
// opinion. A handful of requests is not evidence of what the fleet runs, and
// adopting off it would let one unusual client redefine every box.
func fingerprintMinSamples() int {
	if n, err := strconv.Atoi(os.Getenv("LUMID_CLAUDE_FINGERPRINT_MIN_SAMPLES")); err == nil && n > 0 {
		return n
	}
	return 50
}

// fingerprintMinShare is the fraction of the window's traffic a triple must
// carry to enter the pool. It is a NOISE FLOOR, not a majority test: several
// triples can qualify, and that is deliberate — if the fleet genuinely spans
// two releases, the boxes should span them too. Set high enough that a
// long-tail client cannot install itself as one of the identities the fleet
// presents.
func fingerprintMinShare() float64 {
	if f, err := strconv.ParseFloat(os.Getenv("LUMID_CLAUDE_FINGERPRINT_MIN_SHARE"), 64); err == nil && f > 0 && f < 1 {
		return f
	}
	return 0.15
}

// fingerprintMaxRows caps the pool. Past a few identities the marginal realism
// is nil and the blast radius of a bad observation grows.
const fingerprintMaxRows = 4

type fingerprintObserveBody struct {
	Reporter string `json:"reporter"`
	Samples  []struct {
		CLI   string `json:"cli"`
		SDK   string `json:"sdk"`
		Node  string `json:"node"`
		Count int    `json:"count"`
	} `json:"samples"`
	// Presenting is what the reporting proxy is currently sending for each
	// box. Reported rather than re-derived: identity cannot know which of the
	// proxy's three sources (env override / adopted pool / compiled-in pool)
	// won, and guessing is what left the /code panel confidently wrong for a
	// day. See models.ClaudeFieldPresenting.
	Presenting []struct {
		Label     string `json:"label"`
		UserAgent string `json:"user_agent"`
		CLI       string `json:"cli"`
		SDK       string `json:"sdk"`
		Node      string `json:"node"`
		OS        string `json:"os"`
		Arch      string `json:"arch"`
		Runtime   string `json:"runtime"`
		Source    string `json:"source"`
	} `json:"presenting"`
}

// POST /api/v1/internal/claude-fingerprint/observe  (RequireBridge)
func InternalClaudeFingerprintObserve(c *gin.Context) {
	var body fingerprintObserveBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	now := time.Now().UTC()
	rows := make([]models.ClaudeFingerprintObservation, 0, len(body.Samples))
	for _, s := range body.Samples {
		// A partial triple is unusable: it cannot be presented, and storing it
		// would let it dilute the shares of triples that ARE usable.
		if s.CLI == "" || s.SDK == "" || s.Node == "" || s.Count <= 0 {
			continue
		}
		rows = append(rows, models.ClaudeFingerprintObservation{
			CLI: s.CLI, SDK: s.SDK, Node: s.Node,
			Count: s.Count, Reporter: body.Reporter, ObservedAt: now,
		})
	}
	// Upsert what the proxy says it is presenting. Independent of the samples
	// above: a replica with nothing new to report still refreshes this, which
	// is what keeps UpdatedAt meaningful as a staleness signal.
	for _, p := range body.Presenting {
		if p.Label == "" || p.UserAgent == "" {
			continue
		}
		row := models.ClaudeFieldPresenting{
			Label: p.Label, UserAgent: p.UserAgent,
			CLI: p.CLI, SDK: p.SDK, Node: p.Node,
			OS: p.OS, Arch: p.Arch, Runtime: p.Runtime,
			Source: p.Source, Reporter: body.Reporter, UpdatedAt: now,
		}
		if err := common.DB.Save(&row).Error; err != nil {
			// Non-fatal: this is display truth, not egress behaviour.
			continue
		}
	}

	if len(rows) == 0 {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "stored": 0})
		return
	}
	if err := common.DB.Create(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "insert observations: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "stored": len(rows)})
}

type fingerprintPoolRow struct {
	CLI   string  `json:"cli"`
	SDK   string  `json:"sdk"`
	Node  string  `json:"node"`
	Count int     `json:"count"`
	Share float64 `json:"share"`
}

// GET /api/v1/internal/claude-fingerprint/pool  (RequireBridge)
//
// Returns the adopted pool for the CURRENT window, computed entirely from the
// previous complete one. `window` is the bucket index the answer belongs to;
// a caller can compare it against its own to know a boundary has passed.
func InternalClaudeFingerprintPool(c *gin.Context) {
	win := fingerprintWindow()
	// Bucket on absolute unix seconds so every process — identity, and each
	// proxy replica — derives the same boundaries from the same clock with no
	// shared state and no coordination.
	nowIdx := time.Now().UTC().Unix() / int64(win.Seconds())
	prevStart := time.Unix((nowIdx-1)*int64(win.Seconds()), 0).UTC()
	prevEnd := time.Unix(nowIdx*int64(win.Seconds()), 0).UTC()

	var rows []models.ClaudeFingerprintObservation
	if err := common.DB.
		Where("observed_at >= ? AND observed_at < ?", prevStart, prevEnd).
		Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read observations: "+err.Error())
		return
	}

	pool, total, reason := computeFingerprintPool(rows, fingerprintMinSamples(), fingerprintMinShare())

	resp := gin.H{
		"ret_code": 0,
		"window":   nowIdx,
		"from":     prevStart.Format(time.RFC3339),
		"to":       prevEnd.Format(time.RFC3339),
		"total":    total,
		"pool":     pool,
	}
	if reason != "" {
		resp["reason"] = reason
	}
	c.JSON(http.StatusOK, resp)
}

// computeFingerprintPool is the whole decision, kept pure so the properties
// that make it safe are testable without a database.
//
// Returns the adopted pool, the total sample count, and a non-empty reason
// when the pool is empty. An empty pool is a valid, deliberate answer: the
// proxy reads it as "keep your own compiled-in pool".
func computeFingerprintPool(rows []models.ClaudeFingerprintObservation, minSamples int, minShare float64) ([]fingerprintPoolRow, int, string) {
	type key struct{ cli, sdk, node string }
	totals := map[key]int{}
	total := 0
	for _, r := range rows {
		// Defence in depth: the observe endpoint already drops partial
		// triples, but a row that predates that check must not be able to
		// dilute the shares of usable ones.
		if r.CLI == "" || r.SDK == "" || r.Node == "" || r.Count <= 0 {
			continue
		}
		totals[key{r.CLI, r.SDK, r.Node}] += r.Count
		total += r.Count
	}

	// Too little evidence: decline to have an opinion rather than return a
	// low-confidence pool.
	if total < minSamples {
		return []fingerprintPoolRow{}, total, "insufficient_samples"
	}

	pool := make([]fingerprintPoolRow, 0, len(totals))
	for k, n := range totals {
		share := float64(n) / float64(total)
		if share < minShare {
			continue
		}
		pool = append(pool, fingerprintPoolRow{CLI: k.cli, SDK: k.sdk, Node: k.node, Count: n, Share: share})
	}
	// Deterministic order. Count descending, then the triple lexicographically
	// as a tiebreak — WITHOUT the tiebreak, two equal-count triples could come
	// back in Go map order, which is randomised per iteration, and hand two
	// callers different pools. That is precisely the split identity this whole
	// design exists to prevent, so the tiebreak is load-bearing, not cosmetic.
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].Count != pool[j].Count {
			return pool[i].Count > pool[j].Count
		}
		if pool[i].CLI != pool[j].CLI {
			return pool[i].CLI < pool[j].CLI
		}
		if pool[i].SDK != pool[j].SDK {
			return pool[i].SDK < pool[j].SDK
		}
		return pool[i].Node < pool[j].Node
	})
	if len(pool) > fingerprintMaxRows {
		pool = pool[:fingerprintMaxRows]
	}
	if len(pool) == 0 {
		return pool, total, "no_triple_met_min_share"
	}
	return pool, total, ""
}

// StartClaudeFingerprintGC drops observation rows old enough that no window
// can reference them. Without it this table grows forever for a signal whose
// entire value is recency.
func StartClaudeFingerprintGC() {
	go func() {
		time.Sleep(5 * time.Minute)
		for {
			// Keep several windows so a widened window still has history and
			// so an operator can inspect what drove a past decision.
			cutoff := time.Now().UTC().Add(-8 * fingerprintWindow())
			common.DB.Where("observed_at < ?", cutoff).
				Delete(&models.ClaudeFingerprintObservation{})
			time.Sleep(fingerprintWindow())
		}
	}()
}
