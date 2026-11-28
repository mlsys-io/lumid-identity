package handler

// LLM metering for /me/usage (round-11 addendum, 2026-11-28).
//
// What an app's runs spent on model calls is read from usage_events, the rows
// claude-proxy (kind claude_proxy) and a cycle's own claude CLI charge (kind
// cycle_llm) write, attributed by the app / run_id columns. It cannot be
// bypassed by app code: the proxy charges every call it serves.
//
// Three rules keep the sum honest:
//
//   - run_id "measure:<key>" rows are EXCLUDED. They are the proxy's record of a
//     pooled-llm measurement's call, whose cost is already counted through its
//     measure_results row (usageSpent). See the mint site in me_measure_llm.go.
//   - A routed tenant cycle's claude CLI call is charged twice, once by the
//     cycle (cycle_llm, app code's own count) and once by the proxy that served
//     it (claude_proxy). Both carry the run credential's id as run_id, so a
//     run's cycle_llm rows count only when that run has no claude_proxy row.
//   - Price by MODEL, never by backend:
//     Anthropic rows use the stored cost (cost_cents, the proxy's price);
//     self-hosted models the rate table names (deepseek*, qwen*) are priced at
//     the NOTIONAL USAGE_RATES.llm rate, not 0 — "free" is reserved for reused
//     results. A model the table does not name keeps its stored cost (e.g. an
//     OpenRouter-billed model); a row with tokens and no stored cost falls back
//     to the table (Anthropic list price, or "*").

import (
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type llmTokenRate struct {
	InPerMTok  float64 `json:"in_per_mtok"`
	OutPerMTok float64 `json:"out_per_mtok"`
}

// usageDefaultLLMRates, $ per million tokens. Keep in step with LumidOS
// sdk/apps/usage.py DEFAULT_RATES["llm"].
//
// The self-hosted entries are NOTIONAL: we run these models on our own GPUs, so
// there is no bill. They are set at roughly what the same or a comparable open
// model costs from a cloud API, so LLM work sits on one axis with CPU and GPU
// time and an app's in-house model calls are not "free". deepseek-v4.1-flash
// and deepseek* are the OpenRouter endpoint prices claude-proxy already books
// (modelCostCents, read 2026-10-27 and 2026-08-24), so the two surfaces agree;
// qwen3.8-* is the ~30B-class open-model API price, qwen* claude-proxy's roster
// median; "*" is a deliberately conservative notional for an unnamed model.
//
// The claude-* entries are Anthropic LIST prices, not notional. They apply only
// to an Anthropic row with no stored cost (a cycle's own charge sends none);
// the proxy prices every call it serves and that stored cost wins.
var usageDefaultLLMRates = map[string]llmTokenRate{
	"deepseek-v4.1-flash*": {InPerMTok: 0.14, OutPerMTok: 0.42},
	"deepseek*":            {InPerMTok: 0.04, OutPerMTok: 0.08},
	"qwen3.8-*":            {InPerMTok: 0.10, OutPerMTok: 0.40},
	"qwen*":                {InPerMTok: 0.23, OutPerMTok: 1.13},
	"claude-opus*":         {InPerMTok: 5, OutPerMTok: 25},
	"claude-sonnet*":       {InPerMTok: 3, OutPerMTok: 15},
	"claude-haiku*":        {InPerMTok: 1, OutPerMTok: 5},
	"*":                    {InPerMTok: 0.50, OutPerMTok: 2.00},
}

// llmModelKey normalises a recorded model id for rate lookup: lower case, no
// Claude Code "[1m]" marker, no vendor prefix ("deepseek/deepseek-v4.1-flash"),
// and the CLI aliases haiku/sonnet/opus as their claude- names.
func llmModelKey(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if i := strings.IndexByte(m, '['); i >= 0 {
		m = m[:i]
	}
	if i := strings.LastIndexByte(m, '/'); i >= 0 {
		m = m[i+1:]
	}
	switch m {
	case "haiku", "sonnet", "opus":
		m = "claude-" + m
	}
	return m
}

func isAnthropicModel(model string) bool { return strings.HasPrefix(llmModelKey(model), "claude") }

// llmRateFor: the exact entry, else the longest "prefix*" entry the model
// starts with, else "*". named is false when only "*" (or nothing) matched.
func (r usageRates) llmRateFor(model string) (rate llmTokenRate, named, ok bool) {
	m := llmModelKey(model)
	if v, hit := r.LLM[m]; hit && m != "*" && m != "" {
		return v, true, true
	}
	best := ""
	for k := range r.LLM {
		stem, glob := strings.CutSuffix(k, "*")
		if glob && stem != "" && strings.HasPrefix(m, stem) && len(stem) > len(best) {
			best = stem
		}
	}
	if best != "" {
		return r.LLM[best+"*"], true, true
	}
	v, hit := r.LLM["*"]
	return v, false, hit
}

// llmUSD prices one row (or a group of rows of one model that agree on
// whether they carry a stored cost). notional = priced from the rate table
// rather than from a stored cost.
func (r usageRates) llmUSD(model string, tokensIn, tokensOut, costCents int64) (usd float64, notional bool) {
	rate, named, ok := r.llmRateFor(model)
	stored := costCents > 0
	if stored && (isAnthropicModel(model) || !named) {
		return float64(costCents) / 100, false
	}
	if (tokensIn == 0 && tokensOut == 0) || !ok {
		if stored {
			return float64(costCents) / 100, false
		}
		return 0, false
	}
	return (float64(tokensIn)*rate.InPerMTok + float64(tokensOut)*rate.OutPerMTok) / 1e6, true
}

// llmUsageKinds: the usage_events kinds that are model calls.
var llmUsageKinds = []string{"claude_proxy", "cycle_llm", "chat"}

// llmByRunCap bounds by_run: a busy app runs thousands of cycles a window.
const llmByRunCap = 200

type llmTally struct {
	Calls     int     `json:"calls"`
	TokensIn  int64   `json:"tokens_in"`
	TokensOut int64   `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
}

func (t *llmTally) add(calls int, in, out int64, usd float64) {
	t.Calls += calls
	t.TokensIn += in
	t.TokensOut += out
	t.CostUSD += usd
}

func (t llmTally) rounded() llmTally {
	t.CostUSD = math.Round(t.CostUSD*1e6) / 1e6
	return t
}

// llmSpend is the `used.llm` block of /me/usage.
type llmSpend struct {
	llmTally
	NotionalUSD float64             `json:"notional_usd"` // the part of cost_usd priced from USAGE_RATES.llm
	ByModel     map[string]llmTally `json:"by_model"`
	ByRun       map[string]llmTally `json:"by_run"` // attributed runs only, the latest llmByRunCap
	RunsOmitted int                 `json:"runs_omitted,omitempty"`
}

// llmSpent sums the caller's attributed model calls for app ("" = every app,
// attributed rows only) since t (zero = all time). ok=false when there are
// none: an unmetered block is left out, never written as zeros.
func llmSpent(sub, app string, since time.Time) (llmSpend, bool) {
	type group struct {
		Kind      string  `gorm:"column:kind"`
		Model     string  `gorm:"column:model"`
		RunID     *string `gorm:"column:run_id"`
		HasCost   int     `gorm:"column:has_cost"`
		Calls     int     `gorm:"column:calls"`
		TokensIn  int64   `gorm:"column:tokens_in"`
		TokensOut int64   `gorm:"column:tokens_out"`
		CostCents int64   `gorm:"column:cost_cents"`
		LastID    uint64  `gorm:"column:last_id"`
	}
	q := common.DB.Model(&models.UsageEvent{}).
		Select("kind, model, run_id, CASE WHEN cost_cents > 0 THEN 1 ELSE 0 END AS has_cost, COUNT(*) AS calls, "+
			"COALESCE(SUM(input_tokens), 0) AS tokens_in, COALESCE(SUM(output_tokens), 0) AS tokens_out, "+
			"COALESCE(SUM(cost_cents), 0) AS cost_cents, MAX(id) AS last_id").
		Where("user_sub = ? AND kind IN ?", sub, llmUsageKinds).
		Where("(run_id IS NULL OR run_id NOT LIKE ?)", "measure:%")
	if app != "" {
		q = q.Where("app = ?", app)
	} else {
		q = q.Where("app IS NOT NULL")
	}
	if !since.IsZero() {
		q = q.Where("ts >= ?", since)
	}
	// has_cost splits a model's rows by whether they carry a stored cost, so a
	// group is priced by one rule (llmUSD) and the sum stays linear.
	var groups []group
	if err := q.Group("kind, model, run_id, has_cost").Scan(&groups).Error; err != nil {
		log.Printf("[usage] llm spend for %s/%s unreadable: %v", sub, app, err)
		return llmSpend{}, false
	}
	if len(groups) == 0 {
		return llmSpend{}, false
	}
	proxied := map[string]bool{}
	for _, g := range groups {
		if g.Kind == "claude_proxy" && g.RunID != nil {
			proxied[*g.RunID] = true
		}
	}
	rates := currentRates()
	out := llmSpend{ByModel: map[string]llmTally{}, ByRun: map[string]llmTally{}}
	lastOf := map[string]uint64{}
	for _, g := range groups {
		if g.Kind == "cycle_llm" && g.RunID != nil && proxied[*g.RunID] {
			continue // the proxy's row for the same call is counted instead
		}
		usd, notional := rates.llmUSD(g.Model, g.TokensIn, g.TokensOut, g.CostCents)
		out.add(g.Calls, g.TokensIn, g.TokensOut, usd)
		if notional {
			out.NotionalUSD += usd
		}
		model := g.Model
		if model == "" {
			model = "(unnamed)"
		}
		bm := out.ByModel[model]
		bm.add(g.Calls, g.TokensIn, g.TokensOut, usd)
		out.ByModel[model] = bm
		if g.RunID != nil && *g.RunID != "" {
			br := out.ByRun[*g.RunID]
			br.add(g.Calls, g.TokensIn, g.TokensOut, usd)
			out.ByRun[*g.RunID] = br
			lastOf[*g.RunID] = max(lastOf[*g.RunID], g.LastID)
		}
	}
	if out.Calls == 0 {
		return llmSpend{}, false
	}
	if len(out.ByRun) > llmByRunCap {
		ids := make([]string, 0, len(out.ByRun))
		for id := range out.ByRun {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return lastOf[ids[i]] > lastOf[ids[j]] })
		for _, id := range ids[llmByRunCap:] {
			delete(out.ByRun, id)
		}
		out.RunsOmitted = len(ids) - llmByRunCap
	}
	out.llmTally = out.rounded()
	out.NotionalUSD = math.Round(out.NotionalUSD*1e6) / 1e6
	for k, v := range out.ByModel {
		out.ByModel[k] = v.rounded()
	}
	for k, v := range out.ByRun {
		out.ByRun[k] = v.rounded()
	}
	return out, true
}
