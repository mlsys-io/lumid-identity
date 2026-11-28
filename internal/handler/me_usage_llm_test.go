package handler

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// ── Pure: rates, pricing, words ──────────────────────────────────────────

func TestLLMRateLookupByModel(t *testing.T) {
	r := currentRates()
	for _, c := range []struct {
		model   string
		in, out float64
		named   bool
	}{
		{"deepseek-v4.1-flash", 0.14, 0.42, true},
		{"deepseek/deepseek-v4.1-flash-1017", 0.14, 0.42, true}, // vendor prefix, dated suffix
		{"deepseek-v4-flash-0731", 0.04, 0.08, true},            // the generic deepseek entry
		{"Qwen3.8-27B", 0.10, 0.40, true},
		{"qwen3-embedding", 0.23, 1.13, true},
		{"claude-sonnet-4-6[1m]", 3, 15, true},
		{"haiku", 1, 5, true}, // the CLI alias
		{"kimi-k3", 0.50, 2.00, false},
	} {
		got, named, ok := r.llmRateFor(c.model)
		if !ok || got.InPerMTok != c.in || got.OutPerMTok != c.out || named != c.named {
			t.Errorf("%s → %+v named=%v ok=%v", c.model, got, named, ok)
		}
	}
}

func TestLLMPricingRealForAnthropicNotionalForSelfHosted(t *testing.T) {
	r := currentRates()
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	// Anthropic with the proxy's stored cost: that cost, not the table.
	if usd, notional := r.llmUSD("claude-opus-5-5", 1_000_000, 0, 123); !near(usd, 1.23) || notional {
		t.Errorf("anthropic stored = %v %v", usd, notional)
	}
	// Anthropic with tokens and no stored cost (a cycle's own charge): list price.
	if usd, notional := r.llmUSD("sonnet", 1_000_000, 100_000, 0); !near(usd, 3+1.5) || !notional {
		t.Errorf("anthropic unpriced = %v %v", usd, notional)
	}
	// Self-hosted: notional rate even though the proxy booked its own figure.
	if usd, notional := r.llmUSD("deepseek-v4.1-flash", 2_000_000, 1_000_000, 999); !near(usd, 0.28+0.42) || !notional {
		t.Errorf("self-hosted = %v %v", usd, notional)
	}
	// Self-hosted, never 0: "free" is reserved for reuse.
	if usd, _ := r.llmUSD("qwen3.8-27b", 1000, 1000, 0); usd <= 0 {
		t.Errorf("self-hosted priced at %v", usd)
	}
	// A model the table does not name keeps its stored (billed) cost.
	if usd, notional := r.llmUSD("kimi-k3", 1_000_000, 0, 300); !near(usd, 3) || notional {
		t.Errorf("unnamed stored = %v %v", usd, notional)
	}
	// ...and without one falls back to "*".
	if usd, notional := r.llmUSD("kimi-k3", 1_000_000, 0, 0); !near(usd, 0.5) || !notional {
		t.Errorf("unnamed unpriced = %v %v", usd, notional)
	}
	if usd, _ := r.llmUSD("deepseek-v4.1-flash", 0, 0, 0); usd != 0 {
		t.Errorf("no tokens, no cost = %v", usd)
	}
}

func TestLLMRatesOverrideAndExposure(t *testing.T) {
	t.Setenv("USAGE_RATES", `{"llm":{"DeepSeek-V4.1-Flash*":{"in_per_mtok":0.2,"out_per_mtok":0.6},"bad":{"in_per_mtok":-1,"out_per_mtok":1}}}`)
	r := currentRates()
	if got, _, _ := r.llmRateFor("deepseek-v4.1-flash"); got.InPerMTok != 0.2 || got.OutPerMTok != 0.6 {
		t.Fatalf("override = %+v", got)
	}
	if _, has := r.LLM["bad"]; has {
		t.Fatal("a negative rate must be ignored")
	}
	if r.LLM["qwen*"].InPerMTok != 0.23 || r.GPUHour["RTX 5080"] != 0.25 {
		t.Fatal("an override must keep the other defaults")
	}

	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.GET("/rates", MeUsageRates)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/rates", nil))
	var resp struct {
		Data struct {
			LLM      map[string]map[string]float64 `json:"llm"`
			Notional bool                          `json:"notional"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.LLM["deepseek-v4.1-flash*"]["in_per_mtok"] != 0.2 || resp.Data.LLM["*"]["out_per_mtok"] != 2 ||
		!resp.Data.Notional {
		t.Fatalf("rates on the wire = %s", w.Body.String())
	}
}

func TestBudgetWords(t *testing.T) {
	b := computeBudget{USD: 40, Per: "total"}
	scope := budgetScope("mbb-consultant")
	if w := budgetWords(b, budgetSpend{USD: 34}, budgetEstimate{USD: 7}, scope); w != "Your mbb-consultant budget has $6 of $40 left; this would take about $7" {
		t.Errorf("over by estimate: %q", w)
	}
	if w := budgetWords(b, budgetSpend{USD: 39.6}, budgetEstimate{USD: 0.5}, scope); w != "Your mbb-consultant budget has $0.40 of $40 left; this would take about $0.50" {
		t.Errorf("cents: %q", w)
	}
	if w := budgetWords(b, budgetSpend{USD: 41}, budgetEstimate{}, scope); w != "Your mbb-consultant budget has $0 of $40 left" {
		t.Errorf("spent, no estimate: %q", w)
	}
	if w := budgetWords(b, budgetSpend{USD: 39.99}, budgetEstimate{}, scope); w != "" {
		t.Errorf("not yet spent, no estimate: %q", w)
	}
	g := computeBudget{GPUMinutes: 168}
	if w := budgetWords(g, budgetSpend{GPUS: 159 * 60}, budgetEstimate{GPUS: 600}, budgetScope("trace-lab")); w != "Your trace-lab budget has 9 of 168 GPU-min left; this would take about 10" {
		t.Errorf("gpu: %q", w)
	}
	c := computeBudget{CPUMinutes: 10}
	if w := budgetWords(c, budgetSpend{CPUS: 9.5 * 60}, budgetEstimate{CPUS: 45}, budgetScope("")); w != "Your budget has under 1 of 10 CPU-min left; this would take about under 1" {
		t.Errorf("cpu: %q", w)
	}
	if w := budgetWords(c, budgetSpend{CPUS: 1.5 * 60}, budgetEstimate{CPUS: 9 * 60}, budgetScope("x")); w != "Your x budget has 8.5 of 10 CPU-min left; this would take about 9" {
		t.Errorf("cpu decimals: %q", w)
	}
	for v, want := range map[float64]string{0: "$0", 0.004: "$0", 0.005: "$0.01", 6: "$6", 5.999: "$6", 12.5: "$12.50"} {
		if got := fmtBudgetUSD(v); got != want {
			t.Errorf("fmtBudgetUSD(%v) = %q, want %q", v, got, want)
		}
	}
}

// ── DB-backed (TEST_MYSQL_DSN) ───────────────────────────────────────────

func llmTestUser(t *testing.T) string {
	t.Helper()
	db := setupClaudePoolTestDB(t)
	sub := claudePoolTestUser(t, db, "llmu")
	t.Cleanup(func() {
		db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
		db.Where("user_sub = ?", sub).Delete(&models.MeAppSpec{})
	})
	return sub
}

func llmEvent(t *testing.T, sub, kind, app, run, model string, in, out, cents int, ts time.Time) {
	t.Helper()
	ev := models.UsageEvent{UserSub: sub, Ts: ts, Kind: kind, Model: model, InputTokens: in, OutputTokens: out,
		CostCents: cents, App: optStrTest(app), RunID: optStrTest(run)}
	if err := common.DB.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
}

func optStrTest(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func llmSpec(t *testing.T, sub, app, spec string) {
	t.Helper()
	common.DB.Where("user_sub = ? AND app = ?", sub, app).Delete(&models.MeAppSpec{})
	if err := common.DB.Create(&models.MeAppSpec{UserSub: sub, App: app, SpecYAML: spec, UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
}

func TestLLMSpentSumsAttributedCallsExcludingMeasurements(t *testing.T) {
	sub := llmTestUser(t)
	app, now := "llm-sum-test", time.Now().UTC()
	// run-a: one proxied Sonnet call ($0.25 stored) and the cycle's own count of
	// the same call (cycle_llm, no cost) — counted once, through the proxy.
	llmEvent(t, sub, "claude_proxy", app, "run-a", "claude-sonnet-4-6", 50_000, 10_000, 25, now.Add(-time.Hour))
	llmEvent(t, sub, "cycle_llm", app, "run-a", "claude-sonnet-4-6", 50_000, 10_000, 0, now.Add(-time.Hour))
	// run-b: two self-hosted calls, notional: 2M in × 0.14 + 1M out × 0.42 = $0.70.
	llmEvent(t, sub, "claude_proxy", app, "run-b", "deepseek-v4.1-flash", 1_000_000, 500_000, 35, now.Add(-30*time.Minute))
	llmEvent(t, sub, "claude_proxy", app, "run-b", "deepseek-v4.1-flash", 1_000_000, 500_000, 35, now.Add(-20*time.Minute))
	// run-c: an operator cycle with no proxy row: its cycle_llm row counts, at
	// Haiku list price: 1M × $1 = $1.
	llmEvent(t, sub, "cycle_llm", app, "run-c", "haiku", 1_000_000, 0, 0, now.Add(-10*time.Minute))
	// Excluded: a pooled-llm measurement's call (counted via measure rows), another
	// app, an unattributed chat, a non-LLM kind, and one before `since`.
	llmEvent(t, sub, "claude_proxy", app, "measure:abc", "claude-sonnet-4-6", 9_000_000, 9_000_000, 9999, now)
	llmEvent(t, sub, "claude_proxy", "other-app", "run-z", "claude-sonnet-4-6", 1, 1, 500, now)
	llmEvent(t, sub, "chat", "", "", "claude-sonnet-4-6", 1, 1, 700, now)
	llmEvent(t, sub, "external_api", app, "run-a", "", 0, 0, 0, now)
	llmEvent(t, sub, "claude_proxy", app, "run-old", "claude-sonnet-4-6", 1, 1, 800, now.Add(-72*time.Hour))

	l, ok := llmSpent(sub, app, now.Add(-24*time.Hour))
	if !ok {
		t.Fatal("no llm block")
	}
	if l.Calls != 4 || l.TokensIn != 3_050_000 || l.TokensOut != 1_010_000 || l.CostUSD != 0.25+0.70+1 {
		t.Fatalf("llm = %+v", l)
	}
	if l.NotionalUSD != 1.70 {
		t.Errorf("notional = %v", l.NotionalUSD)
	}
	if l.ByModel["deepseek-v4.1-flash"].Calls != 2 || l.ByModel["deepseek-v4.1-flash"].CostUSD != 0.70 ||
		l.ByModel["claude-sonnet-4-6"].CostUSD != 0.25 || l.ByModel["haiku"].CostUSD != 1 {
		t.Errorf("by_model = %+v", l.ByModel)
	}
	if len(l.ByRun) != 3 || l.ByRun["run-a"].Calls != 1 || l.ByRun["run-b"].CostUSD != 0.70 {
		t.Errorf("by_run = %+v", l.ByRun)
	}
	if _, has := l.ByRun["measure:abc"]; has {
		t.Error("a measurement's call must not be in by_run")
	}
	// All time picks up the old row too.
	if all, _ := llmSpent(sub, app, time.Time{}); all.Calls != 5 || all.CostUSD != 1.95+8 {
		t.Errorf("all time = %+v", all.llmTally)
	}
	// The budget sees it: usageSpent's USD carries the LLM spend at app level.
	if s := usageSpent(sub, app, "", now.Add(-24*time.Hour)); !s.HasLLM || s.USD != 1.95 || s.GPUS != 0 {
		t.Errorf("usageSpent = USD %v llm %v", s.USD, s.HasLLM)
	}
	if s := usageSpent(sub, app, "some-workflow", time.Time{}); s.HasLLM || s.USD != 0 {
		t.Error("a workflow's spend has no LLM part (usage_events carry no workflow)")
	}
	if _, ok := llmSpent(sub, "never-ran", time.Time{}); ok {
		t.Error("no calls = no block (unset, never zeros)")
	}
}

func TestMeUsageCarriesTheLLMBlockAndAddsItToCost(t *testing.T) {
	_, owner, _ := fleetTestSetup(t)
	sub := subOf(t, owner)
	t.Cleanup(func() {
		common.DB.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
		common.DB.Where("user_sub = ?", sub).Delete(&models.MeAppSpec{})
	})
	app := "llm-me-usage-test"
	llmSpec(t, sub, app, "name: "+app+"\ncompute:\n  budget: {usd: 5, per: total}\n")
	llmEvent(t, sub, "claude_proxy", app, "run-1", "claude-opus-5-5", 10_000, 2_000, 150, time.Now().UTC())

	g := gin.New()
	g.GET("/u", MeUsage)
	r := httptest.NewRequest(http.MethodGet, "/u?app="+app, nil)
	r.Header.Set("Authorization", "Bearer "+owner)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	var resp struct {
		Data struct {
			Used struct {
				CostUSD float64        `json:"cost_usd"`
				GPUS    float64        `json:"gpu_s"`
				LLM     map[string]any `json:"llm"`
			} `json:"used"`
			Remaining map[string]float64 `json:"remaining"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	u := resp.Data.Used
	if u.CostUSD != 1.5 || u.LLM == nil || u.LLM["calls"] != 1.0 || u.LLM["cost_usd"] != 1.5 ||
		u.LLM["tokens_in"] != 10000.0 || resp.Data.Remaining["cost_usd"] != 3.5 {
		t.Fatalf("usage = %s", w.Body.String())
	}
	for _, k := range []string{"by_model", "by_run", "tokens_out", "notional_usd"} {
		if _, has := u.LLM[k]; !has {
			t.Errorf("llm block lacks %s: %v", k, u.LLM)
		}
	}
}

func verdictCall(t *testing.T, body map[string]any) (int, budgetVerdict) {
	t.Helper()
	g := gin.New()
	g.POST("/v", InternalBudgetVerdict)
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v", bytes.NewReader(b)))
	var resp struct {
		Data budgetVerdict `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp.Data
}

func TestBudgetVerdictOkRefusedUndeclaredAndCached(t *testing.T) {
	sub := llmTestUser(t)
	gin.SetMode(gin.TestMode)
	clock := time.Now()
	budgetVerdictNow = func() time.Time { return clock }
	t.Cleanup(func() { budgetVerdictNow = time.Now })
	app, bare := "llm-verdict-test", "llm-verdict-none"
	t.Cleanup(func() { invalidateBudgetVerdict(sub, app); invalidateBudgetVerdict(sub, bare) })
	llmSpec(t, sub, app, "name: "+app+"\ncompute:\n  budget: {usd: 1, gpu_minutes: 10, per: week}\n")
	llmSpec(t, sub, bare, "name: "+bare+"\n")
	llmEvent(t, sub, "claude_proxy", app, "run-1", "claude-sonnet-4-6", 1, 1, 60, time.Now().UTC()) // $0.60

	// Undeclared: ok, no words, no budget.
	code, v := verdictCall(t, map[string]any{"user_sub": sub, "app": bare, "estimate": map[string]any{"usd": 100}})
	if code != 200 || !v.OK || v.Words != "" || v.Budget != nil {
		t.Fatalf("undeclared = %d %+v", code, v)
	}
	// Fits.
	_, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app, "estimate": map[string]any{"usd": 0.3}})
	if !v.OK || v.Words != "" || v.Budget == nil || v.Budget.USD != 1 || v.Left["usd"] != 0.4 || v.Left["gpu_minutes"] != 10.0 {
		t.Fatalf("fits = %+v", v)
	}
	// Refused by the estimate, in the shared words.
	_, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app, "estimate": map[string]any{"usd": 0.5}})
	if v.OK || v.Words != "Your llm-verdict-test budget has $0.40 of $1 left; this would take about $0.50" {
		t.Fatalf("refused = %+v", v)
	}
	// No estimate (the proxy's hard stop): fits until spent.
	if _, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app}); !v.OK {
		t.Fatalf("no estimate = %+v", v)
	}

	// Cached: a row written behind the cache's back is not seen inside the TTL...
	llmEvent(t, sub, "claude_proxy", app, "run-2", "claude-sonnet-4-6", 1, 1, 50, time.Now().UTC())
	if _, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app}); !v.OK || v.Left["usd"] != 0.4 {
		t.Fatalf("cached = %+v", v)
	}
	// ...and is after it.
	clock = clock.Add(budgetVerdictTTL + time.Second)
	if _, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app}); v.OK || v.Left["usd"] != 0.0 ||
		v.Words != "Your llm-verdict-test budget has $0 of $1 left" {
		t.Fatalf("after ttl = %+v", v)
	}

	// A charge landing through /internal/usage/charge drops the entry at once.
	common.DB.Where("user_sub = ? AND app = ?", sub, app).Delete(&models.UsageEvent{})
	if _, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app}); v.OK {
		t.Fatal("still the cached refusal expected inside the TTL")
	}
	g := gin.New()
	g.POST("/charge", InternalUsageCharge)
	cb, _ := json.Marshal(map[string]any{"user_sub": sub, "kind": "claude_proxy", "model": "claude-haiku-4-5",
		"input_tokens": 1, "output_tokens": 1, "cost_cents": 10, "app": app, "run_id": "run-3"})
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/charge", bytes.NewReader(cb)))
	if w.Code != 200 {
		t.Fatalf("charge = %d %s", w.Code, w.Body.String())
	}
	if _, v = verdictCall(t, map[string]any{"user_sub": sub, "app": app}); !v.OK || v.Left["usd"] != 0.9 {
		t.Fatalf("after charge = %+v", v)
	}

	// Bad bodies.
	if code, _ := verdictCall(t, map[string]any{"user_sub": sub}); code != 400 {
		t.Errorf("no app = %d", code)
	}
	if code, _ := verdictCall(t, map[string]any{"user_sub": sub, "app": app, "estimate": map[string]any{"usd": -1}}); code != 400 {
		t.Errorf("negative estimate = %d", code)
	}
}

func TestBudgetVerdictRunCredentialIsBoundToItsUserAndApp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.POST("/v", func(c *gin.Context) {
		c.Set(ctxRunCredential, &models.RunCredential{UserID: "u-1", App: "app-a"})
		c.Next()
	}, InternalBudgetVerdict)
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"user_sub":"u-2","app":"app-a"}`, 403},
		{`{"user_sub":"u-1","app":"app-b"}`, 403},
	} {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v", strings.NewReader(c.body)))
		if w.Code != c.want {
			t.Errorf("%s → %d, want %d", c.body, w.Code, c.want)
		}
	}
}
