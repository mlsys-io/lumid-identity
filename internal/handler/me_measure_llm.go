package handler

// pooled-llm — one call to a pooled model (genuine Claude), measured centrally.
//
// Why this exists (2026-11-28). For a non-admin, claude-proxy serves a
// `claude-sonnet*` / `claude-haiku*` request as the in-house model
// (aliasClaudeForRole), and lumid-llm refuses `claude-*` outright. So tenant app
// code cannot call real Claude, and an app that asked for Sonnet got a
// different model under the Sonnet name. Research apps still need the strong
// model for the one expensive step (confirming a candidate), the way MLSys needs
// the real GPU and quant needs the real backtest. So it is measured centrally,
// like those:
//
//   - content-keyed: identical (model, system, messages, max_tokens) is ONE row
//     for everyone, so a baseline answer is paid for once and shared;
//   - charged to the app's compute budget (spec compute.budget.usd) and a
//     per-user daily cap, refused in words BEFORE anything is spent;
//   - the call runs inside identity with a short-lived bearer minted for the
//     requesting user and naming exactly this model (RunClaims.MeasureModel).
//     claude-proxy serves that model genuinely for that bearer alone; tenant
//     code never sees the bearer;
//   - the reply's model is checked: if the pool served something else, the
//     measurement FAILS rather than record another model's answer under this
//     name.
//
// Temperature is fixed at 0 and a reused answer is the same sample for every
// requester, which is what a paired comparison needs (the same question gets the
// same baseline answer). A fresh sample is `fresh: true`, at full cost.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	llmInstrument      = "pooled-llm"
	llmInstrumentRev   = "v1" // bump when the request shape sent upstream changes
	llmDefaultModels   = "claude-sonnet-4-6"
	llmMaxTokensCap    = 8192
	llmDefaultMaxToken = 2000
	llmMaxMessages     = 64
	// One call's wall budget; a row still running after llmStale was lost (an
	// identity restart mid-call) and is settled failed so asking again retries.
	llmCallTimeout = 10 * time.Minute
	llmStale       = llmCallTimeout + 2*time.Minute
	llmBearerTTL   = llmCallTimeout + time.Minute
)

func init() {
	measureRegistry[llmInstrument] = measureInstrument{
		Name: llmInstrument,
		About: "One call to a pooled model (genuine Claude, for any role), measured centrally at temperature 0. " +
			"Identical requests are answered once for everyone, so a reused answer is free and is the same " +
			"sample for every caller; `fresh: true` draws a new one at full cost. Charged to the app's " +
			"compute budget (usd) and refused in words before anything is spent. A reply from any other " +
			"model than the one asked for fails the measurement instead of being recorded under its name.",
		Share: "global",
		Inputs: map[string]string{
			"model":      "an accepted pooled model id (see versions)",
			"system":     "the system prompt (text)",
			"messages":   "the conversation: [{role: user|assistant, content: text}], ending with the user's turn",
			"max_tokens": "most tokens the answer may use (default 2000, at most 8192); part of the key",
		},
		plan:     llmPlan,
		versions: llmAcceptedModels,
		executor: "llm",
		precheck: llmPrecheck,
	}
}

// llmAcceptedModels: MEASURE_LLM_MODELS (comma separated) or the default.
func llmAcceptedModels() []string {
	raw := strings.TrimSpace(os.Getenv("MEASURE_LLM_MODELS"))
	if raw == "" {
		raw = llmDefaultModels
	}
	out := []string{}
	for _, m := range strings.Split(raw, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

type llmMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func llmPlan(in map[string]any) (measurePlan, error) {
	for k := range in {
		switch k {
		case "model", "system", "messages", "max_tokens", "temperature", "name":
		default:
			return measurePlan{}, fmt.Errorf("unknown input %q; pooled-llm takes model, system, messages, max_tokens", k)
		}
	}
	model, _ := in["model"].(string)
	model = strings.TrimSpace(model)
	accepted := false
	for _, m := range llmAcceptedModels() {
		if m == model {
			accepted = true
		}
	}
	if !accepted {
		return measurePlan{}, fmt.Errorf("model %q is not measured here; accepted: %s", model,
			strings.Join(llmAcceptedModels(), ", "))
	}
	if t, present := in["temperature"]; present {
		if f, err := strconv.ParseFloat(fmt.Sprint(t), 64); err != nil || f != 0 {
			return measurePlan{}, errors.New("temperature is fixed at 0 (a measurement must be repeatable); leave it out")
		}
	}
	system, _ := in["system"].(string)
	maxTok := llmDefaultMaxToken
	if v, present := in["max_tokens"]; present {
		n, err := strconv.Atoi(fmt.Sprint(v))
		if err != nil || n < 1 || n > llmMaxTokensCap {
			return measurePlan{}, fmt.Errorf("max_tokens must be a whole number from 1 to %d", llmMaxTokensCap)
		}
		maxTok = n
	}
	raw, _ := json.Marshal(in["messages"])
	var msgs []llmMessage
	if err := json.Unmarshal(raw, &msgs); err != nil || len(msgs) == 0 {
		return measurePlan{}, errors.New("messages must be a non-empty list of {role, content} with text content")
	}
	if len(msgs) > llmMaxMessages {
		return measurePlan{}, fmt.Errorf("at most %d messages", llmMaxMessages)
	}
	clean := make([]any, 0, len(msgs))
	for i, m := range msgs {
		if m.Role != "user" && m.Role != "assistant" {
			return measurePlan{}, fmt.Errorf("message %d: role must be user or assistant", i+1)
		}
		if strings.TrimSpace(m.Content) == "" {
			return measurePlan{}, fmt.Errorf("message %d: content is empty", i+1)
		}
		clean = append(clean, map[string]any{"role": m.Role, "content": m.Content})
	}
	if msgs[len(msgs)-1].Role != "user" {
		return measurePlan{}, errors.New("the last message must be the user's")
	}
	name, _ := in["name"].(string)
	material := map[string]any{"model": model, "system": system, "messages": clean, "max_tokens": maxTok}
	return measurePlan{
		version:  model + "@" + llmInstrumentRev,
		label:    model,
		material: material,
		name:     name,
	}, nil
}

// ── Price, estimate and caps ─────────────────────────────────────────────

// llmRate: notional list USD per million tokens (in, out) — the same table
// claude-proxy's modelCostCents uses (verified there 2026-08-12), so an
// estimate here and the proxy's own charge agree. The pooled accounts are
// subscriptions: this values the use, it is not an invoice.
func llmRate(model string) (in, out float64) {
	switch {
	case strings.HasPrefix(model, "claude-opus"):
		return 5, 25
	case strings.HasPrefix(model, "claude-haiku"):
		return 1, 5
	}
	return 3, 15 // sonnet, and the conservative default
}

func llmCost(model string, tin, tout int) float64 {
	pin, pout := llmRate(model)
	return math.Round((float64(tin)*pin+float64(tout)*pout)/1e6*1e6) / 1e6
}

// llmEstimate: an UPPER bound for the precheck — the prompt at ~3.5 characters
// a token, plus every output token max_tokens allows.
func llmEstimate(plan measurePlan) float64 {
	chars := len(fmt.Sprint(plan.material["system"]))
	if msgs, isList := plan.material["messages"].([]any); isList {
		for _, m := range msgs {
			if mm, isMap := m.(map[string]any); isMap {
				chars += len(fmt.Sprint(mm["content"]))
			}
		}
	}
	maxTok, _ := plan.material["max_tokens"].(int)
	model, _ := plan.material["model"].(string)
	return llmCost(model, int(float64(chars)/3.5)+1, maxTok)
}

func llmEnvFloat(name string, def float64) float64 {
	if f, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil && f >= 0 {
		return f
	}
	return def
}

// llmSpentSince: what this user's own fresh pooled-llm measurements cost
// since t (the row's executor paid for it; reused answers cost nothing).
func llmSpentSince(sub string, t time.Time) float64 {
	var total *float64
	common.DB.Model(&models.MeasureResult{}).
		Where("instrument = ? AND executor_sub = ? AND claimed_at >= ? AND cost_usd IS NOT NULL", llmInstrument, sub, t).
		Select("SUM(cost_usd)").Scan(&total)
	if total == nil {
		return 0
	}
	return *total
}

// llmPrecheck: the per-user running cap (wait), the per-user daily cap and the
// app's own usd budget (refusals, in words), all before anything is claimed.
func llmPrecheck(c *gin.Context, sub string, plan measurePlan, app, workflow string) (string, bool) {
	var running int64
	common.DB.Model(&models.MeasureResult{}).
		Where("instrument = ? AND executor_sub = ? AND status IN ?", llmInstrument, sub, []string{"queued", "running"}).
		Count(&running)
	if limit := int64(measureLimit("MEASURE_LLM_RUNNING_CAP", 4)); running >= limit {
		return fmt.Sprintf("waiting for a model slot (%d of %d in use)", running, limit), true
	}
	est := llmEstimate(plan)
	day := time.Now().UTC().Truncate(24 * time.Hour)
	if limit := llmEnvFloat("MEASURE_LLM_DAILY_USD", 10); limit > 0 {
		if spent := llmSpentSince(sub, day); spent+est > limit {
			return fmt.Sprintf("You have $%.2f of today's $%.2f for pooled-model measurements left; this call "+
				"could cost up to $%.2f. It resets at 00:00 UTC.", math.Max(0, limit-spent), limit, est), false
		}
	}
	if app == "" {
		return "", false
	}
	sb := appBudgets(sub, app)
	check := func(b computeBudget, scope, wf string) string {
		if b.USD <= 0 {
			return ""
		}
		s := usageSpent(sub, app, wf, b.since(time.Now()))
		if s.USD+est > b.USD {
			return fmt.Sprintf("%s has $%.2f of $%.2f left; this call could cost up to $%.2f",
				scope, math.Max(0, b.USD-s.USD), b.USD, est)
		}
		return ""
	}
	if why := check(sb.App, "Your "+app+" budget", ""); why != "" {
		return why, false
	}
	if wb, declared := sb.Workflows[workflow]; declared {
		if why := check(wb, "The "+workflow+" workflow's budget", workflow); why != "" {
			return why, false
		}
	}
	return "", false
}

// ── The call ─────────────────────────────────────────────────────────────

func llmProxyURL() string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("MEASURE_LLM_PROXY_URL")), "/"); u != "" {
		return u
	}
	return "http://claude-proxy.lumid.svc.cluster.local:8080"
}

// llmMeasureSubmit claims the row as running and makes the call in the
// background; the row settles when the reply arrives. The caller polls
// GET /me/measure/:key, as for every instrument.
func llmMeasureSubmit(row *models.MeasureResult, plan measurePlan, sub, app string) error {
	var u models.User
	if err := common.DB.First(&u, "id = ?", sub).Error; err != nil {
		return errors.New("unknown user")
	}
	model, _ := plan.material["model"].(string)
	tok, _, _, err := common.IssueBridgeJWTWithClaims(u.ID, u.Email, u.Role, "lumid-ecosystem", nil, llmBearerTTL,
		common.RunClaims{App: app, RunID: "measure:" + row.Key, MeasureModel: model})
	if err != nil {
		return fmt.Errorf("mint: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"model":       model,
		"system":      plan.material["system"],
		"messages":    plan.material["messages"],
		"max_tokens":  plan.material["max_tokens"],
		"temperature": 0,
	})
	ref := "llm:" + model
	row.Status, row.ExecutorRef = "running", ref
	if err := common.DB.Model(row).Updates(map[string]any{"status": "running", "executor_ref": ref}).Error; err != nil {
		return err
	}
	key := row.Key
	go func() {
		defer func() {
			if r := recover(); r != nil {
				llmSettleKey(key, "failed", "", fmt.Sprintf("the model call crashed: %v", r), nil)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), llmCallTimeout)
		defer cancel()
		out, usage, why := llmCall(ctx, tok, model, body)
		if why != "" {
			llmSettleKey(key, "failed", "", why, usage)
			return
		}
		llmSettleKey(key, "succeeded", out, "", usage)
	}()
	return nil
}

type llmUsage struct {
	in, out int
	cost    float64
}

type llmReply struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens         int `json:"input_tokens"`
		OutputTokens        int `json:"output_tokens"`
		CacheReadTokens     int `json:"cache_read_input_tokens"`
		CacheCreationTokens int `json:"cache_creation_input_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// llmCall returns the canonical result JSON, what it used, or why it failed.
func llmCall(ctx context.Context, bearer, model string, body []byte) (string, *llmUsage, string) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, llmProxyURL()+"/v1/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := (&http.Client{Timeout: llmCallTimeout}).Do(req)
	if err != nil {
		return "", nil, "the model pool could not be reached: " + fleetClip(err.Error(), 200)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var r llmReply
	_ = json.Unmarshal(raw, &r)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fleetClip(string(raw), 300)
		if r.Error != nil && r.Error.Message != "" {
			msg = r.Error.Message
		}
		return "", nil, fmt.Sprintf("the model pool refused the call (HTTP %d): %s", resp.StatusCode, msg)
	}
	tin := r.Usage.InputTokens + r.Usage.CacheReadTokens + r.Usage.CacheCreationTokens
	usage := &llmUsage{in: tin, out: r.Usage.OutputTokens, cost: llmCost(model, tin, r.Usage.OutputTokens)}
	// The answer must come from the model asked for. A reply from another one
	// (an alias the proxy applied) is spent, so it is charged, but it is never
	// recorded as this model's answer.
	if !llmServedAsAsked(model, r.Model) {
		return "", usage, fmt.Sprintf("the pool answered with %q, not %q; nothing is recorded under %q", r.Model, model, model)
	}
	var text strings.Builder
	for _, b := range r.Content {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return "", usage, "the model returned no text (stop reason " + r.StopReason + ")"
	}
	out, _ := canonicalJSON(map[string]any{
		"value": map[string]any{"text": text.String(), "served_model": r.Model, "stop_reason": r.StopReason},
		"metrics": map[string]any{"tokens_in": tin, "tokens_out": r.Usage.OutputTokens,
			"cost_usd": usage.cost},
	})
	return out, usage, ""
}

// llmServedAsAsked: Anthropic replies carry the dated id (claude-sonnet-4-6 →
// claude-sonnet-4-6 or claude-sonnet-4-6-2026…); anything else is another model.
func llmServedAsAsked(asked, served string) bool {
	served = strings.TrimSpace(served)
	return served == asked || strings.HasPrefix(served, asked+"-")
}

func llmSettleKey(key, status, result, msg string, u *llmUsage) {
	var row models.MeasureResult
	if common.DB.First(&row, "mkey = ?", key).Error != nil {
		return
	}
	if row.Status != "running" && row.Status != "queued" {
		return // settled already (the stale sweep got there first)
	}
	if u != nil {
		cost := u.cost
		common.DB.Model(&row).Updates(map[string]any{"cost_usd": cost, "tokens_in": u.in, "tokens_out": u.out,
			"metered": "measured"})
	}
	measureSettle(&row, status, result, msg)
}

// llmAdvance: the call runs in the background; a row it never settled (identity
// restarted mid-call) is failed once it is older than the call could take.
func llmAdvance(row *models.MeasureResult) {
	if (row.Status == "queued" || row.Status == "running") && time.Since(row.ClaimedAt) > llmStale {
		measureSettle(row, "failed", "", "the model call did not finish (the service restarted); asking again retries it")
	}
}

// llmUsageBlock: a pooled-llm result's usage, in the round-10 contract's names
// (tokens are this instrument's own numbers; reused costs 0 and says what it saved).
func llmUsageBlock(row *models.MeasureResult, reused bool) gin.H {
	out := gin.H{"llm_models": strings.TrimPrefix(row.ExecutorRef, "llm:")}
	tin, tout := 0, 0
	if row.TokensIn != nil {
		tin = *row.TokensIn
	}
	if row.TokensOut != nil {
		tout = *row.TokensOut
	}
	if reused {
		out["cost_usd"], out["tokens_in"], out["tokens_out"] = 0.0, 0, 0
		out["saved_cost_usd"], out["saved_tokens_in"], out["saved_tokens_out"] = *row.CostUSD, tin, tout
		out["metered"] = "reused"
		return out
	}
	out["cost_usd"], out["tokens_in"], out["tokens_out"], out["llm_calls"] = *row.CostUSD, tin, tout, 1
	out["metered"] = "measured"
	return out
}
