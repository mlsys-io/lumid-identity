package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func llmInputs(t *testing.T, s string) map[string]any { return decodeInputs(t, s) }

func TestPooledLLMPlanKeysTheContent(t *testing.T) {
	a := `{"model":"claude-sonnet-4-6","system":"S","messages":[{"role":"user","content":"Q"}],"max_tokens":500}`
	b := `{"max_tokens":500,"messages":[{"content":"Q","role":"user"}],"system":"S","model":"claude-sonnet-4-6","name":"lbl"}`
	pa, err := llmPlan(llmInputs(t, a))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := llmPlan(llmInputs(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if measureKey(llmInstrument, pa.version, pa.keyed()) != measureKey(llmInstrument, pb.version, pb.keyed()) {
		t.Fatal("key order or a name label changed the key")
	}
	c := strings.Replace(a, `"Q"`, `"Q2"`, 1)
	pc, _ := llmPlan(llmInputs(t, c))
	if measureKey(llmInstrument, pc.version, pc.keyed()) == measureKey(llmInstrument, pa.version, pa.keyed()) {
		t.Fatal("a different prompt produced the same key")
	}
	d := strings.Replace(a, "500", "600", 1)
	pd, _ := llmPlan(llmInputs(t, d))
	if measureKey(llmInstrument, pd.version, pd.keyed()) == measureKey(llmInstrument, pa.version, pa.keyed()) {
		t.Fatal("max_tokens is part of the measurement but not of the key")
	}
}

func TestPooledLLMPlanRefusesWhatIsNotTheInstrument(t *testing.T) {
	cases := map[string]string{
		"unaccepted model": `{"model":"claude-opus-4-6","messages":[{"role":"user","content":"Q"}]}`,
		"self-hosted":      `{"model":"deepseek-v4.1-flash","messages":[{"role":"user","content":"Q"}]}`,
		"temperature":      `{"model":"claude-sonnet-4-6","temperature":0.7,"messages":[{"role":"user","content":"Q"}]}`,
		"last not user":    `{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"Q"},{"role":"assistant","content":"A"}]}`,
		"no messages":      `{"model":"claude-sonnet-4-6","messages":[]}`,
		"bad role":         `{"model":"claude-sonnet-4-6","messages":[{"role":"system","content":"Q"}]}`,
		"unknown key":      `{"model":"claude-sonnet-4-6","tools":[],"messages":[{"role":"user","content":"Q"}]}`,
		"max_tokens cap":   `{"model":"claude-sonnet-4-6","max_tokens":9000,"messages":[{"role":"user","content":"Q"}]}`,
	}
	for name, in := range cases {
		if _, err := llmPlan(llmInputs(t, in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// temperature 0 spelled out is fine; the allow-list is the env's.
	if _, err := llmPlan(llmInputs(t, `{"model":"claude-sonnet-4-6","temperature":0,"messages":[{"role":"user","content":"Q"}]}`)); err != nil {
		t.Errorf("temperature 0: %v", err)
	}
	t.Setenv("MEASURE_LLM_MODELS", "claude-sonnet-4-6,claude-opus-4-6")
	if _, err := llmPlan(llmInputs(t, cases["unaccepted model"])); err != nil {
		t.Errorf("an env-accepted model was refused: %v", err)
	}
}

func TestPooledLLMEstimateIsAnUpperBound(t *testing.T) {
	p, _ := llmPlan(llmInputs(t, `{"model":"claude-sonnet-4-6","system":"`+strings.Repeat("x", 3500)+
		`","messages":[{"role":"user","content":"Q"}],"max_tokens":1000}`))
	// ~1000 input tokens at $3/M + 1000 output at $15/M = $0.018
	if est := llmEstimate(p); est < 0.017 || est > 0.02 {
		t.Fatalf("estimate = %v, want about 0.018", est)
	}
}

func TestPooledLLMServedModelMustBeTheOneAsked(t *testing.T) {
	for _, served := range []string{"claude-sonnet-4-6", "claude-sonnet-4-6-20260115"} {
		if !llmServedAsAsked("claude-sonnet-4-6", served) {
			t.Errorf("%s refused", served)
		}
	}
	for _, served := range []string{"deepseek-v4.1-flash", "deepseek-v4-flash", "claude-sonnet-4-5", "claude-sonnet-4-60", ""} {
		if llmServedAsAsked("claude-sonnet-4-6", served) {
			t.Errorf("%s accepted as claude-sonnet-4-6", served)
		}
	}
}

// fakePool answers /v1/messages as the given model and records what it got.
type fakePool struct {
	mu     sync.Mutex
	model  string
	status int
	auth   []string
	bodies []string
}

func (f *fakePool) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.bodies = append(f.bodies, string(raw))
	model, status := f.model, f.status
	f.mu.Unlock()
	if status != 0 && status != 200 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"permission_error","message":"Opus models require the admin role"}}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"model": model, "stop_reason": "end_turn",
		"content": []map[string]any{{"type": "text", "text": "Top line: grow share."}},
		"usage":   map[string]any{"input_tokens": 1000, "output_tokens": 200},
	})
}

func TestPooledLLMCallRecordsUsageAndRefusesAnotherModel(t *testing.T) {
	pool := &fakePool{model: "claude-sonnet-4-6-20260115"}
	srv := httptest.NewServer(http.HandlerFunc(pool.handler))
	defer srv.Close()
	t.Setenv("MEASURE_LLM_PROXY_URL", srv.URL)
	body := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"Q"}],"max_tokens":500,"temperature":0}`)

	out, u, why := llmCall(context.Background(), "tok", "claude-sonnet-4-6", body)
	if why != "" || u == nil {
		t.Fatalf("call failed: %s", why)
	}
	if u.in != 1000 || u.out != 200 || u.cost != 0.006 { // 1000*3/1e6 + 200*15/1e6
		t.Fatalf("usage = %+v", *u)
	}
	var res map[string]any
	_ = json.Unmarshal([]byte(out), &res)
	if v, _ := res["value"].(map[string]any); v["text"] != "Top line: grow share." || v["served_model"] != "claude-sonnet-4-6-20260115" {
		t.Fatalf("value = %v", res["value"])
	}
	if pool.auth[0] != "Bearer tok" || !strings.Contains(pool.bodies[0], `"temperature":0`) {
		t.Fatalf("request = %v %v", pool.auth, pool.bodies)
	}

	// The aliasing failure mode: the pool answers with the in-house model.
	pool.model = "deepseek-v4.1-flash"
	_, u, why = llmCall(context.Background(), "tok", "claude-sonnet-4-6", body)
	if !strings.Contains(why, `answered with "deepseek-v4.1-flash"`) || u == nil || u.out != 200 {
		t.Fatalf("another model's answer was not refused (or its use not kept): %q %+v", why, u)
	}

	pool.status = 403
	_, _, why = llmCall(context.Background(), "tok", "claude-sonnet-4-6", body)
	if !strings.Contains(why, "HTTP 403") || !strings.Contains(why, "admin role") {
		t.Fatalf("refusal words = %q", why)
	}
}

func TestRunAndMeasureBearersCarryTheirClaims(t *testing.T) {
	testKeys(t)
	row := &models.RunCredential{ID: "cred-1", App: "mbb-consultant", Loop: "screen"}
	tok, _, _, err := common.IssueBridgeJWTWithClaims("u-1", "s@x", "user", runBearerAudience, nil, time.Minute,
		runBearerClaims(row))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := common.VerifyJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if cl.App != "mbb-consultant" || cl.Loop != "screen" || cl.RunID != "cred-1" || cl.MeasureModel != "" {
		t.Fatalf("run claims = %+v", cl.RunClaims)
	}
	// A plain bridge token is unchanged: no run claims at all.
	plain, _, _, _ := common.IssueBridgeJWT("u-1", "s@x", "user", runBearerAudience, nil, time.Minute)
	parts := strings.Split(plain, ".")
	if len(parts) != 3 || strings.Contains(decodeSeg(t, parts[1]), `"app"`) {
		t.Fatalf("plain bridge token grew claims: %s", decodeSeg(t, parts[1]))
	}
}

func decodeSeg(t *testing.T, s string) string {
	t.Helper()
	b, err := jwtSegDecode(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPooledLLMEndToEnd: POST → running → settles in the background → the
// second user is served the same answer for free, with what it saved. Needs a DB.
func TestPooledLLMEndToEnd(t *testing.T) {
	_, owner, other := fleetTestSetup(t)
	pool := &fakePool{model: "claude-sonnet-4-6"}
	srv := httptest.NewServer(http.HandlerFunc(pool.handler))
	defer srv.Close()
	t.Setenv("MEASURE_LLM_PROXY_URL", srv.URL)
	measureCleanup(t, subOf(t, owner), subOf(t, other))
	body := `{"instrument":"pooled-llm","app":"mbb-consultant","inputs":{"model":"claude-sonnet-4-6",` +
		`"system":"You are an analyst.","messages":[{"role":"user","content":"Size the market ` + t.Name() + `"}],"max_tokens":400}}`

	code, first := measureCall(t, "POST", "/api/v1/me/measure", body, owner)
	if code != http.StatusAccepted || first["status"] != "running" {
		t.Fatalf("first = %d %v", code, first)
	}
	key := first["key"].(string)
	var got map[string]any
	for i := 0; i < 50; i++ {
		_, got = measureCall(t, "GET", "/api/v1/me/measure/"+key, "", owner)
		if got["status"] == "succeeded" || got["status"] == "failed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	res, _ := got["result"].(map[string]any)
	if got["status"] != "succeeded" || res == nil {
		t.Fatalf("settled = %v", got)
	}
	usage, _ := res["usage"].(map[string]any)
	if usage["metered"] != "measured" || usage["cost_usd"] != 0.006 {
		t.Fatalf("usage = %v", usage)
	}
	// The bearer the pool saw names the model and the app, for the requester.
	cl, err := common.VerifyJWT(strings.TrimPrefix(pool.auth[0], "Bearer "))
	if err != nil || cl.MeasureModel != "claude-sonnet-4-6" || cl.App != "mbb-consultant" ||
		cl.Subject != subOf(t, owner) || !strings.HasPrefix(cl.RunID, "measure:") || cl.Scopes != "claude:proxy" {
		t.Fatalf("pool bearer claims = %+v err=%v", cl, err)
	}

	code, again := measureCall(t, "POST", "/api/v1/me/measure", body, other)
	ares, _ := again["result"].(map[string]any)
	if code != 200 || ares["reused"] != true || len(pool.bodies) != 1 {
		t.Fatalf("second user = %d %v (pool calls %d)", code, again, len(pool.bodies))
	}
	if au, _ := ares["usage"].(map[string]any); au["metered"] != "reused" || au["saved_cost_usd"] != 0.006 || au["cost_usd"] != 0.0 {
		t.Fatalf("reused usage = %v", ares["usage"])
	}
	// The owner's spend counts it; the other user's does not.
	if s := usageSpent(subOf(t, owner), "mbb-consultant", "", time.Time{}); s.USD != 0.006 {
		t.Errorf("owner spent = %v", s.USD)
	}
	if s := usageSpent(subOf(t, other), "mbb-consultant", "", time.Time{}); s.USD != 0 || s.SavedUSD != 0.006 {
		t.Errorf("other spent = %v saved = %v", s.USD, s.SavedUSD)
	}
}

func jwtSegDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// The generic budget check sees an LLM measurement coming: with a median own
// cost on record and compute.budget.usd 0.01, a fresh call is refused in words.
func TestPooledLLMBudgetRefusalUsesTheMedianCost(t *testing.T) {
	_, owner, _ := fleetTestSetup(t)
	sub := subOf(t, owner)
	measureCleanup(t, sub)
	if err := common.DB.AutoMigrate(&models.MeAppSpec{}); err != nil {
		t.Fatal(err)
	}
	app := "llm-budget-test"
	spec := "name: " + app + "\ncompute:\n  budget: {usd: 0.01, per: total}\n"
	common.DB.Where("user_sub = ? AND app = ?", sub, app).Delete(&models.MeAppSpec{})
	if err := common.DB.Create(&models.MeAppSpec{UserSub: sub, App: app, SpecYAML: spec,
		UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { common.DB.Where("user_sub = ? AND app = ?", sub, app).Delete(&models.MeAppSpec{}) })

	// One settled call that cost $0.006, charged to this user for this app.
	cost, tin, tout := 0.006, 1000, 200
	now := time.Now()
	key := "k-" + strings.ReplaceAll(t.Name(), "/", "-")
	row := models.MeasureResult{Key: key, Instrument: llmInstrument, Version: "claude-sonnet-4-6@v1",
		ShareScope: "global", Status: "succeeded", Executor: "llm", ExecutorSub: sub, ExecutorRef: "llm:claude-sonnet-4-6",
		ClaimedAt: now, SettledAt: &now, CostUSD: &cost, TokensIn: &tin, TokensOut: &tout}
	if err := common.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	req := models.MeasureRequest{UserSub: sub, Key: key, App: app, Outcome: "submitted"}
	common.DB.Create(&req)
	common.DB.Model(&row).Update("charged_request_id", req.ID)

	if usd, k := measureCostEstimate(llmInstrument); k == 0 || usd <= 0 {
		t.Fatalf("estimate = %v from %d", usd, k)
	}
	// $0.006 spent + about $0.006 more > $0.01.
	why := budgetRefusal(sub, app, "", llmInstrument, "MBB Consultant")
	if !strings.Contains(why, "Your MBB Consultant budget has $0 of $0.01 left; this would take about $0.01") {
		t.Fatalf("refusal = %q", why)
	}
	if s := usageSpent(sub, app, "", time.Time{}); s.TokensIn != 1000 || s.TokensOut != 200 || s.USD != 0.006 {
		t.Fatalf("spent = %+v", s)
	}
}
