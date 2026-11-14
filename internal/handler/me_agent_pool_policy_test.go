package handler

import (
	"context"
	"net/http"
	"testing"
)

func mustProvider(t *testing.T, id string) llmProvider {
	t.Helper()
	p, ok := providerByID(id)
	if !ok {
		t.Fatalf("provider %q missing from llmProviders", id)
	}
	return p
}

// The deepseek chip calls lumid-llm directly, so it IS on-prem and must be
// closed by allow_onprem=false — the hole this file exists to close.
func TestOnpremOffHidesSelfHostedChips(t *testing.T) {
	ds := mustProvider(t, "deepseek-v4.1-flash")
	if !providerIsOnprem(ds) {
		t.Fatal("deepseek chip not classed on-prem")
	}
	off := poolAccess{Onprem: false}
	for _, role := range []string{"user", "admin", "super_admin"} {
		if providerPoolAllowed(role, off, ds) {
			t.Errorf("role=%s: deepseek selectable on an on-prem-off pool", role)
		}
	}
	if !providerPoolAllowed("user", statusQuoPoolAccess, ds) {
		t.Fatal("status quo must keep deepseek open to role=user")
	}
}

// role=user on an on-prem-off pool has no door left: refuse, never
// silently hand them some other model.
func TestOnpremOffLeavesUserNothing(t *testing.T) {
	if p, _, ok := resolveProviderForCaller("deepseek-v4.1-flash", "user", poolAccess{Onprem: false}); ok {
		t.Fatalf("expected no provider, got %s", p.id)
	}
}

// An admin on an on-prem-off pool falls back to a pooled-Claude chip, and
// the downgrade is named.
func TestOnpremOffAdminFallsBackOffFleet(t *testing.T) {
	p, note, ok := resolveProviderForCaller("deepseek-v4.1-flash", "admin", poolAccess{Onprem: false})
	if !ok || providerIsOnprem(p) {
		t.Fatalf("admin should fall back to a non-fleet provider, got %q ok=%v", p.id, ok)
	}
	if note == "" {
		t.Fatal("downgrade must be named")
	}
}

// Fable mirrors claude-proxy modelAllowed: super_admin by role, anyone else by
// the pool grant. Before, the grant did nothing in lum.id chat.
func TestFableFollowsPoolGrant(t *testing.T) {
	fb := mustProvider(t, "claude-code-fable")
	if !providerIsFable(fb) {
		t.Fatal("fable chip not classed fable")
	}
	cases := []struct {
		role  string
		grant bool
		want  bool
	}{
		{"super_admin", false, true},
		{"admin", false, false},
		{"admin", true, true},
		{"user", true, true},
		{"user", false, false},
	}
	for _, c := range cases {
		pa := poolAccess{Onprem: true, Fable: c.grant}
		if got := providerPoolAllowed(c.role, pa, fb); got != c.want {
			t.Errorf("role=%s grant=%v: got %v want %v", c.role, c.grant, got, c.want)
		}
		p, _, ok := resolveProviderForCaller("claude-code-fable", c.role, pa)
		if c.want && (!ok || p.id != "claude-code-fable") {
			t.Errorf("role=%s grant=%v: pick resolved to %q, want fable", c.role, c.grant, p.id)
		}
		if !c.want && p.id == "claude-code-fable" {
			t.Errorf("role=%s grant=%v: fable served without a grant", c.role, c.grant)
		}
	}
}

func TestOpenRouterVetoOnlyOnLumidLLMWithVerdictOff(t *testing.T) {
	mk := func(url string, pa *poolAccess) *http.Request {
		ctx := context.Background()
		if pa != nil {
			ctx = withPoolAccess(ctx, *pa)
		}
		r, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		r.Header.Set(lumidLLMOpenRouterHeader, "deny") // stale value must not survive
		applyOpenRouterPolicy(r)
		return r
	}
	llm := lumidLLMBase() + "/v1/messages"
	off, on := poolAccess{Onprem: true}, poolAccess{Onprem: true, Openrouter: true}
	if mk(llm, &off).Header.Get(lumidLLMOpenRouterHeader) != "deny" {
		t.Error("pool off + lumid-llm: veto missing")
	}
	if mk(llm, &on).Header.Get(lumidLLMOpenRouterHeader) != "" {
		t.Error("pool on: veto must not be sent")
	}
	if mk(llm, nil).Header.Get(lumidLLMOpenRouterHeader) != "" {
		t.Error("no verdict on ctx: request must be left as it was")
	}
	if mk("https://api.anthropic.com/v1/messages", &off).Header.Get(lumidLLMOpenRouterHeader) != "" {
		t.Error("veto must only go to lumid-llm")
	}
}
