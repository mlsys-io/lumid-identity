package handler

// Per-pool model policy for the lum.id agent (/me/agent/*).
//
// The three ClaudePool switches on lum.id/code (allow_onprem, allow_openrouter,
// allow_fable) were enforced only by claude-proxy, and the agent's chips do not
// all go through claude-proxy: the deepseek/qwen chips call lumid-llm directly
// with the shared kvrunPAT, so the proxy never sees the user. Measured
// 2026-11-14 the consequences were:
//   - on-prem "off" did nothing in lum.id chat (deepseek stayed the default);
//   - Fable "on" did nothing in lum.id chat (the chip was super_admin by role);
//   - OpenRouter "off" did nothing for the agent's lumid-llm calls, which
//     overflowed to OpenRouter like any header-less caller.
//
// This file applies the same verdicts at the agent's own decision points:
// chip listing, provider resolution, and the outbound lumid-llm request.
// The verdicts come from claudePolicyFor, the same function introspection
// uses for claude-proxy, so the two can never disagree about a user's pool.

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// poolAccess is a caller's pool verdict set, as claude-proxy sees it.
type poolAccess struct {
	Onprem     bool
	Openrouter bool
	Fable      bool
}

// statusQuoPoolAccess mirrors claudePolicyFor's zero-value policy: on-prem
// open, money closed. Used when there is no user to resolve.
var statusQuoPoolAccess = poolAccess{Onprem: true, Openrouter: false, Fable: false}

// poolAccessFor resolves the caller's EFFECTIVE pool (primary > default). It
// does not read a claude-pool:<id> scope hint: the agent runs on the
// caller's session, not on a pool-scoped PAT.
func poolAccessFor(c *gin.Context) poolAccess {
	uid, ok := currentUserID(c)
	if !ok || uid == "" {
		return statusQuoPoolAccess
	}
	pol := claudePolicyFor(uid, nil)
	return poolAccess{Onprem: pol.Onprem, Openrouter: pol.Openrouter, Fable: pol.Fable}
}

// providerIsOnprem: served by our own fleet, either directly via lumid-llm
// (deepseek/qwen chips) or as a Claude Code harness on a lumid-llm model.
func providerIsOnprem(p llmProvider) bool {
	if p.endpoint != "" && strings.HasPrefix(p.endpoint, lumidLLMBase()) {
		return true
	}
	return strings.HasPrefix(p.upstreamModel, "lumid-llm/")
}

// providerIsFable mirrors claude-proxy's modelAllowed, which matches
// "fable" anywhere in the model id.
func providerIsFable(p llmProvider) bool {
	return strings.Contains(strings.ToLower(p.upstreamModel), "fable") ||
		strings.Contains(strings.ToLower(p.id), "fable")
}

// providerPoolAllowed: may this caller select p, by role AND pool?
//
// Fable is decided exactly as claude-proxy decides it (super_admin by role,
// anyone else by the pool grant), so the chip's minRole is not consulted
// for it. A grant the proxy would honour and the picker hid was the bug.
func providerPoolAllowed(role string, pa poolAccess, p llmProvider) bool {
	if providerIsOnprem(p) && !pa.Onprem {
		return false
	}
	if providerIsFable(p) {
		return role == "super_admin" || pa.Fable
	}
	return providerAllowed(role, p)
}

// defaultProviderForCaller is defaultProviderFor with the pool applied.
// ok=false means NOTHING is selectable (e.g. role=user on an on-prem-off
// pool: both of their doors are shut, as at claude-proxy).
func defaultProviderForCaller(role string, pa poolAccess) (llmProvider, bool) {
	if d := defaultProviderFor(role); providerPoolAllowed(role, pa, d) {
		return d, true
	}
	for _, p := range llmProviders {
		if providerPoolAllowed(role, pa, p) {
			return p, true
		}
	}
	return llmProvider{}, false
}

// resolveProviderForCaller is resolveProviderWhy with the pool applied.
// Returns ok=false when no provider at all is open to this caller.
func resolveProviderForCaller(modelID, role string, pa poolAccess) (llmProvider, string, bool) {
	// A pool-granted Fable pick must not be downgraded by the role-only
	// resolver first.
	if p, found := providerByID(modelID); found && providerIsFable(p) && providerPoolAllowed(role, pa, p) {
		return p, "", true
	}
	p, note := resolveProviderWhy(modelID, role)
	if providerPoolAllowed(role, pa, p) {
		return p, note, true
	}
	d, ok := defaultProviderForCaller(role, pa)
	if !ok {
		return llmProvider{}, "", false
	}
	return d, "model " + p.id + " is not available to your Claude pool — used " + d.id + " instead", true
}

// autoRouteForCaller wraps autoRouteForTurn so a capability reroute (vision,
// app tools) can never land on a provider the pool closes. A blocked reroute
// keeps the provider the caller was already allowed.
func autoRouteForCaller(msgs []chatMessage, picked llmProvider, role string, pa poolAccess, ctx map[string]any, mode string) (llmProvider, bool) {
	p, routed := autoRouteForTurn(msgs, picked, role, ctx, mode)
	if routed && !providerPoolAllowed(role, pa, p) {
		return picked, false
	}
	return p, routed
}

// ── OpenRouter veto on outbound lumid-llm calls ──────────────────────────────

type poolAccessCtxKey struct{}

// withPoolAccess stamps the caller's verdicts onto ctx so the HTTP senders
// (callLLM, streamOneAnthropicTurn) can apply them without threading a new
// parameter through every caller.
func withPoolAccess(ctx context.Context, pa poolAccess) context.Context {
	return context.WithValue(ctx, poolAccessCtxKey{}, pa)
}

// lumidLLMOpenRouterHeader is lumid-llm's deny-only per-request veto
// (lumid-data-service handlers/llm.rs OPENROUTER_POLICY_HEADER; claude-proxy
// openrouter_policy.go sends the same).
const lumidLLMOpenRouterHeader = "X-Lumid-Openrouter"

// applyOpenRouterPolicy sets the veto on a request to lumid-llm when the
// caller's pool has OpenRouter off. No verdict on ctx (a background job with
// no user) leaves the request as it was.
func applyOpenRouterPolicy(req *http.Request) {
	req.Header.Del(lumidLLMOpenRouterHeader)
	pa, ok := req.Context().Value(poolAccessCtxKey{}).(poolAccess)
	if !ok || pa.Openrouter {
		return
	}
	if strings.HasPrefix(req.URL.String(), lumidLLMBase()) {
		req.Header.Set(lumidLLMOpenRouterHeader, "deny")
	}
}
