package handler

// me_agent tools: lqt_mailbox_read + lqt_mailbox_submit — read LQT mailbox
// data and submit a strategy from the native (deepseek) chat path.
//
// The LQT mailbox is the governed control-plane for the prediction-market
// runtime (strategies, results, telemetry, venue health). It is NOT reachable
// in-cluster from lumid-identity — the `lqt-allow-ingress` NetworkPolicy only
// admits ingress-nginx + the mailbox consumer, so a direct call to
// `http://lqt.lumid.svc.cluster.local:8088` is DROPPED. The working read path
// is the public route `https://lum.id/dataapp-proxy/lqt/<path>`, which injects
// a read PAT when none is sent; we send the operator's Lumid PAT (kvrunPAT)
// explicitly so the caller's identity rides the request.
//
// lqt_mailbox_read is read-only and available to every role (like data_query).
// The endpoint is WHITELISTED — the model can only name one of the known-good
// read surfaces, never an arbitrary path (SSRF guard). lqt_mailbox_submit is a
// WRITE (deploys a strategy via the `strategy.deploy` mailbox topic) and is
// gated like the operator tools: super_admin-only, in destructiveTools
// (interactive approval), and audited via writeAudit.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	lqtMailboxTimeout = 30 * time.Second
	// Row cap for list endpoints. The server enforces its own cap too, but we
	// clamp before requesting so a careless read doesn't materialize a giant
	// payload into the chat context.
	lqtReadLimit = 100
)

// lqtReadSpec describes one whitelisted read surface. `list` marks the
// endpoints that accept a ?limit= query param (arrays); the scalar/health
// endpoints ignore it.
type lqtReadSpec struct {
	path string
	list bool
}

// lqtReadEndpoints — the allowlist of LQT mailbox read surfaces the model may
// name. Keys are the friendly names the tool advertises; values carry the path
// appended to lqtMailboxBase(). Anything not here is refused outright — this is
// the SSRF guard (no arbitrary paths, no host injection).
var lqtReadEndpoints = map[string]lqtReadSpec{
	"venue_health_nyc":    {path: "/lqt/venue-health/nyc", list: false},
	"venue_health_chi":    {path: "/lqt/venue-health/chi", list: false},
	"venue_health_dublin": {path: "/lqt/venue-health/dublin", list: false},
	"stats":               {path: "/xpio/stats", list: false},
	"strategies":          {path: "/xpio/strategies", list: true},
	"results":             {path: "/xpio/results", list: true},
	"cycles_nyc":          {path: "/runtime/cycles/nyc", list: true},
	"signals_venue_mid":   {path: "/lqt/signals/venue_mid", list: true},
}

// lqtMailboxBase resolves the base URL of the LQT mailbox read/write ingress.
// Defaults to the public dataapp-proxy hairpin (the only path admitted by the
// lqt NetworkPolicy from this service). Trailing slashes are trimmed so callers
// can append paths.
func lqtMailboxBase() string {
	base := strings.TrimSpace(os.Getenv("LQT_MAILBOX_BASE"))
	if base == "" {
		base = "https://lum.id/dataapp-proxy/lqt"
	}
	return strings.TrimRight(base, "/")
}

// lqtMailboxHeaders returns the Authorization header for LQT calls using the
// operator's Lumid PAT. If no PAT is resolvable, returns nil headers — the
// dataapp-proxy path injects a read PAT when none is sent.
func lqtMailboxHeaders() http.Header {
	h := http.Header{}
	if tok, err := kvrunPAT(); err == nil && tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// lqtMailboxDo performs an HTTP request against the LQT mailbox base and
// returns the parsed JSON body + status. Errors are wrapped so the chat sees
// why a read/submit failed.
func lqtMailboxDo(method, path string, body []byte) (map[string]any, int, error) {
	u := lqtMailboxBase() + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return nil, 0, err
	}
	for k, vs := range lqtMailboxHeaders() {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: lqtMailboxTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("lqt mailbox unreachable: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out == nil {
		out = map[string]any{"raw": truncateStr(string(rb), 520)}
	}
	return out, resp.StatusCode, nil
}

// resolveLqtEndpoint normalizes a model-supplied endpoint string to a
// whitelisted spec. Accepts the friendly key ("strategies") or the raw path
// ("/xpio/strategies", "xpio/strategies"). Returns ok=false for anything not on
// the allowlist — the SSRF guard.
func resolveLqtEndpoint(e string) (lqtReadSpec, bool) {
	e = strings.ToLower(strings.TrimSpace(e))
	e = strings.TrimPrefix(e, "/lqt/")
	e = strings.TrimPrefix(e, "/")
	if spec, ok := lqtReadEndpoints[e]; ok {
		return spec, true
	}
	for _, spec := range lqtReadEndpoints {
		if strings.TrimPrefix(spec.path, "/lqt/") == e ||
			strings.TrimPrefix(spec.path, "/") == e {
			return spec, true
		}
	}
	return lqtReadSpec{}, false
}

// toolLqtMailboxRead fetches one whitelisted LQT mailbox read surface and
// returns the parsed JSON. `endpoint` names a known-good surface (see
// lqtReadEndpoints); `limit` caps list endpoints. Read-only — no gating beyond
// the endpoint allowlist, mirroring data_query.
func toolLqtMailboxRead(endpoint string, limit int) (map[string]any, bool) {
	spec, ok := resolveLqtEndpoint(endpoint)
	if !ok {
		return map[string]any{"error": fmt.Sprintf("unknown lqt endpoint %q — use one of: %s", endpoint, strings.Join(sortedKeys(lqtReadEndpoints), ", "))}, false
	}
	path := spec.path
	if spec.list {
		if limit <= 0 || limit > 1000 {
			limit = lqtReadLimit
		}
		path += "?" + url.Values{"limit": {fmt.Sprintf("%d", limit)}}.Encode()
	}
	out, status, err := lqtMailboxDo(http.MethodGet, path, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("lqt mailbox %d: %s", status, out["raw"])}, false
	}
	return map[string]any{"endpoint": endpoint, "data": out}, true
}

// toolLqtMailboxSubmit submits a strategy to the LQT mailbox via the
// `strategy.deploy` topic (POST /xpio/strategies). super_admin-gated + in
// destructiveTools (interactive approval) + audited — defense in depth, the
// same posture as operator_remediate.
func toolLqtMailboxSubmit(c *gin.Context, userID, role, name, version, strategy string) (map[string]any, bool) {
	if role != "super_admin" {
		return map[string]any{"error": "lqt_mailbox_submit requires super_admin"}, false
	}
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	strategy = strings.TrimSpace(strategy)
	if name == "" || version == "" || strategy == "" {
		return map[string]any{"error": "name, version and strategy are all required"}, false
	}
	payload, _ := json.Marshal(map[string]any{
		"strategy_id": name + "@" + version,
		"name":        name,
		"version":     version,
		"strategy":    map[string]any{"dsl": strategy},
	})
	out, status, err := lqtMailboxDo(http.MethodPost, "/xpio/strategies", payload)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	writeAudit(c, userID, userID, "lqt:strategy.submit",
		fmt.Sprintf("name=%s version=%s (via chatbox)", name, version))
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("lqt mailbox submit %d: %s", status, out["raw"])}, false
	}
	return map[string]any{"name": name, "version": version, "acked": out}, true
}

// sortedKeys returns the map keys in lexical order — used to render the
// endpoint allowlist in error messages deterministically.
func sortedKeys(m map[string]lqtReadSpec) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// lqtToolDefs returns the super_admin-only LQT mailbox WRITE tool definition.
// Appended in buildToolDefsForRole only when the caller is super_admin, so the
// model never sees it otherwise (mirrors operatorToolDefs). lqt_mailbox_read is
// in the base catalog — read-only, available to every role.
func lqtToolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "lqt_mailbox_submit",
			"description": "Submit a strategy to the LQT mailbox for deployment (strategy.deploy topic). WRITE — super_admin only, requires explicit user approval, audited. Provide the strategy name, semantic version, and the .lqts DSL source.",
			"input_schema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":     map[string]any{"type": "string", "description": "Strategy name, e.g. 'zh_momentum'."},
					"version":  map[string]any{"type": "string", "description": "Semantic version, e.g. '1.0.0'."},
					"strategy": map[string]any{"type": "string", "description": "The .lqts DSL source defining the strategy."},
				},
				"required": []string{"name", "version", "strategy"},
			},
		},
	}
}
