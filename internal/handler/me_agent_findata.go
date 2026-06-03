package handler

// me_agent tool: query_findata — read-only finance lookups against
// the kv.run:5000 warehouse. Six kinds:
//   - quote   → /quotes?symbols=X
//   - news    → /news/X?limit=N
//   - earnings→ /earnings?symbol=X
//   - peers   → /peers/X
//   - filings → /filings/X?limit=N
//   - ohlc    → /ohlc/X?interval=...&start=...&end=...
//
// Operator-funded — uses the same Lumid PAT as Studio chat's
// kvrun-minimax provider (env KVRUN_LLM_TOKEN → ~/.lumilake/pat).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	findataBase    = "https://kv.run:5000"
	findataTimeout = 15 * time.Second
)

// findataGET signs a GET to kv.run:5000 with the operator's Lumid PAT.
func findataGET(ctx context.Context, path string, query url.Values) ([]byte, int, error) {
	tok, err := kvrunPAT()
	if err != nil {
		return nil, 0, err
	}
	u := findataBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	return body, r.StatusCode, nil
}

// toolQueryFindata dispatches one of six lookup kinds. Returns a
// JSON-able map mirroring the upstream shape (with a status-on-error
// envelope for non-2xx). Symbol is required for every kind except…
// none — all six are per-symbol.
func toolQueryFindata(kind, symbol string, limit int) (map[string]any, bool) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	symbol = strings.ToUpper(strings.TrimSpace(symbol))
	if symbol == "" {
		return map[string]any{"error": "symbol required"}, false
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	ctx, cancel := context.WithTimeout(context.Background(), findataTimeout)
	defer cancel()

	var path string
	q := url.Values{}
	switch kind {
	case "quote", "quotes":
		path = "/quotes"
		q.Set("symbols", symbol)
	case "news":
		path = "/news/" + symbol
		q.Set("limit", fmt.Sprintf("%d", limit))
	case "earnings":
		path = "/earnings"
		q.Set("symbol", symbol)
		q.Set("limit", fmt.Sprintf("%d", limit))
	case "peers":
		path = "/peers/" + symbol
	case "filings":
		path = "/filings/" + symbol
		q.Set("limit", fmt.Sprintf("%d", limit))
	case "ohlc":
		path = "/ohlc/" + symbol
		// Default to a recent ~30 day window when caller didn't pass
		// one — gives the agent something useful without further args.
		end := time.Now().UTC()
		start := end.AddDate(0, 0, -30)
		q.Set("interval", "1d")
		q.Set("start", start.Format("2006-01-02"))
		q.Set("end", end.Format("2006-01-02"))
	default:
		return map[string]any{"error": fmt.Sprintf("unknown kind %q (use quote|news|earnings|peers|filings|ohlc)", kind)}, false
	}

	body, status, err := findataGET(ctx, path, q)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		excerpt := string(body)
		if len(excerpt) > 300 {
			excerpt = excerpt[:300]
		}
		return map[string]any{"error": fmt.Sprintf("kv.run %d: %s", status, excerpt)}, false
	}
	// Endpoint shapes vary — sometimes it's an array, sometimes an
	// object. Pass-through with a tagged wrapper so the LLM has both
	// the kind hint and the original payload.
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]any{"error": "parse: " + err.Error()}, false
	}
	out := map[string]any{
		"kind":   kind,
		"symbol": symbol,
		"data":   raw,
	}
	// Truncate news + filings summaries to keep the context budget sane.
	if kind == "news" {
		if arr, ok := raw.([]any); ok {
			for _, it := range arr {
				if m, ok := it.(map[string]any); ok {
					if s, ok := m["summary"].(string); ok && len(s) > 600 {
						m["summary"] = s[:600] + "…"
					}
				}
			}
		}
	}
	return out, true
}
