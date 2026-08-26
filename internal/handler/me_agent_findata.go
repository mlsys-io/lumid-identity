package handler

// me_agent tools: data_catalog + data_query — read-only FinData analysis
// against the live findata warehouse (lumid-data-service / lumid-platform),
// reached in-cluster at findata-primary:8088. Mirrors the proven logic in
// LumidOS/sdk/ops/data.py (data_catalog → /catalog/*, data_query → POST
// /retrieve then fetch the materialized JSONL blob).
//
// The old query_findata tool pointed at the RETIRED kv.run:5000 warehouse
// (closed 2026-07). It is kept here as a thin compat shim mapping the six
// canned kinds onto the corresponding read endpoints of the new base, so
// existing sub-agent references and personas don't break.
//
// Operator-funded — authenticates with the same Lumid PAT as the lumid-llm
// gateway (env KVRUN_LLM_TOKEN → ~/.lumilake/pat). findata's /retrieve and
// /catalog/* accept a bearer PAT (the public lum.id/findata/* path injects an
// anon-read PAT when none is sent).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	findataTimeout = 30 * time.Second
	// Row cap for ad-hoc SELECTs — the server enforces its own cap too, but
	// we clamp before requesting so a careless query doesn't materialize a
	// giant blob. Mirrors sdk/ops/data.py's default limit=200.
	dataQueryLimit = 200
)

// findataBase resolves the base URL of the findata warehouse. Reads
// FIN_DATA_BASE (e.g. https://lum.id/findata for a public hairpin, or
// http://findata-primary:8088 in-cluster), defaulting to the in-cluster
// Service. Trailing slashes are trimmed so callers can append paths.
func findataBase() string {
	base := strings.TrimSpace(os.Getenv("FIN_DATA_BASE"))
	if base == "" {
		base = "http://findata-primary:8088"
	}
	return strings.TrimRight(base, "/")
}

// findataHeaders returns the Authorization header for findata calls using the
// operator's Lumid PAT. If no PAT is resolvable, returns nil headers — the
// public path injects an anon-read PAT, and in-cluster the endpoint may allow
// unauthenticated catalog reads.
func findataHeaders() http.Header {
	h := http.Header{}
	if tok, err := kvrunPAT(); err == nil && tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
	return h
}

// findataDo performs an HTTP request against the findata base and returns the
// raw body + status. Handles the /retrieve two-hop (returns the materialized
// blob body when uri is non-empty).
func findataDo(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	u := findataBase() + path
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, 0, err
	}
	for k, vs := range findataHeaders() {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return b, r.StatusCode, nil
}

// toolDataCatalog lists the findata warehouse schemas (and, when a schema is
// given, its tables). Returns {"schemas": [...]} or {"tables": [...]}.
func toolDataCatalog(app, schema string) (map[string]any, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), findataTimeout)
	defer cancel()

	path := "/catalog/schemas"
	if strings.TrimSpace(schema) != "" {
		path = "/catalog/schemas/" + url.PathEscape(strings.TrimSpace(schema)) + "/tables"
	}
	body, status, err := findataDo(ctx, http.MethodGet, path, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("findata %d: %s", status, excerpt(body))}, false
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]any{"error": "parse: " + err.Error()}, false
	}
	out := map[string]any{"app": appOrDefault(app)}
	if strings.TrimSpace(schema) != "" {
		out["schema"] = strings.TrimSpace(schema)
		out["tables"] = raw
	} else {
		out["schemas"] = raw
	}
	return out, true
}

// toolDataQuery runs an ad-hoc read-only SELECT against the findata warehouse
// via POST /retrieve, then fetches the materialized JSONL blob. Returns
// {"rows": [...], "count": N}. Mirrors sdk/ops/data.py::data_query.
func toolDataQuery(sql, app string, limit int) (map[string]any, bool) {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return map[string]any{"error": "sql required"}, false
	}
	if limit <= 0 || limit > 1000 {
		limit = dataQueryLimit
	}
	// Append LIMIT if the caller didn't specify one — mirrors data.py:184.
	if !hasLimitClause(sql) {
		sql = fmt.Sprintf("%s LIMIT %d", strings.TrimRight(sql, ";"), limit)
	}

	payload, _ := json.Marshal(map[string]any{
		"sql":           sql,
		"output_format": "jsonl",
	})

	ctx, cancel := context.WithTimeout(context.Background(), findataTimeout)
	defer cancel()

	body, status, err := findataDo(ctx, http.MethodPost, "/retrieve", payload)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("findata /retrieve %d: %s", status, excerpt(body))}, false
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return map[string]any{"error": "parse /retrieve: " + err.Error()}, false
	}
	uri, _ := result["materialized_uri"].(string)
	if uri == "" || !strings.HasPrefix(uri, "/") {
		// Some builds return rows inline.
		if rows, ok := result["rows"].([]any); ok {
			return map[string]any{"app": appOrDefault(app), "rows": rows, "count": len(rows)}, true
		}
		return map[string]any{"error": "unexpected /retrieve response", "raw": result}, false
	}

	// Second hop: fetch the materialized JSONL blob.
	blob, status, err := findataDo(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("findata blob %d: %s", status, excerpt(blob))}, false
	}
	rows := parseJSONL(blob)
	return map[string]any{"app": appOrDefault(app), "rows": rows, "count": len(rows)}, true
}

// parseJSONL splits a JSONL byte stream into a slice of row maps, skipping
// blank/malformed lines. Mirrors sdk/ops/data.py:202-211.
func parseJSONL(data []byte) []any {
	var rows []any
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 65536), 4194304)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			continue
		}
		rows = append(rows, v)
	}
	return rows
}

var limitRe = regexp.MustCompile(`(?i)\blimit\s+\d+`)

// hasLimitClause reports whether the SQL already carries a LIMIT clause.
func hasLimitClause(sql string) bool {
	return limitRe.MatchString(sql)
}

// toolQueryFindata — compat shim for the retired kv.run:5000 tool. Maps the
// six canned kinds onto the corresponding findata read endpoints at the new
// base. Kept so existing sub-agent references and personas don't break.
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
		end := time.Now().UTC()
		start := end.AddDate(0, 0, -30)
		q.Set("interval", "1d")
		q.Set("start", start.Format("2006-01-02"))
		q.Set("end", end.Format("2006-01-02"))
	default:
		return map[string]any{"error": fmt.Sprintf("unknown kind %q (use quote|news|earnings|peers|filings|ohlc)", kind)}, false
	}

	body, status, err := findataDo(ctx, http.MethodGet, path+"?"+q.Encode(), nil)
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	if status >= 300 {
		return map[string]any{"error": fmt.Sprintf("findata %d: %s", status, excerpt(body))}, false
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]any{"error": "parse: " + err.Error()}, false
	}
	out := map[string]any{
		"kind":   kind,
		"symbol": symbol,
		"data":   raw,
	}
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

// appOrDefault returns the given app, or "findata" when empty.
func appOrDefault(app string) string {
	if strings.TrimSpace(app) == "" {
		return "findata"
	}
	return strings.TrimSpace(app)
}

// excerpt truncates a byte slice for inclusion in an error message.
func excerpt(b []byte) string {
	s := string(b)
	if len(s) > 480 {
		return s[:480] + "…"
	}
	return s
}

// MeDataQuery — POST /api/v1/me/data-query
//
// The SQL console's backend. Deliberately a thin wrapper over toolDataQuery,
// which is the SAME code path chat uses, so the console and the assistant
// cannot drift into answering the same question differently.
//
// WHY NOT /dataapp-proxy/findata/retrieve, which the browser can already reach:
// that nginx block OVERWRITES Authorization with a shared read-scoped service
// PAT ($findata_auth). Every user's query would arrive as one service account,
// which is fine for a catalog browse and wrong for a console — it erases who
// ran what. Routing through identity keeps the caller's own session on the
// request and gets the audit row below.
//
// ATTRIBUTION, STATED HONESTLY: this is user-authenticated at identity and
// service-credentialed at findata, exactly like chat. The audit trail is
// identity's, not the warehouse's. The only path with warehouse-level
// per-user attribution is the sql_<name> role over the Postgres wire — which
// is why that seat still exists and is not replaced by this.
//
// No extra entitlement gate: data_query is read-only and available to every
// role today via chat, and putting a stricter gate on the same capability
// purely because it has a UI would be theatre.
func MeDataQuery(c *gin.Context) {
	u, ok := findataSQLLoadUser(c)
	if !ok {
		return
	}
	var req struct {
		SQL   string `json:"sql" binding:"required"`
		App   string `json:"app"`
		Limit int    `json:"limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.SQL) == "" {
		fail(c, http.StatusBadRequest, 1400, "sql required")
		return
	}

	out, ok2 := toolDataQuery(req.SQL, req.App, req.Limit)
	if !ok2 {
		// Pass the underlying message through rather than flattening it. A
		// console's whole value is that a bad query tells you WHY, and the
		// warehouse's own error ("relation does not exist", a syntax caret) is
		// more useful than anything this layer could restate.
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = "query failed"
		}
		fail(c, http.StatusBadRequest, 1400, msg)
		return
	}

	writeAudit(c, u.ID, u.ID, "me:data-query", excerpt([]byte(strings.TrimSpace(req.SQL))))
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": out})
}
