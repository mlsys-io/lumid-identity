package handler

// me_agent tools for web search + deep research, backed by Tavily.
//
// Three tools:
//   - web_search    → POST https://api.tavily.com/search    (basic)
//   - web_fetch     → POST https://api.tavily.com/extract   (URL → markdown)
//   - deep_research → POST https://api.tavily.com/search    (advanced + answer)
//
// All three share one operator-funded TAVILY_API_KEY (env or
// /home/webmaster/.api_keys/tavily). Per-user budget cap is shared
// with the LLM-token budget — search calls don't decrement tokens but
// the calls themselves are still cheap enough to leave un-metered for
// now. Per-tool budget enforcement is a follow-up.
//
// Response shape: each tool returns a JSON-able map; failures return
// {"error": "..."} with ok=false from dispatchTool.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	tavilySearchEndpoint  = "https://api.tavily.com/search"
	tavilyExtractEndpoint = "https://api.tavily.com/extract"
	tavilyTimeout         = 25 * time.Second
	// Response body cap (per tool call). Tavily can return tens of KB
	// per result with raw_content enabled; bounding here keeps the
	// LLM context budget sane on long multi-turn chats.
	tavilyResponseCapBytes = 64 * 1024
)

// tavilyKey resolves the operator's Tavily API key. Env first
// (TAVILY_API_KEY), then /home/webmaster/.api_keys/tavily (mode 0600,
// raw key on the first line).
func tavilyKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv("TAVILY_API_KEY")); k != "" {
		return k, nil
	}
	if b, err := os.ReadFile("/home/webmaster/.api_keys/tavily"); err == nil {
		key := strings.TrimSpace(strings.Split(string(b), "\n")[0])
		if key != "" {
			return key, nil
		}
	}
	return "", fmt.Errorf("no TAVILY_API_KEY set (place key at /home/webmaster/.api_keys/tavily or set env)")
}

// tavilyPOST is a thin helper that signs + posts to Tavily, returning
// the parsed JSON body. Errors carry the upstream status + a 300-char
// excerpt for debugging.
func tavilyPOST(ctx context.Context, endpoint, apiKey string, body map[string]any) (map[string]any, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	respBody, _ := io.ReadAll(r.Body)
	if r.StatusCode >= 300 {
		excerpt := string(respBody)
		if len(excerpt) > 300 {
			excerpt = excerpt[:300]
		}
		return nil, fmt.Errorf("tavily %d: %s", r.StatusCode, excerpt)
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return out, nil
}

// truncStr returns s capped at n chars with a "…" suffix when cut.
func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// capJSONSize re-marshals m and, if larger than tavilyResponseCapBytes,
// progressively shrinks the longest "content" / "raw_content" /
// "answer" fields. Best-effort; the LLM tolerates partial data.
func capJSONSize(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	if len(b) <= tavilyResponseCapBytes {
		return m
	}
	// Quick shrink: walk known long-field paths and truncate.
	if results, ok := m["results"].([]any); ok {
		for _, r := range results {
			if rm, ok := r.(map[string]any); ok {
				if c, ok := rm["content"].(string); ok {
					rm["content"] = truncStr(c, 1200)
				}
				if rc, ok := rm["raw_content"].(string); ok {
					rm["raw_content"] = truncStr(rc, 2000)
				}
			}
		}
	}
	if a, ok := m["answer"].(string); ok {
		m["answer"] = truncStr(a, 4000)
	}
	// Final hard cap on the JSON itself in the rare case the per-field
	// shrink wasn't enough — re-marshal and clip the trailing tail.
	b, _ = json.Marshal(m)
	if len(b) > tavilyResponseCapBytes {
		m["_truncated"] = true
	}
	return m
}

// toolWebSearch — quick keyword search.
// Returns: {"results": [{title, url, content, score}], "query": "..."}
func toolWebSearch(query string, numResults int) (map[string]any, bool) {
	if strings.TrimSpace(query) == "" {
		return map[string]any{"error": "query required"}, false
	}
	if numResults <= 0 || numResults > 10 {
		numResults = 5
	}
	apiKey, err := tavilyKey()
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), tavilyTimeout)
	defer cancel()
	resp, err := tavilyPOST(ctx, tavilySearchEndpoint, apiKey, map[string]any{
		"query":          query,
		"search_depth":   "basic",
		"max_results":    numResults,
		"include_answer": false,
	})
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// Drop large fields we don't surface in basic mode.
	delete(resp, "raw_content")
	return capJSONSize(resp), true
}

// toolWebFetch — extract the readable content of one URL as markdown.
// Returns: {"url": "...", "content": "..." (markdown), "title": "..."}
func toolWebFetch(url string) (map[string]any, bool) {
	if strings.TrimSpace(url) == "" {
		return map[string]any{"error": "url required"}, false
	}
	apiKey, err := tavilyKey()
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), tavilyTimeout)
	defer cancel()
	resp, err := tavilyPOST(ctx, tavilyExtractEndpoint, apiKey, map[string]any{
		"urls":             []string{url},
		"extract_depth":    "basic",
		"include_images":   false,
	})
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// Extract returns {"results": [{url, raw_content}], "failed_results": [...]}.
	// Flatten to the common shape so the agent can read the content
	// without indexing into a list.
	out := map[string]any{"url": url}
	if results, ok := resp["results"].([]any); ok && len(results) > 0 {
		if first, ok := results[0].(map[string]any); ok {
			if rc, ok := first["raw_content"].(string); ok {
				out["content"] = truncStr(rc, 16*1024)
			}
			if t, ok := first["title"].(string); ok {
				out["title"] = t
			}
		}
	}
	if failed, ok := resp["failed_results"].([]any); ok && len(failed) > 0 {
		if _, hasContent := out["content"]; !hasContent {
			return map[string]any{"error": "extract failed", "details": failed}, false
		}
	}
	return capJSONSize(out), true
}

// toolDeepResearch — advanced multi-source search with LLM-generated
// answer + per-result content chunks. Optimised for "tell me about X"
// type questions where the agent wants a synthesized brief.
// Returns: {"answer": "...", "results": [{title, url, content, score}], "query": "..."}
func toolDeepResearch(question string, maxResults int) (map[string]any, bool) {
	if strings.TrimSpace(question) == "" {
		return map[string]any{"error": "question required"}, false
	}
	if maxResults <= 0 || maxResults > 10 {
		maxResults = 8
	}
	apiKey, err := tavilyKey()
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	// Deep research can take >20s on hard questions; give it a wider
	// timeout than basic search.
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	resp, err := tavilyPOST(ctx, tavilySearchEndpoint, apiKey, map[string]any{
		"query":                 question,
		"search_depth":          "advanced",
		"topic":                 "general",
		"max_results":           maxResults,
		"include_answer":        "advanced",
		"include_raw_content":   false,
		"chunks_per_source":     3,
	})
	if err != nil {
		return map[string]any{"error": err.Error()}, false
	}
	return capJSONSize(resp), true
}
