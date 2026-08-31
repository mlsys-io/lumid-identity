package handler

// GET /api/v1/admin/onprem-gpu-stats — live tok/s + QPS per on-prem GPU
// backend (h100/GX10/s0 CPU, all serving deepseek-v4-flash) for the /code
// dashboard's on-prem GPU panel.
//
// Pure passthrough to lumid-llm's own GET /admin/llm-backend-stats, which
// computes the rolling-window rates from its in-process /metrics scrape (see
// lumid-data-service crates/platform/src/llm_pool.rs — no new upstream poll,
// this reads the same 5s scrape start_queue_scraper already runs). Cached
// short-TTL here so the dashboard's own auto-refresh doesn't hammer
// lumid-llm. Mirrors admin_openrouter_balance.go's cache + graceful-degrade
// shape exactly.
//
// Auth: lumid-llm's /admin/* routes are gated by its own require_admin
// (super_admin role or local key) on top of its request-level identity gate
// — same PAT + base-URL resolution already used by me_agent.go's calls to
// lumid-llm (lumidLLMBase() + kvrunPAT()).

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	onpremStatsTTL     = 10 * time.Second
	onpremStatsTimeout = 10 * time.Second
)

// onpremStatsCache is a process-local cache so a fast dashboard poll (the UI
// panel refreshes every ~10-15s) doesn't turn into a 1:1 hammer on lumid-llm.
// Mirrors openRouterBalanceCache's pattern in admin_openrouter_balance.go.
var (
	onpremStatsMu    sync.Mutex
	onpremStatsCache *onpremStatsCached
)

type onpremStatsCached struct {
	at   time.Time
	data onpremStatsPayload
}

// onpremStatsPayload is the normalized response handed to the client — the
// same shape lumid-llm's own /admin/llm-backend-stats returns, so this
// handler adds a cache and a degrade path without reshaping the data.
type onpremStatsPayload struct {
	Available     bool                 `json:"available"`
	WindowSeconds int                  `json:"window_seconds,omitempty"`
	Backends      []onpremBackendStats `json:"backends,omitempty"`
	Error         string               `json:"error,omitempty"`
}

type onpremBackendStats struct {
	Label      string   `json:"label"`
	URL        string   `json:"url"`
	Tier       uint32   `json:"tier"`
	Healthy    bool     `json:"healthy"`
	TokS       *float64 `json:"tok_s"`
	QPS        *float64 `json:"qps"`
	QueueDepth int32    `json:"queue_depth"`
}

// llmBackendStatsResp mirrors lumid-llm's raw /admin/llm-backend-stats body.
type llmBackendStatsResp struct {
	WindowSeconds int                  `json:"window_seconds"`
	Backends      []onpremBackendStats `json:"backends"`
}

func AdminOnpremGpuStats(c *gin.Context) {
	onpremStatsMu.Lock()
	if onpremStatsCache != nil && time.Since(onpremStatsCache.at) < onpremStatsTTL {
		payload := onpremStatsCache.data
		onpremStatsMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}
	onpremStatsMu.Unlock()

	degrade := func(errMsg string) {
		payload := onpremStatsPayload{Available: false, Error: errMsg}
		onpremStatsMu.Lock()
		onpremStatsCache = &onpremStatsCached{at: time.Now(), data: payload}
		onpremStatsMu.Unlock()
		// 200, not 5xx: a lumid-llm outage must blank this ONE panel, not the
		// rest of /code — same reasoning as the OpenRouter balance handler.
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
	}

	pat, err := kvrunPAT()
	if err != nil {
		degrade("lumid-llm credential not configured")
		return
	}

	req, err := http.NewRequest(http.MethodGet, lumidLLMBase()+"/admin/llm-backend-stats", nil)
	if err != nil {
		degrade("build request: " + err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+pat)

	cl := &http.Client{Timeout: onpremStatsTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		degrade("lumid-llm unreachable")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	if resp.StatusCode != http.StatusOK {
		degrade("lumid-llm HTTP " + http.StatusText(resp.StatusCode))
		return
	}

	var upstream llmBackendStatsResp
	if err := json.Unmarshal(raw, &upstream); err != nil {
		degrade("malformed lumid-llm response")
		return
	}

	payload := onpremStatsPayload{
		Available:     true,
		WindowSeconds: upstream.WindowSeconds,
		Backends:      upstream.Backends,
	}
	onpremStatsMu.Lock()
	onpremStatsCache = &onpremStatsCached{at: time.Now(), data: payload}
	onpremStatsMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
}
