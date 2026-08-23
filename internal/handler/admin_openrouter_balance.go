package handler

// GET /api/v1/admin/openrouter-balance — OpenRouter account credit/limit for
// the /code dashboard.
//
// The dashboard's per-model chips + provider subtotals distinguish pooled
// Claude from OpenRouter from on-prem, but the OpenRouter side is metered
// pay-per-use — so the operator needs to see how much credit is left on the
// OpenRouter account. This endpoint reads the same key lumid-llm uses
// (LUMID_LLM_OPENROUTER_KEY, injected into identity-env) and asks OpenRouter
// for the key's usage/limit.
//
// SECURITY: the key never leaves the server. The client only ever sees the
// normalized balance, never the raw credential. Degrades gracefully to
// {available:false} when the key is unset or the call fails, so a missing key
// blanks the panel instead of erroring the whole page.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	openRouterBalanceURL     = "https://openrouter.ai/api/v1/auth/key"
	openRouterBalanceTTL     = 5 * time.Minute
	openRouterBalanceTimeout = 10 * time.Second
)

// openRouterBalanceCache is a process-local cache so the dashboard's 2-min
// auto-refresh doesn't hammer OpenRouter. Mirrors the quotaCacheTTL pattern.
var (
	openRouterBalanceMu    sync.Mutex
	openRouterBalanceCache *openRouterBalanceCached
)

type openRouterBalanceCached struct {
	at   time.Time
	data openRouterBalancePayload
}

// openRouterBalancePayload is the normalized response handed to the client.
type openRouterBalancePayload struct {
	Available  bool    `json:"available"`
	BalanceUsd float64 `json:"balance_usd"`
	LimitUsd   float64 `json:"limit_usd"`
	UsageUsd   float64 `json:"usage_usd"`
	Currency   string  `json:"currency"`
	IsFreeTier bool    `json:"is_free_tier"`
	Label      string  `json:"label,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// openRouterAuthKeyResp is the subset of OpenRouter's /auth/key response we
// care about. Amounts arrive in MILLIcents (1/1000 of a cent) per OpenRouter's
// API; we normalize to dollars.
type openRouterAuthKeyResp struct {
	Data struct {
		Label      string  `json:"label"`
		Usage      float64 `json:"usage"`
		Limit      float64 `json:"limit"`
		IsFreeTier bool    `json:"is_free_tier"`
		Currency   string  `json:"currency"`
	} `json:"data"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func AdminOpenRouterBalance(c *gin.Context) {
	// Serve from cache if fresh.
	openRouterBalanceMu.Lock()
	if openRouterBalanceCache != nil && time.Since(openRouterBalanceCache.at) < openRouterBalanceTTL {
		payload := openRouterBalanceCache.data
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}
	openRouterBalanceMu.Unlock()

	key := os.Getenv("LUMID_LLM_OPENROUTER_KEY")
	if key == "" {
		payload := openRouterBalancePayload{Available: false, Error: "openrouter key not configured"}
		openRouterBalanceMu.Lock()
		openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}

	req, err := http.NewRequest(http.MethodGet, openRouterBalanceURL, nil)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "openrouter balance: "+err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)

	cl := &http.Client{Timeout: openRouterBalanceTimeout}
	resp, err := cl.Do(req)
	if err != nil {
		payload := openRouterBalancePayload{Available: false, Error: "openrouter unreachable"}
		openRouterBalanceMu.Lock()
		openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK {
		payload := openRouterBalancePayload{Available: false, Error: fmt.Sprintf("openrouter HTTP %d", resp.StatusCode)}
		openRouterBalanceMu.Lock()
		openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}

	var ar openRouterAuthKeyResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		payload := openRouterBalancePayload{Available: false, Error: "malformed openrouter response"}
		openRouterBalanceMu.Lock()
		openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}
	if ar.Error != nil {
		payload := openRouterBalancePayload{Available: false, Error: ar.Error.Message}
		openRouterBalanceMu.Lock()
		openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
		openRouterBalanceMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
		return
	}

	// OpenRouter reports usage/limit in MILLIcents (1/1000 cent). Normalize to
	// dollars. A free-tier key has no limit (0) — show usage only.
	payload := openRouterBalancePayload{
		Available:  true,
		BalanceUsd: (ar.Data.Limit - ar.Data.Usage) / 1000,
		LimitUsd:   ar.Data.Limit / 1000,
		UsageUsd:   ar.Data.Usage / 1000,
		Currency:   ar.Data.Currency,
		IsFreeTier: ar.Data.IsFreeTier,
		Label:      ar.Data.Label,
	}
	openRouterBalanceMu.Lock()
	openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
	openRouterBalanceMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
}
