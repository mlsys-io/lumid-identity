package handler

// GET /api/v1/admin/openrouter-balance — OpenRouter account credit for the
// /code dashboard.
//
// The dashboard's per-model chips + provider subtotals distinguish pooled
// Claude from OpenRouter from on-prem, but the OpenRouter side is metered
// pay-per-use — so the operator needs to see how much credit is left on the
// OpenRouter account. This endpoint reads the same key lumid-llm uses
// (LUMID_LLM_OPENROUTER_KEY, injected into identity-env) and asks OpenRouter
// for the account's total credit + usage.
//
// We use GET /api/v1/credits, NOT /api/v1/auth/key: the latter reports
// per-key usage with `limit: null` for unlimited (pay-as-you-go) keys, so it
// cannot express a credit balance. /credits returns the account-level
// `total_credits` / `total_usage` in USD — the number the operator wants.
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
	openRouterCreditsURL     = "https://openrouter.ai/api/v1/credits"
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
// BalanceUsd = total_credits - total_usage (the spendable remainder).
type openRouterBalancePayload struct {
	Available    bool    `json:"available"`
	BalanceUsd   float64 `json:"balance_usd"`
	TotalCredits float64 `json:"total_credits"`
	UsageUsd     float64 `json:"usage_usd"`
	Error        string  `json:"error,omitempty"`
}

// openRouterCreditsResp is the subset of OpenRouter's /credits response we
// care about. Values are in USD.
type openRouterCreditsResp struct {
	Data struct {
		TotalCredits float64 `json:"total_credits"`
		TotalUsage   float64 `json:"total_usage"`
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

	req, err := http.NewRequest(http.MethodGet, openRouterCreditsURL, nil)
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

	var ar openRouterCreditsResp
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

	// /credits returns total_credits / total_usage in USD. Balance is the
	// spendable remainder.
	payload := openRouterBalancePayload{
		Available:    true,
		BalanceUsd:   ar.Data.TotalCredits - ar.Data.TotalUsage,
		TotalCredits: ar.Data.TotalCredits,
		UsageUsd:     ar.Data.TotalUsage,
	}
	openRouterBalanceMu.Lock()
	openRouterBalanceCache = &openRouterBalanceCached{at: time.Now(), data: payload}
	openRouterBalanceMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": payload})
}
