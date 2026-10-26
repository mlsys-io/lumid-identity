package handler

import (
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

const defaultMaxInFlight = 256

// maxInFlightFromEnv reads IDENTITY_MAX_INFLIGHT (default 256; 0 disables the cap).
func maxInFlightFromEnv() int {
	if v, err := strconv.Atoi(os.Getenv("IDENTITY_MAX_INFLIGHT")); err == nil && v >= 0 {
		return v
	}
	return defaultMaxInFlight
}

// MaxInFlight sheds load instead of queueing it: once n requests are in progress, further ones get
// 503 + Retry-After: 1 immediately. Without it, a backlog (e.g. every consumer retrying the moment
// MySQL returns from an outage) grows identity's memory until the NODE runs out — 2026-10-26,
// svc-lthl8-q9wmb went NotReady and the kernel OOM-killed identity. Health probes are never shed,
// so a busy pod is not mistaken for a dead one.
func MaxInFlight(n int) gin.HandlerFunc {
	if n <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	sem := make(chan struct{}, n)
	return func(c *gin.Context) {
		switch c.Request.URL.Path {
		case "/livez", "/readyz", "/healthz":
			c.Next()
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		default:
			c.Header("Retry-After", "1")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"code": 503, "message": "identity busy, retry shortly"})
		}
	}
}
