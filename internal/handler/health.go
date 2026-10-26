package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// Livez is the k8s LIVENESS probe: 200 whenever the process is serving. It deliberately checks
// no dependency — a DB or Redis outage must not get healthy pods restarted (and stuck in
// CrashLoopBackOff), which is what /healthz-as-liveness did on 2026-10-26.
func Livez(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Readyz is the k8s READINESS probe: 503 only when the DB is unreachable, because login,
// /oauth/introspect and JWKS need the DB but not Redis. Redis is reported, not required —
// its users degrade on their own (rate limits fail open, OTP/cool-downs return errors).
func Readyz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 1*time.Second)
	defer cancel()

	sqlDB, err := common.DB.DB()
	if err != nil || sqlDB.PingContext(ctx) != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false, "reason": "db"})
		return
	}
	redisState := "ok"
	if common.Redis == nil || common.Redis.Ping(ctx).Err() != nil {
		redisState = "down"
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "redis": redisState})
}

// Healthz is a cheap full-dependency check — edge-proxy, Docker, monitoring
// all hit this. 200 means "process is up AND I can talk to DB + Redis".
// Not used by the k8s probes any more (see Livez / Readyz).
func Healthz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 1*time.Second)
	defer cancel()

	sqlDB, err := common.DB.DB()
	if err != nil || sqlDB.PingContext(ctx) != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false, "reason": "db"})
		return
	}
	if err := common.Redis.Ping(ctx).Err(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"ok": false, "reason": "redis"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "issuer": "lum.id", "active_kid": common.Keys.Active().Kid})
}
