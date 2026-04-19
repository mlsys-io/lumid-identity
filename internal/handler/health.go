package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// Healthz is a cheap liveness probe — edge-proxy, Docker, monitoring
// all hit this. 200 means "process is up AND I can talk to DB + Redis".
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
