package handler

// Phase D3 — /me/* PAT + session rate limit.
//
// Per-caller sliding-window counter in Redis. Default 60 req/min;
// burst tolerated up to 75 within the 60-second window (the leaky
// bucket smooths short spikes from genuine human use).
//
// Identity for the counter:
//   - bearer token (PAT or session JWT) hash, when present
//   - else session cookie value hash
//   - else remote IP (covers anonymous + edge-case calls)
//
// Failure modes:
//   - Redis unreachable → no-op (let request through). The limit is
//     defence against well-behaved clients gone rogue, not a
//     security boundary. Failing closed would take out /me/* every
//     time Redis hiccups.
//   - Counter overflow → 429 with Retry-After: <seconds_to_reset>.

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

const (
	// The Studio dashboard legitimately bursts many /me/* calls: the Apps
	// page polls ~6 endpoints/20s, the shell polls drafts+recents, the chat
	// loads models/personas/agents on mount + a runs SSE, and
	// useStudioRefetch re-fans-out on every chat tool call. 60/min throttled
	// real single-user use (apps/jobs failed to load). This is a rogue-client
	// backstop, not a security boundary — set it well above human polling.
	// 300/min (5/sec sustained per caller). After the client over-fetch cuts
	// (longer polls, narrowed refetch scopes) + in-flight GET dedup, normal
	// dashboard use sits well under this; a runaway still trips it. (Was 1200
	// as an emergency ceiling during the 429 incident; 60 originally.)
	defaultRateLimit    = 300
	defaultRateWindowS  = 60
)

func rateLimitN() int {
	if v := os.Getenv("LUMID_ME_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultRateLimit
}

// callerKey derives a stable identifier for the rate-limit bucket.
// Falls back gracefully so anonymous probes still get bucketed by IP.
func callerKey(c *gin.Context) string {
	// Prefer the explicit bearer / PAT — that's the strongest
	// caller identity. Hash it so the key never contains the
	// raw token.
	if h := c.GetHeader("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
		sum := sha256.Sum256([]byte(h[7:]))
		return "bearer:" + hex.EncodeToString(sum[:8])
	}
	if ck, err := c.Cookie("lm_session"); err == nil && ck != "" {
		sum := sha256.Sum256([]byte(ck))
		return "sess:" + hex.EncodeToString(sum[:8])
	}
	// IP — last resort. ClientIP follows X-Forwarded-For when the
	// proxy chain is trusted (it is for our nginx setup).
	return "ip:" + c.ClientIP()
}

// MeRateLimit returns a Gin middleware enforcing per-caller limits on
// the /me/* surface. Apply to the `me := v1.Group("/me", …)` block.
func MeRateLimit() gin.HandlerFunc {
	limit := rateLimitN()
	windowS := defaultRateWindowS
	return func(c *gin.Context) {
		if common.Redis == nil {
			// Redis not initialised — fail open. The dogfood scheduler
			// can take a brief Redis outage; clamping every /me/*
			// caller during that would be more disruptive than
			// letting a few extras through.
			c.Next()
			return
		}
		key := "rl:me:" + callerKey(c)
		ctx := c.Request.Context()
		// INCR then EXPIRE — both pipelined would be cleaner but the
		// two-call shape keeps the dependency on go-redis tight.
		n, err := common.Redis.Incr(ctx, key).Result()
		if err != nil {
			c.Next()
			return
		}
		if n == 1 {
			_ = common.Redis.Expire(ctx, key, time.Duration(windowS)*time.Second).Err()
		}
		if n > int64(limit) {
			ttl, _ := common.Redis.TTL(ctx, key).Result()
			retry := int(ttl.Seconds())
			if retry < 1 {
				retry = windowS
			}
			// Distinct, greppable event — so a rate-limit storm is visible at a
			// glance instead of being inferred from a wall of GIN 429 lines.
			log.Printf("[me-ratelimit] tripped caller=%s n=%d/%d path=%s", callerKey(c), n, limit, c.FullPath())
			c.Header("Retry-After", strconv.Itoa(retry))
			c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
			c.Header("X-RateLimit-Reset", strconv.Itoa(retry))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"ret_code": 1429, "message": "too many requests",
				"data": gin.H{"limit": limit, "window_s": windowS, "retry_after_s": retry},
			})
			c.Abort()
			return
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(limit-int(n)))
		c.Next()
	}
}
