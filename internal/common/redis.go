package common

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"

	"lumid_identity/internal/config"
)

var Redis *redis.Client

// OpenRedis creates the client and waits up to `wait` for Redis to answer PING, backing off
// between attempts. It returns the last error if Redis never answered — but the client is set
// either way, and callers must NOT treat that error as fatal.
//
// Why: identity's critical path (login, /oauth/introspect, JWKS) does not touch Redis; every
// Redis use in the handlers already degrades (rate limits fail open, OTP/cool-downs return an
// error). go-redis also reconnects lazily on the next command. The old `log.Fatalf` on a failed
// startup PING turned a ~4 min Redis outage (PVC swap, 2026-10-26) into a crash loop of BOTH
// replicas — i.e. lum.id auth down — and CrashLoopBackOff then delayed recovery further.
func OpenRedis(c *config.Config, wait time.Duration) error {
	Redis = redis.NewClient(&redis.Options{
		Addr:     c.Redis.Addr,
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})
	deadline := time.Now().Add(wait)
	backoff := 500 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := Redis.Ping(ctx).Err()
		cancel()
		if err == nil || time.Now().Add(backoff).After(deadline) {
			return err
		}
		time.Sleep(backoff)
		if backoff < 5*time.Second {
			backoff *= 2
		}
	}
}
