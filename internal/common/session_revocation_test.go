package common

import (
	"context"
	"testing"
	"time"
)

// The whole point is that these degrade rather than panic or lock users out
// when Redis is absent — identity must keep authenticating during a Redis blip.
func TestRevocationFailsOpenWithoutRedis(t *testing.T) {
	saved := Redis
	Redis = nil
	defer func() { Redis = saved }()

	ctx := context.Background()
	// Must not panic.
	RevokeSessionJTI(ctx, "some-jti", time.Hour)
	if IsSessionRevoked(ctx, "some-jti") {
		t.Error("with no Redis the check must fail OPEN — a blip must not lock every user out")
	}
}

func TestRevocationIgnoresEmptyAndExpired(t *testing.T) {
	ctx := context.Background()
	// An empty jti is not a session; never write a key for it, or the denylist
	// grows a permanent entry that matches every token without a jti claim.
	if IsSessionRevoked(ctx, "") {
		t.Error("an empty jti must never read as revoked")
	}
	// A session already past its own expiry needs no denylist entry — the JWT
	// is refused on `exp` anyway. Writing one would be unbounded growth.
	RevokeSessionJTI(ctx, "expired-jti", -time.Second)
	if IsSessionRevoked(ctx, "expired-jti") {
		t.Error("a already-expired session must not be written to the denylist")
	}
}
