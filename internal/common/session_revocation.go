package common

// Session revocation — make a revoked session actually stop working.
//
// THE GAP. `ChangePasswordHandler` has always written `revoked_at` on the
// user's other sessions, and nothing ever read it: `currentUserID` accepts a
// JWT on SIGNATURE ALONE ("fast, no DB hit"). So changing your password kicked
// nobody — a stolen or shared session kept working for the full 24h token
// lifetime, and the revocation column was decoration. e2e 06 has asserted the
// intended behaviour all along and been red for it.
//
// WHY REDIS AND NOT THE DB. Identity runs 2 replicas, so an in-process cache
// would let the OTHER replica keep honouring a session this one just revoked.
// The DB is the source of truth but a point query on every authenticated
// request is exactly the cost the original comment was avoiding. Redis is
// already the cross-replica carrier here (see me_agent_grants.go, which uses it
// for approvals for the same reason), a GET is sub-millisecond, and the key
// carries its own TTL so the denylist cannot grow without bound.
//
// FAIL-OPEN, DELIBERATELY. If Redis is unreachable, IsSessionRevoked reports
// false and the request proceeds. Fail-CLOSED would turn a Redis blip into a
// total auth outage for every user — a much larger harm than the residual
// window this closes. The DB row remains authoritative for audit either way,
// and the same degradation is what the approvals path already accepts.

import (
	"context"
	"time"
)

const sessionRevokedPrefix = "session:revoked:"

// RevokeSessionJTI marks one session's jti as dead for `ttl`. Best-effort: the
// caller has already written revoked_at, which is the durable record.
func RevokeSessionJTI(ctx context.Context, jti string, ttl time.Duration) {
	if Redis == nil || jti == "" {
		return
	}
	if ttl <= 0 {
		// Already past its own expiry — the JWT will be refused on `exp`
		// anyway, so there is nothing to deny.
		return
	}
	_ = Redis.Set(ctx, sessionRevokedPrefix+jti, "1", ttl).Err()
}

// IsSessionRevoked reports whether this jti has been revoked. False on any
// Redis error or when Redis is absent — see FAIL-OPEN above.
func IsSessionRevoked(ctx context.Context, jti string) bool {
	if Redis == nil || jti == "" {
		return false
	}
	n, err := Redis.Exists(ctx, sessionRevokedPrefix+jti).Result()
	if err != nil {
		return false
	}
	return n > 0
}
