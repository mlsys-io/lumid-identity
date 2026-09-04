package handler

import (
	"context"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Session revocation has two halves, and for a long time only one of them ran
// outside the change-password path.
//
// Flipping `sessions.revoked_at` is the DURABLE record, but every request that
// arrives with an already-verified JWT takes the fast path in pat.go and never
// reads that column — so a revoked session kept working until it expired on its
// own. The Redis denylist is what makes revocation take effect NOW.
//
// The ordering is deliberate and is the reason these are two calls rather than
// one helper that does both: read the doomed rows BEFORE the write (afterwards
// they no longer match `revoked_at IS NULL`), publish AFTER the commit (a
// denylist entry for a session the DB did not actually revoke locks someone out
// with no durable record explaining why).

// liveSessionsForUser returns the jti + expiry of every unrevoked session a
// user holds. Call it before the revoking UPDATE.
func liveSessionsForUser(userID string, exceptJTI string) []models.Session {
	var doomed []models.Session
	q := common.DB.Select("jti", "expires_at").
		Where("user_id = ? AND revoked_at IS NULL", userID)
	if exceptJTI != "" {
		q = q.Where("jti <> ?", exceptJTI)
	}
	_ = q.Find(&doomed).Error
	return doomed
}

// denylistSessions publishes each session to the Redis denylist for exactly as
// long as the token it kills would otherwise have lived, so the list self-trims.
// Best-effort by design: RevokeSessionJTI fails OPEN when Redis is absent, since
// a dead cache must not take authentication down with it.
func denylistSessions(ctx context.Context, doomed []models.Session) {
	if ctx == nil {
		ctx = context.Background()
	}
	for i := range doomed {
		ttl := time.Until(doomed[i].ExpiresAt)
		if ttl <= 0 {
			continue // already expired; nothing to deny
		}
		common.RevokeSessionJTI(ctx, doomed[i].JTI, ttl)
	}
}
