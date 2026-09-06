package handler

// Isolation must hold in BOTH directions and must not depend on anything the
// client sends. These cover the two identity-side halves of that: the pool
// carried out to claude-proxy on introspection (which is what lets it notice a
// cached lease predates a membership change), and the shared session pin,
// which was an unauthenticated lookup into other users' account bindings.
//
// DB-backed, same convention as claude_pool_membership_test.go: runs only when
// TEST_MYSQL_DSN is set.

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// Introspection must report the pool the caller actually draws from, not just
// the three access verdicts. claude-proxy caches a leased credential per
// session for up to 30 minutes WITHOUT calling identity again, so this value
// is the only way it can learn that a membership changed underneath a live
// session.
func TestIntrospectionCarriesTheResolvedPool(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	const poolID = "iso-carry"
	cleanupClaudePool(t, db, poolID)
	if err := db.Create(&models.ClaudePool{ID: poolID, Name: "Isolation", Mode: models.ClaudePoolModeDistributed}).Error; err != nil {
		t.Fatalf("create pool: %v", err)
	}
	member := claudePoolTestUser(t, db, "carry")
	outsider := claudePoolTestUser(t, db, "outsider")
	if err := db.Create(&models.ClaudePoolMember{PoolID: poolID, UserSub: member, IsPrimary: true, AddedAt: time.Now()}).Error; err != nil {
		t.Fatalf("add member: %v", err)
	}

	if got := enrichClaudePolicy(IntrospectResponse{Active: true, Sub: member}).ClaudePoolID; got != poolID {
		t.Fatalf("member of %s introspects as pool %q — claude-proxy cannot detect a pool change without this",
			poolID, got)
	}
	// A NON-member must resolve to default, whatever they ask for. The hint is
	// a client-supplied PAT scope; trusting it would make pool membership
	// self-service.
	if got := enrichClaudePolicy(IntrospectResponse{
		Active: true, Sub: outsider, Scopes: []string{"claude-pool:" + poolID},
	}).ClaudePoolID; got != models.DefaultClaudePoolID {
		t.Fatalf("a non-member presenting claude-pool:%s introspected as %q, want %q — "+
			"membership is identity's to decide, not the token's",
			poolID, got, models.DefaultClaudePoolID)
	}
	// An inactive token carries no identity, so it must not resolve a pool at
	// all — an empty value is what disables the consumer's comparison.
	if got := enrichClaudePolicy(IntrospectResponse{Active: false, Sub: member}).ClaudePoolID; got != "" {
		t.Fatalf("an inactive token resolved pool %q", got)
	}
}

// The shared session pin reads ClaudeSessionBinding by session_key — which is
// x-claude-code-session-id, a value the CLIENT sends. Unscoped, presenting
// another user's id returned their bound account as prefer_email. Pool scoping
// stops that becoming a cross-pool leak (candidates are WHERE pool_id = ?, and
// an account belongs to exactly one pool), but within a pool it still let one
// user steer another's session onto their subscription.
func TestTheSharedSessionPinDoesNotCrossUsers(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	owner := claudePoolTestUser(t, db, "pinowner")
	other := claudePoolTestUser(t, db, "pinother")

	const key = "01998fd9-a-real-looking-session-id"
	db.Exec(`DELETE FROM claude_session_bindings WHERE session_key = ?`, key)
	t.Cleanup(func() { db.Exec(`DELETE FROM claude_session_bindings WHERE session_key = ?`, key) })
	now := time.Now()
	if err := db.Create(&models.ClaudeSessionBinding{
		SessionKey: key, Email: "owners-account@example.com", UserSub: owner,
		CreatedAt: now, LastSeenAt: now,
	}).Error; err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// Exercises the production resolver, not a re-typed copy of its query.
	if got := sessionPinPrefer(key, owner); got != "owners-account@example.com" {
		t.Fatalf("the owner lost their own pin: %q", got)
	}
	if got := sessionPinPrefer(key, other); got != "" {
		t.Fatalf("another user presenting the same session id was handed %q as prefer_email", got)
	}
}
