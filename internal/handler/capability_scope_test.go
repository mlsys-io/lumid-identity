package handler

import (
	"testing"

	"lumid_identity/models"
)

// TestCapabilityScopeGrantable pins the additive capability-scope rule: a plain
// active role=user may mint a PAT carrying an allowlisted opaque capability tag
// (lqt:universe:refresh), and this rule is strictly additive — it must not
// widen the platform access matrix (parseScope still ignores the tag) and must
// not turn arbitrary lqt:* strings into grantable scopes.
func TestCapabilityScopeGrantable(t *testing.T) {
	user := models.User{Role: "user", Status: "active"}
	suspended := models.User{Role: "user", Status: "suspended"}

	// The blessed capability tag is grantable by an active role=user.
	if !canGrant(user, nil, "lqt:universe:refresh") {
		t.Fatalf("expected role=user to be able to mint lqt:universe:refresh")
	}
	// A suspended user cannot mint it (status overrides everything).
	if canGrant(suspended, nil, "lqt:universe:refresh") {
		t.Fatalf("suspended user must not be able to mint lqt:universe:refresh")
	}

	// The lqt:strategy capability tag (authorizes the strategy.deploy mailbox
	// topic in lqt-auth) is likewise grantable by an active role=user and denied
	// to a suspended user.
	if !canGrant(user, nil, "lqt:strategy") {
		t.Fatalf("expected role=user to be able to mint lqt:strategy")
	}
	if canGrant(suspended, nil, "lqt:strategy") {
		t.Fatalf("suspended user must not be able to mint lqt:strategy")
	}

	// Least-privilege: an arbitrary/near-miss lqt:* string is NOT a capability
	// tag and stays un-grantable for a plain user (no wildcard, no prefix rule).
	for _, bad := range []string{
		"lqt:universe:refresh:extra",
		"lqt:universe",
		"lqt:admin",
		"lqt:*",
		"lqt:trade:execute",
		"lqt:strategy:deploy", // near-miss: the tag is exactly "lqt:strategy"
		"lqt:strategies",
	} {
		if isCapabilityScope(bad) {
			t.Fatalf("scope %q must NOT be treated as a capability tag", bad)
		}
	}

	// The capability tags must remain invisible to the access matrix: parseScope
	// (which feeds computeAccess) still returns ("","") for them, so they can
	// never upgrade a user's per-service level or role.
	for _, tag := range []string{"lqt:universe:refresh", "lqt:strategy"} {
		if svc, lvl := parseScope(tag); svc != "" || lvl != "" {
			t.Fatalf("parseScope must ignore the capability tag %q (got svc=%q lvl=%q); "+
				"otherwise computeAccess would widen access", tag, svc, lvl)
		}
	}
}
