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

// TestLumilakeCapabilityScopesGrantable pins the Lumilake tags. Every scope the
// lumid plugin's policy names must be mintable here, or it is enforceable and
// unobtainable at the same time: Lumilake answers 403 naming a scope the platform
// refuses to issue. That is exactly what happened twice — jobs:read/write before
// 2026-09-13, then workers:read on 2026-09-14, where a PAT mint told super_admin
// "scope not grantable: lumilake:workers:read".
//
// These must remain CAPABILITY tags rather than service scopes: parseScope splits
// on the FIRST colon, so "lumilake:workers:read" reads as level "workers:read",
// which is not a level, and canGrant's `svc == ""` return sits ABOVE the admin
// bypass — so without the allowlist entry not even super_admin can mint one.
func TestLumilakeCapabilityScopesGrantable(t *testing.T) {
	user := models.User{Role: "user", Status: "active"}
	suspended := models.User{Role: "user", Status: "suspended"}
	super := models.User{Role: "super_admin", Status: "active"}

	for _, s := range []string{
		"lumilake:jobs:read",
		"lumilake:jobs:write",
		"lumilake:jobs:cancel",
		"lumilake:workers:read",
	} {
		if !canGrant(user, nil, s) {
			t.Fatalf("active role=user must be able to mint %q", s)
		}
		if !canGrant(super, nil, s) {
			t.Fatalf("super_admin must be able to mint %q", s)
		}
		if canGrant(suspended, nil, s) {
			t.Fatalf("suspended user must not be able to mint %q", s)
		}
		// The tag must stay OPAQUE: it confers no platform access, so parseScope
		// must still refuse to read it as a service/level pair.
		if svc, _ := parseScope(s); svc != "" {
			t.Fatalf("%q must stay opaque to parseScope, got service %q", s, svc)
		}
	}

	// Least-privilege: near-miss strings are not grantable, no prefix/wildcard rule.
	for _, bad := range []string{
		"lumilake:workers:write",
		"lumilake:workers",
		"lumilake:workers:read:extra",
		"lumilake:nodes:read",
	} {
		if canGrant(user, nil, bad) {
			t.Fatalf("%q must not be grantable by a plain user", bad)
		}
	}
}
