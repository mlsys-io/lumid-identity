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

// TestFlowmeshFleetReadScopesGrantable pins the FlowMesh fleet-read tags. These
// are the strings the lumid plugin maps for (WORKER, READ) and (NODE, READ) and
// declares as `fleet_kinds`. Studio gets them on the aud=flowmesh session-bearer,
// which bypasses canGrant entirely — so the gap was PAT-only, and the practical
// cost was that least-privilege could not be expressed: reading workers through
// /ll/<site>/ forwards the caller's bearer to FlowMesh, and the only mintable
// option was the `flowmesh:*` wildcard.
//
// READ ONLY is the whole point. The write counterparts must stay un-grantable, so
// a mistake here shows up as a test failure rather than as a PAT that can mutate
// the fleet.
func TestFlowmeshFleetReadScopesGrantable(t *testing.T) {
	user := models.User{Role: "user", Status: "active"}
	suspended := models.User{Role: "user", Status: "suspended"}

	for _, s := range []string{"flowmesh:workers:read", "flowmesh:nodes:read"} {
		if !canGrant(user, nil, s) {
			t.Fatalf("active role=user must be able to mint %q", s)
		}
		if canGrant(suspended, nil, s) {
			t.Fatalf("suspended user must not be able to mint %q", s)
		}
		if svc, _ := parseScope(s); svc != "" {
			t.Fatalf("%q must stay opaque to parseScope, got service %q", s, svc)
		}
	}

	// Scopes outside the session-bearer set must stay un-grantable for a plain user.
	// `flowmesh:*` remains admin-only via the matrix, not via this allowlist.
	//
	// NARROWED 2026-09-14: this list used to include flowmesh:workflows:write and
	// flowmesh:tasks:read. Both are now deliberately grantable — see
	// TestFlowmeshSessionBearerParity. They are in the aud=flowmesh session-bearer
	// that every signed-in user already receives, so refusing them on a PAT bought
	// no safety and forced callers onto the `flowmesh:*` WILDCARD to run one job.
	// The remaining entries are NOT in that set, so they would be a real widening.
	for _, bad := range []string{
		"flowmesh:workers:write",
		"flowmesh:nodes:write",
		"flowmesh:results:write",
		"flowmesh:system:read",
		"flowmesh:workers",
		"flowmesh:workers:read:extra",
	} {
		if canGrant(user, nil, bad) {
			t.Fatalf("%q must not be grantable by a plain user", bad)
		}
	}
}

// TestFlowmeshSessionBearerParity pins the rule that decides this list: a PAT may
// carry exactly what the aud=flowmesh SESSION-BEARER already mints for every
// signed-in user (user.go, `case "flowmesh"`), and nothing more. That is a
// credential-type change, not a privilege change — the same person holds these the
// moment they log in.
//
// The mutating scopes that are NOT in the session-bearer set must stay
// un-grantable, so widening shows up here as a failure rather than as a PAT that
// can do more than a login.
func TestFlowmeshSessionBearerParity(t *testing.T) {
	user := models.User{Role: "user", Status: "active"}
	suspended := models.User{Role: "user", Status: "suspended"}

	// Exactly the set user.go mints for aud=flowmesh.
	sessionBearerSet := []string{
		"flowmesh:ssh",
		"flowmesh:workflows:write",
		"flowmesh:workflows:read",
		"flowmesh:tasks:read",
		"flowmesh:results:read",
		"flowmesh:workers:read",
		"flowmesh:nodes:read",
	}
	for _, s := range sessionBearerSet {
		if !canGrant(user, nil, s) {
			t.Fatalf("session-bearer scope %q must be PAT-mintable (credential parity)", s)
		}
		if canGrant(suspended, nil, s) {
			t.Fatalf("suspended user must not be able to mint %q", s)
		}
		if svc, _ := parseScope(s); svc != "" {
			t.Fatalf("%q must stay opaque to parseScope, got service %q", s, svc)
		}
	}

	// NOT in the session-bearer set => must NOT be grantable. Adding any of these
	// would let a PAT exceed what its owner gets by logging in.
	for _, bad := range []string{
		"flowmesh:workers:write",
		"flowmesh:nodes:write",
		"flowmesh:results:write",
		"flowmesh:system:read",
		"flowmesh:workflows:cancel",
	} {
		if canGrant(user, nil, bad) {
			t.Fatalf("%q is not in the session-bearer set and must not be grantable", bad)
		}
	}
}
