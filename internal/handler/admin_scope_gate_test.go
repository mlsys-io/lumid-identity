package handler

// A PAT's ROLE decided the admin surface; its SCOPES were never read.
//
// So a token minted for one narrow purpose was a full operator credential.
// Measured 2026-09-21: a PAT whose scopes are exactly
// ["claude:proxy", "flowmesh:workflows:write"] — neither an admin scope —
// returned 200 on every admin AND super_admin route, including
// /admin/claude-sessions, which carries recorded session content and was moved
// behind super_admin on 2026-09-02 precisely because it is sensitive.
//
// The check lands in OBSERVE mode. Every admin PAT in the estate was minted
// without an admin scope because nothing ever asked for one, so enforcing
// immediately would revoke access from automation that is working correctly.
// These tests pin the DECISION, which is what the eventual flip turns on.

import (
	"os"
	"testing"
)

func TestScopesThatAuthorizeAdmin(t *testing.T) {
	for _, s := range []string{
		"lumid:admin",
		"lumid:*",
		"*",
		"claude:proxy lumid:admin",       // admin scope among others
		"  lumid:admin  claude:proxy   ", // whitespace is not significant
	} {
		if !scopesAuthorizeAdmin(s) {
			t.Errorf("scopes %q should authorize the admin surface", s)
		}
	}
}

func TestScopesThatDoNotAuthorizeAdmin(t *testing.T) {
	for _, s := range []string{
		"",             // a PAT with no scopes at all
		"claude:proxy", // the credential from the finding
		"claude:proxy flowmesh:workflows:write",
		"lqt:strategy findata:sql",
		"lumid:read",
	} {
		if scopesAuthorizeAdmin(s) {
			t.Errorf("scopes %q must NOT authorize the admin surface", s)
		}
	}
}

func TestLumidWriteIsNotAnAdminScope(t *testing.T) {
	// Called out separately because it is the tempting mistake.
	// callerHasLumidWrite (pat.go) accepts lumid:write for writes on your OWN
	// resources. The operator surface is a different question — reusing that
	// scope here would hand the whole admin API to every token that can edit
	// its owner's own things.
	if scopesAuthorizeAdmin("lumid:write") {
		t.Fatal("lumid:write must not authorize the admin surface")
	}
	if !scopesAuthorizeAdmin("lumid:write lumid:admin") {
		t.Fatal("lumid:write alongside lumid:admin should still authorize")
	}
}

func TestEnforcementIsOffByDefault(t *testing.T) {
	// The safety property of this change. If this ever defaults to true, every
	// admin PAT in the estate stops working at once.
	t.Setenv("IDENTITY_REQUIRE_ADMIN_SCOPE", "")
	if requireAdminScope() {
		t.Fatal("enforcement must default to observe-only")
	}
	_ = os.Unsetenv("IDENTITY_REQUIRE_ADMIN_SCOPE")
	if requireAdminScope() {
		t.Fatal("an unset env must mean observe-only")
	}
}

func TestEnforcementFlipsOnTheDocumentedValues(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", " true "} {
		t.Setenv("IDENTITY_REQUIRE_ADMIN_SCOPE", v)
		if !requireAdminScope() {
			t.Errorf("IDENTITY_REQUIRE_ADMIN_SCOPE=%q should enforce", v)
		}
	}
	for _, v := range []string{"0", "false", "no", "maybe"} {
		t.Setenv("IDENTITY_REQUIRE_ADMIN_SCOPE", v)
		if requireAdminScope() {
			t.Errorf("IDENTITY_REQUIRE_ADMIN_SCOPE=%q should NOT enforce", v)
		}
	}
}
