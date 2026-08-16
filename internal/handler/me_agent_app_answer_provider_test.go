package handler

// answerWithAppVoiceModel speaks HTTP only, but some providers are SUBPROCESS
// transports (claude-code-* runs the CLI in the sandbox and carries
// endpoint: ""), and super_admin's default IS claude-code-sonnet. So every
// app_answer by a super_admin — the operator and demo account — POSTed to ""
// and returned "unsupported protocol scheme".
//
// It failed loudly and degraded quietly: seeing the tool error, the agent
// answered from its own knowledge, so the reply still looked like a consulting
// answer while carrying none of the app's analyst prompt, none of its skill
// cards, and no score. That is the failure mode this pins.

import "testing"

func TestHTTPProviderFor_NeverReturnsASubprocessProvider(t *testing.T) {
	for _, role := range []string{"user", "admin", "super_admin", "", "nonsense"} {
		p := httpProviderFor(role)
		if p.endpoint == "" {
			t.Fatalf("role %q got endpoint-less provider %q — this path cannot run a subprocess", role, p.id)
		}
	}
}

func TestSuperAdminDefaultIsSubprocess(t *testing.T) {
	// Documents WHY the guard exists. If this ever stops being true the guard
	// is harmless, but the bug it prevents is worth keeping visible.
	d := defaultProviderFor("super_admin")
	if d.endpoint != "" {
		t.Skipf("super_admin default %q now has an endpoint — guard is belt-and-braces", d.id)
	}
	if got := httpProviderFor("super_admin"); got.endpoint == "" {
		t.Fatal("super_admin still resolves to a subprocess provider on the HTTP path")
	}
}

func TestHTTPProviderFor_RespectsRole(t *testing.T) {
	// The fallback must not escalate a low-tier caller onto a high-tier model.
	p := httpProviderFor("user")
	if p.endpoint == "" {
		t.Fatal("no HTTP provider for a plain user")
	}
	if !providerAllowed("user", p) {
		t.Fatalf("fallback escalated a user to %q", p.id)
	}
}
