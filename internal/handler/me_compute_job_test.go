package handler

import "testing"

// The handler itself needs a real bearer token (currentUserID reads the
// request, not a context key), so these cover the parts that are wrong in a way
// a user would NOT see. A 200 with nothing in it looks exactly like a job that
// has not started.

func TestComputeSiteAndJobIdAreValidated(t *testing.T) {
	// Both land in a URL this service builds, and the job id is caller-supplied.
	for _, s := range []string{"../../etc", "office/evil", "", "OFFICE", "-x", "a/b"} {
		if computeSiteRe.MatchString(s) {
			t.Errorf("site %q accepted; it must not reach a built URL", s)
		}
	}
	for _, s := range []string{"office", "home", "vast2"} {
		if !computeSiteRe.MatchString(s) {
			t.Errorf("real site %q rejected", s)
		}
	}
	for _, j := range []string{"../../jobs", "wfl-abcdef", "req-a", "req-", "", "req-ab/cd"} {
		if computeJobRe.MatchString(j) {
			t.Errorf("job id %q accepted; it must not reach a built URL", j)
		}
	}
	// A real id the office site issued. Guards the validator against being
	// tightened until it rejects reality.
	if !computeJobRe.MatchString("req-FQ89FpUz6jnoyYyyjoPxxX") {
		t.Error("a real job id was rejected by the validator")
	}
}

func TestComputeTerminalCoversEveryEndState(t *testing.T) {
	// A canvas that thinks a failed job is still running polls forever, and the
	// user watches a spinner over a job that died minutes ago.
	for _, s := range []string{"completed", "failed", "cancelled"} {
		if !computeTerminal(s) {
			t.Errorf("%q must be terminal", s)
		}
	}
	for _, s := range []string{"running", "pending", "", "unknown"} {
		if computeTerminal(s) {
			t.Errorf("%q must NOT be terminal", s)
		}
	}
}

func TestComputeBaseURLDefaultsAndOverrides(t *testing.T) {
	t.Setenv("LUMILAKE_URL", "")
	if got := computeBaseURL(); got != "https://lum.id/ll" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("LUMILAKE_URL", "https://example.test/ll/")
	if got := computeBaseURL(); got != "https://example.test/ll" {
		t.Errorf("override kept the trailing slash: %q — it would build a //path", got)
	}
}

func TestStatusTokenEnvNameIsStable(t *testing.T) {
	// The 503 message names this variable so the next person configures the
	// right thing instead of debugging Lumilake. Renaming it silently would
	// make that message a lie.
	if computeStatusTokenEnv != "LUMILAKE_STATUS_TOKEN" {
		t.Errorf("env name changed to %q — update the 503 message and the secret",
			computeStatusTokenEnv)
	}
}
