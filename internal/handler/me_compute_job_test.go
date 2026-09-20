package handler

import (
	"encoding/json"
	"testing"
)

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

// The compute job-status route proxies with OUR credential, not the caller's.
// Everything that keeps it from being an open reader of every job on every
// site runs through computeJobsContain, so these are the security tests.
func TestComputeJobOwnershipIsExactNotSubstring(t *testing.T) {
	const stored = `[{"job_id":"req-abcdef","site":"office"},{"job_id":"req-zz","site":"home"}]`

	cases := []struct {
		name      string
		site, job string
		want      bool
		why       string
	}{
		{"the pair it actually ran", "office", "req-abcdef", true, ""},
		{"a second pair on another site", "home", "req-zz", true, ""},

		// The LIKE pre-filter matches a substring anywhere in the column, so a
		// row holding req-abcdef is HANDED to this function when the caller
		// asks for req-abc. Authorizing on that would grant a job the caller
		// never ran, using a prefix of one they did.
		{"a prefix of a job it ran", "office", "req-abc", false,
			"prefix must not authorize the longer id"},
		{"a suffix of a job it ran", "office", "abcdef", false,
			"suffix must not authorize"},

		// Both halves or nothing: cloud/home/office are three separate
		// Lumilakes that each answer "not found" for the others' jobs, so
		// owning req-abcdef on office says nothing about it on home.
		{"right job, wrong site", "home", "req-abcdef", false,
			"a job id is only owned on the site it ran"},
		{"right site, wrong job", "office", "req-zz", false, ""},

		{"empty job", "office", "", false, ""},
		{"empty site", "", "req-abcdef", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeJobsContain(stored, tc.site, tc.job); got != tc.want {
				t.Fatalf("computeJobsContain(%q, %q) = %v, want %v — %s",
					tc.site, tc.job, got, tc.want, tc.why)
			}
		})
	}
}

func TestComputeJobOwnershipFailsClosedOnBadData(t *testing.T) {
	// A column that cannot be parsed is not permission. Malformed state must
	// deny, never default open — the whole point of the gate is that the
	// upstream credential is ours.
	for _, raw := range []string{"", "not json", "{}", "null", `[{"job_id":"req-a"}]`,
		`[{"site":"office"}]`, `["req-a"]`} {
		if computeJobsContain(raw, "office", "req-a") {
			t.Fatalf("malformed stored value %q authorized a job", raw)
		}
	}
}

// A switcher is only useful if it names what it draws, so the arm has to
// survive the round trip through the stored JSON.
func TestStoredJobRefsCarryTheirArmAndWorkers(t *testing.T) {
	const stored = `[{"job_id":"req-a","site":"office","arm":"baseline",` +
		`"workers":{"score":"w-1"}},{"job_id":"req-b","site":"home","arm":"variant"}]`
	var refs []computeJobRef
	if err := json.Unmarshal([]byte(stored), &refs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(refs) != 2 || refs[0].Arm != "baseline" || refs[1].Arm != "variant" {
		t.Fatalf("arms lost in the round trip: %+v", refs)
	}
	if refs[0].Workers["score"] != "w-1" {
		t.Fatalf("worker placement lost: %+v", refs[0].Workers)
	}
	// An arm-less entry is legal — a single-job run has no arm — and must not
	// become the empty string masquerading as one.
	if refs[1].Workers != nil {
		t.Fatalf("absent workers should stay nil, got %+v", refs[1].Workers)
	}
}

// Ownership still decides, and it decides on the pair — adding arm/workers to
// the struct must not have widened what counts as a match.
func TestArmDoesNotWidenOwnership(t *testing.T) {
	const stored = `[{"job_id":"req-a","site":"office","arm":"baseline"}]`
	if !computeJobsContain(stored, "office", "req-a") {
		t.Fatal("the owned pair stopped matching")
	}
	if computeJobsContain(stored, "home", "req-a") {
		t.Fatal("arm presence let a wrong-site job through")
	}
}
