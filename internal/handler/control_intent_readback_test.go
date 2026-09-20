package handler

import "testing"

// Reading a run back is half the control plane, and it was the missing half.
// These are realistic phrasings measured against the live router on 2026-09-18,
// when 0/8 of them routed while every "run the ..." form did.
func TestControlIntent_LoopRunReadBackRoutes(t *testing.T) {
	want := []string{
		"what did the last curation cycle produce?",
		"why did the last vla_curate cycle fail?",
		"show me the last vla_curate run",
		"how did the vla_curate run go?",
		"did the vla_curate job finish?",
		"summarize the last vla_curate cycle",
		"how many records did the vla_curate cycle write?",
		"did the workflow finish?",
		"what was the outcome of the loop?",
		"show me the records the workflow produced",
		"why did the case_cycle loop fail?",
		"when did the regression_sweep run complete?",
	}
	for _, s := range want {
		if !routes(s) {
			t.Errorf("read-back did NOT route: %q", s)
		}
	}
}

// The router also fronts a CODING agent. Every turn here must stay on
// claude-code: the platform toolset cannot see a repo, so stealing one of these
// answers it from nothing. This is the constraint that decides how wide the
// read-back patterns above may be -- they are anchored on a RESULT noun
// precisely so the GitHub-workflow and CI families below stay out.
func TestControlIntent_CodingTurnsAreNotStolen(t *testing.T) {
	mustNot := []string{
		// GitHub Actions / CI — the family a naive (show|how).*workflow steals
		"how do I write a github workflow",
		"show me the workflow file",
		"what does this workflow do?",
		"why did the workflow file fail to parse?",
		"add a new github actions workflow for linting",
		"the ci workflow output is confusing, explain it",
		"show me the output of the build workflow file",
		"why did the last CI run fail?",
		"how did the deploy go?",
		"did the build finish?",
		"what was the result of the test run?",
		// test / script runs, including underscored identifiers
		"run the tests",
		"run npm install",
		"run test_integration",
		"execute build_all.sh",
		"why did test_auth fail?",
		"show me the last commit",
		"summarize the last PR review",
		"launch a debugger on this function",
		"start the dev server",
		"what does the for loop do in this function?",
		"why does this while loop never finish?",
		"show me the output of the render loop",
		"how many records does this query return?",
		"what is the result of that function call?",
	}
	stolen := []string{}
	for _, s := range mustNot {
		if routes(s) {
			stolen = append(stolen, s)
		}
	}
	if len(stolen) > 0 {
		t.Errorf("%d coding turn(s) stolen from claude-code:", len(stolen))
		for _, s := range stolen {
			t.Errorf("   STOLEN %q", s)
		}
	}
}

// Regression guard: the forms that already worked must keep working.
func TestControlIntent_RunVerbsStillRoute(t *testing.T) {
	for _, s := range []string{
		"run the vla_curate workflow",
		"run the vla_curate loop now",
		"run the workflow",
		"kick off the VLA curation pipeline",
		"run the arm",
		"list the experiments",
	} {
		if !routes(s) {
			t.Errorf("regression — run verb stopped routing: %q", s)
		}
	}
}
