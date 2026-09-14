package handler

// define_experiment must not destroy what its schema cannot express.
//
// Measured 2026-09-13 on the live stack. Asked to add an arm, the platform agent
// noticed analyst_local_gpu was attached to no loop, called define_experiment to
// re-bind it, and ERASED both arms of a finished 52-row experiment whose verdict
// had just been published. The tool description already said "this is a FULL
// definition, not a patch: resend the fields you want to keep" — and a contract
// that depends on the caller remembering will meet a caller who does not. Here
// that caller was this platform's own agent, within a minute of being asked a
// perfectly reasonable question.
//
// The rule: a field the schema CANNOT set is carried forward, because omitting
// it was never a choice the caller could make. A field the schema CAN set stays
// caller-authoritative.

import (
	"strings"
	"testing"
)

// defineSchemaFields are the inputs define_experiment actually accepts.
func defineSchemaFields(t *testing.T) map[string]bool {
	t.Helper()
	for _, d := range buildToolDefsForRole("super_admin") {
		if n, _ := d["name"].(string); n != "define_experiment" {
			continue
		}
		sch, _ := d["input_schema"].(map[string]any)
		props, _ := sch["properties"].(map[string]any)
		out := map[string]bool{}
		for k := range props {
			out[k] = true
		}
		return out
	}
	t.Fatal("define_experiment not registered")
	return nil
}

func TestArmsAreNotExpressibleAndSoMustBeCarried(t *testing.T) {
	f := defineSchemaFields(t)
	for _, k := range []string{"arms", "dispatch", "baseline"} {
		if f[k] {
			t.Fatalf("%q IS settable now — if the schema gained it, the carry-forward "+
				"rule must be revisited rather than silently duplicating intent", k)
		}
	}
}

func TestHandlerCarriesTheInexpressibleFields(t *testing.T) {
	src := mustRead(t, "me_agent.go")
	// The carry list must cover every field the schema cannot set.
	for _, k := range []string{"arms", "dispatch", "baseline", "kind", "benchmark_id", "status"} {
		if !strings.Contains(src, `"`+k+`"`) {
			t.Fatalf("field %q is never referenced; it cannot be carried forward", k)
		}
	}
	if !strings.Contains(src, `carried["arms"]`) {
		t.Fatal("the patch_experiment payload does not carry arms — the destructive path is open")
	}
	if !strings.Contains(src, `carried["dispatch"]`) {
		t.Fatal("dispatch is not carried; add_experiment_arm reads its loop from there")
	}
}

// The other half of the same incident: the arm verb refused an experiment that
// WAS attached, because it knew only one of two linkage conventions.
func TestAddArmAcceptsDispatchLoop(t *testing.T) {
	src := mustRead(t, "me_agent.go")
	i := strings.Index(src, `case "add_experiment_arm":`)
	if i < 0 {
		t.Fatal("add_experiment_arm handler missing")
	}
	block := src[i : i+6000]
	// The resolution moved into declLoop, shared with the HTTP write path so the
	// two cannot disagree about what "attached" means. What this test still owns
	// is that the handler USES it; that declLoop reads both conventions is
	// pinned behaviourally by TestDeclLoopReadsBothLinkageConventions.
	if !strings.Contains(block, "declLoop(decl)") {
		t.Fatal("add_experiment_arm does not resolve its loop through declLoop; if it has " +
			"gone back to reading loops[] alone it will refuse an experiment declared " +
			"with dispatch.loop, as analyst_local_gpu is")
	}
	if got := declLoop(map[string]any{"dispatch": map[string]any{"loop": "case_eval"}}); got != "case_eval" {
		t.Fatalf("declLoop ignores dispatch.loop: %q", got)
	}
}
