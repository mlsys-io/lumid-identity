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
		t.Fatal("dispatch is not carried; a define that drops it deletes the `dispatch.loop` " +
			"an experiment is attached by, and the `dispatch.ask` that makes its arms " +
			"dispatchable at all")
	}
}

// The other half of the same incident, and then its successor.
//
// The arm verb used to refuse an experiment that WAS attached, because it knew
// only one of two linkage conventions — so this test pinned `declLoop(decl)`.
// That refusal path is now GONE, and deliberately: the verb no longer reads a
// declaration at all. It cannot. identity mounts no tenant volume, so what it
// reads is a materialised copy of the PUBLISHED repo, while define_experiment
// writes the INSTALL — an experiment the user had just defined was invisible
// here, and the verb answered "experiment not found" forever
// (chiquanji@gmail.com, 2026-09-16).
//
// So the property worth pinning got stronger: add_experiment_arm must not GATE
// on anything it reads locally. That subsumes the dispatch.loop case — you
// cannot refuse an attached experiment if you never look one up — and it is the
// only shape in which the verb works for a cloud tenant at all.
func TestAddArmDoesNotGateOnALocalRead(t *testing.T) {
	src := mustRead(t, "me_agent.go")
	i := strings.Index(src, `case "add_experiment_arm":`)
	if i < 0 {
		t.Fatal("add_experiment_arm handler missing")
	}
	j := strings.Index(src[i:], `case "experiment_control":`)
	if j < 0 {
		t.Fatal("could not bound the add_experiment_arm case")
	}
	block := src[i : i+j]

	for _, gate := range []string{"resolveAppDir(", "loadAppExperimentsFor(", "declLoop("} {
		if strings.Contains(block, gate) {
			t.Errorf("add_experiment_arm calls %s — it is judging the arm against a bundle "+
				"this service cannot see. For a cloud tenant that is the PUBLISHED copy, "+
				"which never contains a locally-defined experiment, so the verb will "+
				"refuse work that is perfectly valid.", gate)
		}
	}
	// The merge belongs where the spec lives; the scheduler refuses by name
	// against the INSTALL if the experiment really is absent.
	if !strings.Contains(block, `"op": "add_arm"`) {
		t.Error("add_experiment_arm no longer queues experiment_control op=add_arm; " +
			"if it has gone back to merging here, it is merging from a stale copy and " +
			"a resent entry will erase arms it could not see")
	}
	if strings.Contains(block, `"patch_experiment"`) {
		t.Error("add_experiment_arm queues patch_experiment, which REPLACES the whole " +
			"entry — that is how both arms of a finished 52-row experiment were erased")
	}
	// declLoop still serves the HTTP write path; its two-convention behaviour is
	// pinned by TestDeclLoopReadsBothLinkageConventions.
	if got := declLoop(map[string]any{"dispatch": map[string]any{"loop": "case_eval"}}); got != "case_eval" {
		t.Fatalf("declLoop ignores dispatch.loop: %q", got)
	}
}
