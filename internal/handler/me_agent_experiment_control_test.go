package handler

// The lifecycle verbs had no front door and no back end.
//
// `status: concluded|archived` is READ by the surface (VerdictChip) and nothing
// could write it, so an experiment that was finished stayed "collecting"
// forever — while refresh_for_cycle emitted an offer, exactly once, saying
// "Consider promoting the winning variant or concluding the experiment". The
// platform asked for a verb that did not exist.

import (
	"strings"
	"testing"
)

func TestControlIntentRecognisesTheLifecycleVerbs(t *testing.T) {
	yes := []string{
		"conclude the experiment",
		"we're done with this experiment, archive it",
		"archive the analyst_local_gpu experiment",
		"reopen that experiment",
		"fork this experiment with a new arm set",
		"checkpoint the experiment — the rubric changed",
		"the rubric changed, start fresh on this metric",
		"remove the qwen14b arm",
		"drop that arm please",
		"revert the experiment definition",
		"undo that change to the experiment",
		"use experiment_control to conclude it",
	}
	for _, m := range yes {
		if !controlIntent(userMsg(m)) {
			t.Errorf("not routed to a tool-capable provider: %q", m)
		}
	}
}

func TestLifecyclePatternsLeaveConversationAlone(t *testing.T) {
	no := []string{
		"should we archive old data in general",
		"fork the repository",
		"explain checkpointing",
	}
	// NOT asserted: "what does it mean to conclude an experiment". It does route
	// to the control lane — but via a PRE-EXISTING pattern, `(list|show|what) …
	// experiments?`, not via anything added here. Narrowing that would put
	// "what experiments are running" at risk for a case whose only cost is that
	// the model answers a definition question with the registry available. The
	// lifecycle patterns themselves require the definite article ("conclude THE
	// experiment", not "conclude AN experiment"), which is the distinction that
	// was mine to get right.
	for _, m := range no {
		if controlIntent(userMsg(m)) {
			t.Errorf("a general question was captured by the control router: %q", m)
		}
	}
}

// A checkpoint fences every row measured so far out of the comparison. Doing
// that without recording why is what the hand-written comment blocks in the
// live specs exist to compensate for.
func TestCheckpointRequiresAReasonAtTheToolBoundary(t *testing.T) {
	src := loopPatchSrc(t, "me_agent.go")
	i := strings.Index(src, `case "experiment_control":`)
	if i < 0 {
		t.Fatal("experiment_control handler missing")
	}
	block := src[i : i+2500]
	if !strings.Contains(block, `op == "checkpoint" && strVal(args, "reason") == ""`) {
		t.Error("checkpoint does not require a reason before queueing")
	}
	for _, guard := range []string{`op == "fork" && strVal(args, "new_id")`, `op == "remove_arm" && strVal(args, "arm")`} {
		if !strings.Contains(block, guard) {
			t.Errorf("missing argument guard: %s", guard)
		}
	}
	if !strings.Contains(block, `writeIntent(c, "experiment_control"`) {
		t.Error("the handler does not queue an intent; identity cannot write that spec itself")
	}
}

// Every mutating experiment verb must invalidate the panel, or it keeps serving
// the pre-write copy — the bug class toolDataScopes exists to close.
func TestExperimentControlInvalidatesTheSurface(t *testing.T) {
	scopes, ok := toolDataScopes["experiment_control"]
	if !ok {
		t.Fatal("experiment_control is not in toolDataScopes")
	}
	var hasExp bool
	for _, s := range scopes {
		if s == "experiments" {
			hasExp = true
		}
	}
	if !hasExp {
		t.Errorf("scopes = %v, want the experiments scope", scopes)
	}
}

// Simple mode is the DEFAULT surface. A user who can start an experiment there
// must be able to finish one.
func TestSimpleModeCanConclude(t *testing.T) {
	if !simpleModeTools["experiment_control"] {
		t.Error("Simple mode can define, dispatch and read an experiment but not conclude it")
	}
}
