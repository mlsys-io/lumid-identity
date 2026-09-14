package handler

// A warning nobody reads is not a warning.
//
// The model guard is why define_experiment has a guard at all: a model name
// that resolves nowhere does not error, it ABSTAINS, and a "median of three"
// panel quietly becomes a panel of one while every number on screen still looks
// healthy. mbb-ai published an n=300 verdict off an instrument in that state.
//
// The scheduler produces that warning — after writing the spec, in the intent
// result — and the tool's own answer said "poll the intent for any model
// warnings" while nothing polled. So the assistant reported success and the
// warning was never spoken.

import (
	"strings"
	"testing"
)

func TestDefineExperimentWaitsForItsWarnings(t *testing.T) {
	src := loopPatchSrc(t, "me_agent.go")
	i := strings.Index(src, `case "define_experiment":`)
	if i < 0 {
		t.Fatal("define_experiment handler missing")
	}
	block := src[i : i+6000]
	if !strings.Contains(block, "waitIntentWarnings(") {
		t.Error("define_experiment does not wait for the intent result; the model warning " +
			"lands in a place nothing reads")
	}
	if strings.Contains(block, "poll the intent for the result and any model warnings\"}, true") {
		t.Error("the old fire-and-forget return is still there")
	}
	// And when it DOES time out it must say so, not imply there was nothing to
	// report — silence is what the warning was competing with.
	if !strings.Contains(block, "do not report it as done yet") {
		t.Error("a timed-out wait does not tell the assistant to withhold the claim")
	}
}

// The wait is bounded: a chat turn cannot stall on a queue.
func TestTheWaitIsBounded(t *testing.T) {
	src := loopPatchSrc(t, "me_experiment_carry.go")
	if !strings.Contains(src, "deadline := time.Now().Add(budget)") {
		t.Error("waitIntentWarnings has no deadline")
	}
	if !strings.Contains(src, "First(&row).Error; err != nil") {
		t.Error("the poll does not scope the lookup to the caller")
	}
	agent := loopPatchSrc(t, "me_agent.go")
	if !strings.Contains(agent, "waitIntentWarnings(userID, id, 6*time.Second)") {
		t.Error("the chat-side budget is not the short one a turn can afford")
	}
}

// Promote and discard shelled out to a binary this image does not ship, so both
// returned 503 and a red toast — two controls the run tree offers that have
// never worked for anyone.
func TestPromoteAndDiscardFallThroughToAnIntent(t *testing.T) {
	src := loopPatchSrc(t, "me_trajectory_ops.go")
	if !strings.Contains(src, `writeIntent(c, "mark_run"`) {
		t.Error("promote/discard still dead-ends on the missing CLI")
	}
	if !strings.Contains(src, "if status == http.StatusServiceUnavailable {") {
		t.Error("the fallback is not scoped to the CLI-absent case; a real CLI error " +
			"must still surface as an error rather than being queued")
	}
}
