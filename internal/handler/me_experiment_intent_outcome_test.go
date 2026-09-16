package handler

// Why define_experiment looped on 2026-09-16.
//
// A user asked the chat to set up one experiment with two arms. The assistant
// called define_experiment ~14 times over the session. Every call but one came
// back "queued — still applying ... do not report it as done yet", so it kept
// retrying; the one that answered differently said "applied: true, WITH
// WARNINGS"; and add_experiment_arm said "experiment not found" throughout.
//
// Three defects, each of which alone produces part of that transcript:
//
//  1. waitIntentWarnings polled for status "completed". The queue stores
//     done|failed — "completed" is only what MeAppIntentGet PROJECTS for API
//     clients. So a SUCCESSFUL intent never matched, the wait ran to its
//     deadline, and the tool reported "still applying" for work that had
//     already landed. Only a FAILED intent could settle the wait.
//  2. The caller read `done` (settled) as `applied`, so the single failure that
//     did settle was announced as "applied", with the scheduler's error
//     demoted into the warnings list where it reads like advice.
//  3. The warnings were read from the top level of the stored envelope, but
//     drain_once nests the handler's return under "data" — so the model
//     guard this path exists to deliver returned nothing.
//
// FILENAME NOTE: must not end in _arm_test.go — `arm` is a GOARCH, so Go
// treats such a file as architecture-specific and silently skips it on amd64.

import (
	"os"
	"strings"
	"testing"
)

// The status a successful intent actually carries must settle the wait. This is
// the whole loop: "done" not matching meant success was indistinguishable from
// still-running.
func TestSettledStatusesMatchWhatTheQueueStores(t *testing.T) {
	for _, s := range []string{"done", "failed"} {
		if !intentIsSettled(s) {
			t.Errorf("status %q is terminal in the queue but does not settle the wait — "+
				"the tool will report %q as 'still applying' forever", s, s)
		}
	}
	for _, s := range []string{"pending", "claimed", ""} {
		if intentIsSettled(s) {
			t.Errorf("status %q is not terminal but settles the wait", s)
		}
	}
	// "completed" is the API projection, never a stored value. Accepting it is
	// harmless; relying on it is the bug.
	if intentIsSettled("completed") {
		t.Error(`"completed" is never written to the status column — matching it ` +
			`is what made this wait see only failures`)
	}
}

// Pins the vocabulary at its source, so a rename on the writer side breaks here
// rather than silently reopening the loop.
func TestIntentResultWriterStillUsesDoneAndFailed(t *testing.T) {
	src, err := os.ReadFile("me_intents_db.go")
	if err != nil {
		t.Fatalf("read me_intents_db.go: %v", err)
	}
	s := string(src)
	for _, want := range []string{`status := "failed"`, `status = "done"`} {
		if !strings.Contains(s, want) {
			t.Errorf("InternalMeIntentResult no longer contains %q — the terminal status "+
				"vocabulary moved; update intentIsSettled to match", want)
		}
	}
}

func TestSuccessfulIntentIsReportedAsSucceeded(t *testing.T) {
	warns, ok := readIntentOutcome("done", `{"ok":true,"action":"patch_experiment",
		"data":{"ok":true,"action":"created","experiment":"judge_panel_parity_test_run"}}`)
	if !ok {
		t.Error("a successful patch was reported as not applied")
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings on a clean apply: %v", warns)
	}
}

// The model guard: the scheduler returns warnings INSIDE data, and they must
// reach the caller. A seat naming a model nothing serves does not error, it
// abstains, and a median-of-3 panel silently becomes a panel of one.
func TestWarningsAreReadFromTheNestedEnvelope(t *testing.T) {
	warns, ok := readIntentOutcome("done", `{"ok":true,"action":"patch_experiment",
		"data":{"ok":true,"warnings":["arm panel_median3: gemma4 resolves nowhere"]}}`)
	if !ok {
		t.Error("warnings are not a failure; the definition still applied")
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "gemma4") {
		t.Errorf("nested data.warnings never surfaced: %v", warns)
	}
}

// A failure must not be dressed up as an application, however it is signalled.
func TestFailureIsNeverReportedAsApplied(t *testing.T) {
	cases := map[string]string{
		"crash arm, top-level error": `{"ok":false,"action":"patch_experiment",
			"error":"loop 'case_eval' is not declared"}`,
		"handler error nested in data": `{"ok":true,"action":"patch_experiment",
			"data":{"error":"demo-app: no xpcloud spec to edit"}}`,
		"handler ok:false nested in data": `{"ok":true,"action":"patch_experiment",
			"data":{"ok":false}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status := "failed"
			if strings.Contains(body, `"ok":true,"action"`) &&
				!strings.Contains(body, `"error":"loop`) {
				status = "done" // the queue believed it succeeded; the body says otherwise
			}
			_, ok := readIntentOutcome(status, body)
			if ok {
				t.Error("a failed definition was reported as applied — the caller will " +
					"then add arms to an experiment that does not exist")
			}
		})
	}
}

// The caller must branch on the success verdict, not merely on settlement.
func TestDefineExperimentDoesNotEquateSettledWithApplied(t *testing.T) {
	src, err := os.ReadFile("me_agent.go")
	if err != nil {
		t.Fatalf("read me_agent.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, `if warns, done := waitIntentWarnings(`) {
		t.Error("define_experiment still reads settlement as success; a failed intent " +
			"will be announced as applied with its error demoted to a warning")
	}
	if !strings.Contains(s, `out["applied"] = succeeded`) {
		t.Error(`define_experiment must set out["applied"] from the success verdict`)
	}
}
