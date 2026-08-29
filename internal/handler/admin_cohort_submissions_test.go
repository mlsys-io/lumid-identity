package handler

import "testing"

// extractSubmission is the only parsing in this handler, and everything a
// reviewer sees hangs off it. A submission that is present but unreadable
// renders as an empty row — a researcher who filed reads as one who did not,
// which is the single worst failure this surface can have.

func TestExtractSubmissionTopLevel(t *testing.T) {
	got := extractSubmission(`{"ok":true,"submission":{"for_period":"2026-08-29"}}`)
	if got == nil || got["for_period"] != "2026-08-29" {
		t.Fatalf("top-level submission not extracted: %v", got)
	}
}

// The engine may nest a command's return under its own key (the same shape
// `runs` already reaches through for `command_engine.source_strategy_id`), so
// one level down has to work too.
func TestExtractSubmissionNestedUnderEngineKey(t *testing.T) {
	got := extractSubmission(`{"command_engine":{"submission":{"for_period":"2026-09-12"}}}`)
	if got == nil || got["for_period"] != "2026-09-12" {
		t.Fatalf("nested submission not extracted: %v", got)
	}
}

// Absent, blank and malformed must all be nil rather than panicking or
// inventing a row: a run of the digest loop (not the submit loop) has no
// submission in it at all, and that is ordinary, not an error.
func TestExtractSubmissionAbsentOrMalformed(t *testing.T) {
	for name, blob := range map[string]string{
		"empty":      "",
		"not json":   "{not json",
		"no key":     `{"ok":true,"digest_path":"/tmp/x"}`,
		"wrong type": `{"submission":"a string, not an object"}`,
	} {
		if got := extractSubmission(blob); got != nil {
			t.Fatalf("%s: expected nil, got %v", name, got)
		}
	}
}

// The alias group must not silently widen the query. `lumid-cohort-digest` is
// not in a group, so it must resolve to itself alone — if it ever picked up
// quant-research's group, a reviewer's cohort page would fill with backtest
// runs that are not submissions.
func TestCohortAppHasNoAliasGroup(t *testing.T) {
	got := appAliases(cohortDigestApp)
	if len(got) != 1 || got[0] != cohortDigestApp {
		t.Fatalf("expected [%s] alone, got %v", cohortDigestApp, got)
	}
}
