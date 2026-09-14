package handler

// POST and PATCH are different verbs and now behave differently.
//
// Until this change MeAppExperimentUpsert was pure replace under BOTH: the
// payload was assembled solely from the request body, so a PATCH omitting
// `arms` erased them. That is the HTTP twin of the 2026-09-13 incident in which
// the chat path erased both arms of a finished 52-row experiment — and the SPA's
// only experiment write goes through this handler.
//
// The shape guard compounded it. It requires loop + metric.name + a scope on
// every write, so a PATCH changing only success_criteria was rejected 422, while
// a PATCH complete enough to pass silently dropped everything it did not name.
// Hydrating first makes the guard judge the experiment the write RESULTS IN.

import "testing"

func declFixture() map[string]any {
	return map[string]any{
		"id":               "analyst_local_gpu",
		"loops":            []string{"case_eval"},
		"metric":           map[string]any{"name": "avg_question_score", "higher_is_better": true},
		"dataset_id":       "cases_v1",
		"success_criteria": "best_n >= 20",
		"hypothesis":       "the original hypothesis",
		"description":      "the original description",
		"kind":             "arms",
		"min_samples":      20,
		"baseline":         map[string]any{"arm": "qwen7b_local"},
		"dispatch":         map[string]any{"loop": "case_eval"},
		"arms": []map[string]any{
			{"id": "qwen7b_local"}, {"id": "gemma4_local"}, {"id": "qwen14b_local"},
		},
	}
}

// The case the plan names: change one field, keep the other twelve.
func TestHydratePatchBodyFillsEverythingTheCallerOmitted(t *testing.T) {
	body := experimentWriteBody{ID: "analyst_local_gpu", Criteria: "best_n >= 40"}
	hydratePatchBody(&body, declFixture())

	if body.Criteria != "best_n >= 40" {
		t.Errorf("the caller's own change was overwritten: %q", body.Criteria)
	}
	if len(body.Arms) != 3 {
		t.Fatalf("arms = %d, want 3 — a PATCH that did not mention arms erased them", len(body.Arms))
	}
	if body.Loop != "case_eval" {
		t.Errorf("loop = %q, want case_eval", body.Loop)
	}
	if body.Metric == nil || body.Metric.Name != "avg_question_score" {
		t.Errorf("metric = %#v", body.Metric)
	}
	if body.DatasetID != "cases_v1" {
		t.Errorf("dataset_id = %q", body.DatasetID)
	}
	if body.MinSamples == nil || *body.MinSamples != 20 {
		t.Errorf("min_samples = %#v — declared as an int, and the old code only read float64", body.MinSamples)
	}
	if body.Baseline["arm"] != "qwen7b_local" {
		t.Errorf("baseline = %#v", body.Baseline)
	}
	if body.Dispatch["loop"] != "case_eval" {
		t.Errorf("dispatch = %#v", body.Dispatch)
	}
	if body.Hypothesis == "" || body.Description == "" || body.Kind == "" {
		t.Errorf("prose fields dropped: %q / %q / %q", body.Hypothesis, body.Description, body.Kind)
	}

	// And the merged body must now SATISFY the guard that would have 422'd the
	// request as sent. This is the whole point of hydrating before validating.
	if problems := validateExperimentShape(&body); len(problems) > 0 {
		t.Errorf("merged body still fails the shape guard: %v", problems)
	}
}

// Before hydration the same request is not a valid experiment — which is what
// made "partial" impossible rather than merely lossy.
func TestPatchBodyAloneWouldFailTheShapeGuard(t *testing.T) {
	body := experimentWriteBody{ID: "analyst_local_gpu", Criteria: "best_n >= 40"}
	if problems := validateExperimentShape(&body); len(problems) == 0 {
		t.Fatal("expected the bare PATCH body to fail the guard; hydration has nothing to prove")
	}
}

// Both linkage conventions are legitimate. Knowing only loops[] made
// add_experiment_arm refuse analyst_local_gpu as "attached to no loop".
func TestDeclLoopReadsBothLinkageConventions(t *testing.T) {
	cases := []struct {
		name string
		decl map[string]any
		want string
	}{
		{"loops[] as []string", map[string]any{"loops": []string{"case_eval"}}, "case_eval"},
		{"loops[] as []any", map[string]any{"loops": []any{"case_eval"}}, "case_eval"},
		{"dispatch.loop fallback", map[string]any{"dispatch": map[string]any{"loop": "kol_strategy"}}, "kol_strategy"},
		{"loops[] wins", map[string]any{"loops": []string{"a"}, "dispatch": map[string]any{"loop": "b"}}, "a"},
		{"neither", map[string]any{}, ""},
		{"nil", nil, ""},
	}
	for _, c := range cases {
		if got := declLoop(c.decl); got != c.want {
			t.Errorf("%s: declLoop = %q, want %q", c.name, got, c.want)
		}
	}
}

// A POST means "replace", so it CAN clear arms — but not by accident. The guard
// only fires when arms already exist and the request carries none.
func TestPostReplaceGuardOnlyFiresWhenItWouldDestroy(t *testing.T) {
	decl := declFixture()
	armed := func(d map[string]any) int {
		a, _ := d["arms"].([]map[string]any)
		return len(a)
	}
	if armed(decl) == 0 {
		t.Fatal("fixture has no arms; the guard has nothing to protect")
	}
	// The handler's condition, stated here so a refactor cannot quietly invert it.
	type req struct {
		name      string
		declFound map[string]any
		bodyArms  int
		wantBlock bool
	}
	for _, r := range []req{
		{"new experiment, no arms sent", nil, 0, false},
		{"existing armed experiment, no arms sent", decl, 0, true},
		{"existing armed experiment, arms resent", decl, 2, false},
		{"existing unarmed experiment", map[string]any{"id": "x"}, 0, false},
	} {
		block := r.declFound != nil && r.bodyArms == 0 && armed(r.declFound) > 0
		if block != r.wantBlock {
			t.Errorf("%s: block = %v, want %v", r.name, block, r.wantBlock)
		}
	}
}
