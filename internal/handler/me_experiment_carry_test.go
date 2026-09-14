package handler

// What a partial write must put back.
//
// patch_experiment replaces the whole experiments[] entry, so every verb that
// rewrites an experiment has to resend the fields it did not mean to change.
// Two verbs do that, they were written a day apart, and they had already
// drifted: define_experiment carried six keys, add_experiment_arm carried a
// different (smaller, and partly broken) set. These tests pin the union.
//
// FILENAME NOTE: must not end in _arm_test.go — `arm` is a GOARCH, so Go treats
// such a file as architecture-specific and silently skips it on amd64. The
// package still reports ok, with none of the tests compiled.

import (
	"os"
	"strings"
	"testing"
)

// The carry set is the part define_experiment cannot express; the rewrite set is
// everything a full rewrite must resend. The first must be inside the second, or
// add_experiment_arm would preserve LESS than define_experiment does.
func TestExperimentCarryKeysSubsetOfRewriteKeys(t *testing.T) {
	in := map[string]bool{}
	for _, k := range experimentRewriteKeys {
		in[k] = true
	}
	for _, k := range experimentCarryKeys {
		if !in[k] {
			t.Errorf("carry key %q is not in experimentRewriteKeys — add_experiment_arm "+
				"would drop a field define_experiment preserves", k)
		}
	}
	seen := map[string]bool{}
	for _, k := range experimentRewriteKeys {
		if seen[k] {
			t.Errorf("experimentRewriteKeys lists %q twice", k)
		}
		seen[k] = true
	}
}

// define_experiment builds its intent payload by naming carried[...] keys one by
// one. A key added to experimentCarryKeys but not named there is carried into a
// map and then dropped on the floor — which reads like it works.
func TestDefineExperimentPayloadNamesEveryCarryKey(t *testing.T) {
	src, err := os.ReadFile("me_agent.go")
	if err != nil {
		t.Fatalf("read me_agent.go: %v", err)
	}
	s := string(src)
	for _, k := range experimentCarryKeys {
		if !strings.Contains(s, `carried["`+k+`"]`) {
			t.Errorf("define_experiment's intent payload never reads carried[%q]; the key is "+
				"collected and then discarded", k)
		}
	}
}

// The six fields add_experiment_arm used to lose. Three were invisible: dispatch,
// cases and description were not even on the row it read, and min_samples was on
// the row as an int while the code asserted float64 — so the threshold was erased
// on every arm add and the criteria floor silently fell back to 1.
func TestExperimentCarryOntoPreservesWhatTheVerbCannotExpress(t *testing.T) {
	decl := map[string]any{
		"id":               "kol_alpha",
		"arms":             []map[string]any{{"id": "old"}},
		"dispatch":         map[string]any{"loop": "kol_strategy", "ask": "which strategy?"},
		"baseline":         map[string]any{"arm": "current"},
		"kind":             "arms",
		"benchmark_id":     "bench1",
		"status":           "active",
		"cases":            []string{"Case_001", "Case_002"},
		"description":      "a description",
		"min_samples":      10, // int, as expDecl declares it
		"dataset_id":       "musk_tweets_v1",
		"success_criteria": "best_n >= 10",
		"hypothesis":       "a hypothesis",
		"metric":           map[string]any{"name": "real_tape", "higher_is_better": true},
	}
	payload := map[string]any{
		"app": "quant-research", "experiment": "kol_alpha", "loop": "kol_strategy",
		"arms": []map[string]any{{"id": "old"}, {"id": "new"}},
	}
	experimentCarryOnto(payload, decl, "arms")

	if d, _ := payload["dispatch"].(map[string]any); d == nil || d["ask"] != "which strategy?" {
		t.Errorf("dispatch not carried: %#v — adding an arm to backtest_evidence would delete "+
			"the dispatch.ask that makes its arms dispatchable at all", payload["dispatch"])
	}
	if cs, _ := payload["cases"].([]string); len(cs) != 2 {
		t.Errorf("cases not carried: %#v — the scheduler refuses a patch with no scope, so an "+
			"experiment scoped by cases would fail outright", payload["cases"])
	}
	if payload["min_samples"] != 10 {
		t.Errorf("min_samples = %#v, want int 10 — the old code tested .(float64) against an "+
			"int and never fired", payload["min_samples"])
	}
	for _, k := range []string{"benchmark_id", "description", "dataset_id", "success_criteria", "hypothesis", "kind"} {
		if payload[k] == nil {
			t.Errorf("%s not carried", k)
		}
	}
	if b, _ := payload["baseline"].(map[string]any); b == nil || b["arm"] != "current" {
		t.Errorf("baseline not carried: %#v", payload["baseline"])
	}

	// The verb's own field wins: arms was skipped, so the caller's two-arm list
	// survives rather than being overwritten by the declaration's one.
	if got := len(payload["arms"].([]map[string]any)); got != 2 {
		t.Errorf("arms overwritten by the declaration: got %d, want the caller's 2", got)
	}

	// status "active" is the ROW's default, injected by strOr() even when the
	// spec never declared it. Writing it back would add a key the app did not
	// author, to a file whose contents are a decision record.
	if _, ok := payload["status"]; ok {
		t.Errorf("default status was injected into the payload: %#v", payload["status"])
	}
}

// A concluded or archived experiment must not be silently reopened by someone
// adding an arm to it.
func TestExperimentCarryOntoKeepsNonDefaultStatus(t *testing.T) {
	payload := map[string]any{}
	experimentCarryOnto(payload, map[string]any{"status": "concluded"})
	if payload["status"] != "concluded" {
		t.Errorf("status = %#v, want concluded", payload["status"])
	}
}

// Never clobber what the caller deliberately set.
func TestExperimentCarryOntoDoesNotOverrideTheCaller(t *testing.T) {
	payload := map[string]any{"hypothesis": "the new one"}
	experimentCarryOnto(payload, map[string]any{"hypothesis": "the old one"})
	if payload["hypothesis"] != "the new one" {
		t.Errorf("carry overrode the caller: %#v", payload["hypothesis"])
	}
}

// An absent or empty field must not be written back as an empty value — that
// would turn "not declared" into "declared as nothing" in the spec.
func TestExperimentCarryOntoSkipsEmpties(t *testing.T) {
	payload := map[string]any{}
	experimentCarryOnto(payload, map[string]any{
		"dispatch": map[string]any{}, "cases": []string{},
		"description": "", "min_samples": 0, "baseline": nil,
	})
	for k := range payload {
		t.Errorf("empty %q was carried as %#v", k, payload[k])
	}
}
