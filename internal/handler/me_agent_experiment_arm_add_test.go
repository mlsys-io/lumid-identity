package handler

// An experiment with one arm reports a LEVEL; arms are what make it a
// comparison. define_experiment cannot add one and dispatch_experiment_arm can
// only run one that already exists, so until now a user could define a study
// from chat and never give it anything to compare against.
//
// FILENAME NOTE: this cannot be called *_arm_test.go. `arm` is a GOARCH, so Go
// treats a file ending in _arm.go as architecture-specific and silently skips it
// on amd64 — the package still reports ok, with none of these tests compiled.
//
// The dangerous part is the merge. patch_experiment REPLACES the whole
// experiments[] entry — deliberately, because splicing one key into an existing
// YAML block is how comments get eaten — so sending only the new arm would
// silently delete the baseline. These tests pin the merge, not the plumbing.

import (
	"encoding/json"
	"strings"
	"testing"
)

func armsFromDecl(decl map[string]any, newArm map[string]any, armID string) ([]map[string]any, bool) {
	// Mirror of the handler's merge, exercised through the same shapes
	// loadAppExperimentsFor actually returns ([]any of map[string]any).
	var arms []map[string]any
	replaced := false
	if raw, ok := decl["arms"].([]any); ok {
		for _, a0 := range raw {
			a, _ := a0.(map[string]any)
			if a == nil {
				continue
			}
			if id, _ := a["id"].(string); id == armID {
				arms = append(arms, newArm)
				replaced = true
				continue
			}
			arms = append(arms, a)
		}
	}
	if !replaced {
		arms = append(arms, newArm)
	}
	return arms, replaced
}

func TestAddingAnArmKeepsTheBaseline(t *testing.T) {
	decl := map[string]any{"id": "e1", "arms": []any{
		map[string]any{"id": "baseline", "judge_model": "deepseek-v4-flash"},
	}}
	arms, replaced := armsFromDecl(decl, map[string]any{"id": "variant"}, "variant")
	if replaced {
		t.Fatal("a new id must append, not replace")
	}
	if len(arms) != 2 {
		t.Fatalf("baseline was dropped: %v", arms)
	}
	if id, _ := arms[0]["id"].(string); id != "baseline" {
		t.Fatalf("baseline must survive and stay first: %v", arms)
	}
}

func TestSameArmIdIsAnEditNotADuplicate(t *testing.T) {
	// Two arms with one id would be averaged together by the aggregator.
	decl := map[string]any{"id": "e1", "arms": []any{
		map[string]any{"id": "baseline"},
		map[string]any{"id": "variant", "judge_model": "old"},
	}}
	arms, replaced := armsFromDecl(decl, map[string]any{"id": "variant", "judge_model": "new"}, "variant")
	if !replaced {
		t.Fatal("an existing id must replace")
	}
	if len(arms) != 2 {
		t.Fatalf("replace must not change the count: %v", arms)
	}
	if arms[1]["judge_model"] != "new" {
		t.Fatalf("the arm was not updated: %v", arms[1])
	}
}

func TestFirstArmOnAnExperimentWithNone(t *testing.T) {
	arms, replaced := armsFromDecl(map[string]any{"id": "e1"}, map[string]any{"id": "a"}, "a")
	if replaced || len(arms) != 1 {
		t.Fatalf("expected a single appended arm: %v", arms)
	}
}

// The tool must be reachable: registered, curated into Simple mode, and heard
// by the control-intent router. A tool the router cannot hear falls through to
// claude-code, which cannot see the registry — the same miss that made
// define_experiment useless before its pattern was added.
func TestAddArmIsRegisteredAndRoutable(t *testing.T) {
	defs := buildToolDefsForRole("super_admin")
	found := false
	for _, d := range defs {
		if n, _ := d["name"].(string); n == "add_experiment_arm" {
			found = true
			schema, _ := d["input_schema"].(map[string]any)
			req, _ := schema["required"].([]string)
			if strings.Join(req, ",") != "app,experiment,arm" {
				t.Fatalf("required fields drifted: %v", req)
			}
		}
	}
	if !found {
		t.Fatal("add_experiment_arm is not in the tool defs")
	}
	if !simpleModeTools["add_experiment_arm"] {
		t.Fatal("not curated into Simple mode, where most users are")
	}
	hit := false
	for _, re := range controlIntentPatterns {
		if re.MatchString("please use add_experiment_arm on mbb-consultant") {
			hit = true
		}
	}
	if !hit {
		t.Fatal("the control-intent router cannot hear add_experiment_arm; " +
			"it would fall through to claude-code, which cannot see the registry")
	}
}

func TestConfigMustBeAJsonObject(t *testing.T) {
	var extra map[string]any
	if json.Unmarshal([]byte(`{"prompt_variant":"cards_v2"}`), &extra) != nil {
		t.Fatal("a valid object must parse")
	}
	if json.Unmarshal([]byte(`not json`), &extra) == nil {
		t.Fatal("malformed config must fail at the door, not land in the spec")
	}
}
