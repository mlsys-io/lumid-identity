package handler

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// feedback[].gate → engine.gates {<step>: "<expr>"}, for a chain and a single
// workflow alike — the same shape LumidOS spec_v2.feedback_gates writes
// (tests/apps/test_gates.py::test_gates_translate_onto_the_engine_in_order).
const gatesSpec = `
name: lab
workflows:
  - id: check
    steps: {python: check}
  - id: measure
    steps: {python: measure}
  - id: confirm
    steps: {python: confirm}
  - id: screen
    steps: {workflows: [check, measure, confirm]}
    feedback:
      - {step: check, metrics: [{name: ok_flag, target: 1}], gate: "ok_flag >= 1"}
      - {step: measure, metrics: [{name: score}, {name: n}], gate: " score >= 0.5 and n >= 30 "}
      - {step: confirm, metrics: [{name: holdout}]}
  - id: single
    steps: {python: single}
    feedback:
      - {metrics: [{name: score}], gate: "score > 0"}
experiments:
  - id: search
    workflow: screen
    versions: [{id: v1}]
`

func TestSpecV2GatesTranslateOntoTheEngine(t *testing.T) {
	doc := normalizeSpecDoc(parseSpecForTest(t, gatesSpec), "")
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	eng := asMap(loopNamed(got, "screen")["engine"])
	if eng["type"] != "chain" || eng["experiment"] != "search" {
		t.Fatalf("engine = %#v", eng)
	}
	want := map[string]any{"check": "ok_flag >= 1", "measure": "score >= 0.5 and n >= 30"}
	if !reflect.DeepEqual(eng["gates"], want) {
		t.Fatalf("gates = %#v, want %#v", eng["gates"], want)
	}
	// A step-less entry gates the workflow itself.
	if g := asMap(asMap(loopNamed(got, "single")["engine"])["gates"]); !reflect.DeepEqual(g, map[string]any{"single": "score > 0"}) {
		t.Fatalf("single gates = %#v", g)
	}
	// No gate, no key.
	if _, has := asMap(loopNamed(got, "check")["engine"])["gates"]; has {
		t.Fatal("an ungated workflow must not carry engine.gates")
	}
	// The feedback list stays on the loop (the runner reads its order).
	if n := len(asList(loopNamed(got, "screen")["feedback"])); n != 3 {
		t.Fatalf("feedback entries = %d", n)
	}
}

func TestFeedbackGatesSkipsEmptyAndNonString(t *testing.T) {
	w := map[string]any{"id": "w", "feedback": []any{
		map[string]any{"step": "a", "gate": ""},
		map[string]any{"step": "b", "gate": 3},
		"junk",
		map[string]any{"step": "c", "gate": "x > 1"},
		map[string]any{"step": "c", "gate": "x > 2"}, // first wins
	}}
	if g := feedbackGates(w); !reflect.DeepEqual(g, map[string]any{"c": "x > 1"}) {
		t.Fatalf("gates = %#v", g)
	}
	if g := feedbackGates(map[string]any{"id": "w"}); len(g) != 0 {
		t.Fatalf("gates = %#v", g)
	}
}

func TestSpecV2GateValidation(t *testing.T) {
	cases := []struct {
		name, spec, want string
	}{
		{"gate ok", `
workflows:
  - id: a
    steps: {python: a}
    feedback: [{step: a, metrics: [{name: s}], gate: "s >= 1"}]
`, ""},
		{"no gate", `
workflows:
  - id: a
    steps: {python: a}
    feedback: [{step: a, metrics: [{name: s}]}]
`, ""},
		{"empty gate", `
workflows:
  - id: a
    steps: {python: a}
    feedback: [{step: a, metrics: [{name: s}], gate: "  "}]
`, `workflow "a": feedback step a: gate must be an expression`},
		{"number gate", `
workflows:
  - id: a
    steps: {python: a}
    feedback: [{metrics: [{name: s}], gate: 1}]
`, `workflow "a": feedback step #1: gate must be an expression`},
		{"null gate on a chain", `
workflows:
  - id: a
    steps: {python: a}
  - id: p
    steps: {workflows: [a]}
    feedback: [{step: a, gate: null}]
`, `workflow "p": feedback step a: gate must be an expression`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := specV2ChainError(parseSpecForTest(t, tc.spec))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
