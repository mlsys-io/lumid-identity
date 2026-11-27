package handler

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseSpecForTest(t *testing.T, src string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

const chainSpecOK = `
name: quant
title: Quant
workflows:
  - id: backtest
    steps: {python: backtest}
    inputs: {symbol: BTCUSD}
  - id: forward_test
    steps: {python: forward}
  - id: report
    steps: {skills: [writer]}
  - id: strategy_pipeline
    title: Strategy pipeline
    run: manual
    steps:
      workflows:
        - backtest
        - use: forward_test
          inputs: {days: 7}
        - report
experiments:
  - id: pipe_exp
    workflow: strategy_pipeline
    question: does it hold up?
`

func TestSpecV2ChainTranslation(t *testing.T) {
	doc := normalizeSpecDoc(parseSpecForTest(t, chainSpecOK), "")
	// Round-trip through YAML, as every reader sees it.
	b, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	lp := loopNamed(got, "strategy_pipeline")
	if lp == nil {
		t.Fatal("strategy_pipeline loop missing")
	}
	if lp["schedule"] != "@trigger" {
		t.Fatalf("schedule = %v", lp["schedule"])
	}
	if _, has := lp["steps"]; has {
		t.Fatal("steps should not leak into the loop")
	}
	eng := asMap(lp["engine"])
	want := map[string]any{
		"type": "chain",
		"stages": []any{
			map[string]any{"loop": "backtest"},
			map[string]any{"loop": "forward_test", "inputs": map[string]any{"days": 7}},
			map[string]any{"loop": "report"},
		},
		"experiment": "pipe_exp",
	}
	if !reflect.DeepEqual(eng, want) {
		t.Fatalf("engine =\n%#v\nwant\n%#v", eng, want)
	}
	if lp["description"] != "Chain: backtest → forward_test → report" {
		t.Fatalf("description = %q", lp["description"])
	}
	// The plain workflows are untouched by the chain.
	if asMap(loopNamed(got, "backtest")["engine"])["type"] != "command" {
		t.Fatal("backtest engine changed")
	}
	if err := specV2ChainError(parseSpecForTest(t, chainSpecOK)); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	// The translated form validates too (readers that only see loops[]).
	if err := specV2ChainError(got); err != nil {
		t.Fatalf("translated chain rejected: %v", err)
	}
	// The workflows list reads it without choking (engine type, description).
	if err := specV2ChainErrorBytes(b); err != nil {
		t.Fatal(err)
	}
	var typed struct {
		Loops []rawLoop `yaml:"loops"`
	}
	if err := yaml.Unmarshal(b, &typed); err != nil {
		t.Fatalf("rawLoop decode: %v", err)
	}
	for _, l := range typed.Loops {
		if l.Name == "strategy_pipeline" && (l.Engine.Type != "chain" || len(l.Engine.Experiment) != 1) {
			t.Fatalf("rawLoop = %#v", l)
		}
	}
}

func TestSpecV2ChainAboutWins(t *testing.T) {
	doc := normalizeSpecDoc(parseSpecForTest(t, `
workflows:
  - id: a
    steps: {python: a}
  - id: p
    about: Runs a twice.
    steps: {workflows: [a, a]}
`), "")
	lp := loopNamed(doc, "p")
	if lp["description"] != "Runs a twice." {
		t.Fatalf("description = %q", lp["description"])
	}
	if n := len(asList(asMap(lp["engine"])["stages"])); n != 2 {
		t.Fatalf("stages = %d", n)
	}
}

func TestSpecV2ChainValidation(t *testing.T) {
	cases := []struct {
		name, spec, want string
	}{
		{"bare ids", `
workflows:
  - id: a
    steps: {python: a}
  - id: b
    steps: {dag: b.yaml}
  - id: p
    steps: {workflows: [a, b]}
`, ""},
		{"legacy loop as a stage", `
loops:
  - name: legacy
    schedule: "@trigger"
workflows:
  - id: p
    steps: {workflows: [legacy]}
`, ""},
		{"chain of chains", `
workflows:
  - id: a
    steps: {python: a}
  - id: inner
    steps: {workflows: [a]}
  - id: outer
    steps: {workflows: [inner, a]}
`, ""},
		{"unknown stage", `
workflows:
  - id: a
    steps: {python: a}
  - id: p
    steps:
      workflows: [a, {use: nope}]
`, `workflow "p": stage 2 (nope) is not a workflow in this app`},
		{"self reference", `
workflows:
  - id: a
    steps: {python: a}
  - id: p
    steps: {workflows: [a, p]}
`, `workflow "p": stage 2 runs the workflow itself`},
		{"cycle", `
workflows:
  - id: a
    steps: {python: a}
  - id: x
    steps: {workflows: [a, y]}
  - id: y
    steps: {workflows: [z]}
  - id: z
    steps: {workflows: [x]}
`, `workflow "x": its stages loop back to it (x → y → z → x)`},
		{"empty stage", `
workflows:
  - id: p
    steps:
      workflows: [{inputs: {days: 7}}]
`, `workflow "p": stage 1 names no workflow`},
		{"empty chain", `
workflows:
  - id: p
    steps: {workflows: []}
`, `workflow "p": steps.workflows lists no workflows to run`},
		{"mixed with python", `
workflows:
  - id: a
    steps: {python: a}
  - id: p
    steps: {python: a, workflows: [a]}
`, `cannot be combined with steps.python`},
		{"no chain at all", `
workflows:
  - id: a
    steps: {python: a}
`, ""},
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

func TestValidatePipelineShapeReportsChainError(t *testing.T) {
	ck := validatePipelineShapeBytes([]byte(`
workflows:
  - id: a
    steps: {python: a}
  - id: p
    steps: {workflows: [a, ghost]}
`), nil)
	if ck.Status != "fail" || len(ck.Issues) != 1 || !strings.Contains(ck.Issues[0], "ghost") {
		t.Fatalf("check = %#v", ck)
	}
}

// Both spec writers reject a broken chain BEFORE the write is queued or made,
// so the caller gets the message instead of a run that fails later.
func TestSpecWritersCheckChains(t *testing.T) {
	for _, c := range []struct{ file, fn string }{
		{"me_app_config.go", "MeUpdateAppConfig"},
		{"me_agent_tools_observability.go", "toolAppConfigSet"},
	} {
		block := funcBlock(t, c.file, c.fn)
		i, j := strings.Index(block, "specV2ChainError("), strings.Index(block, "ownerWriteTarget(")
		if i < 0 || j < 0 || i > j {
			t.Errorf("%s must call specV2ChainError before ownerWriteTarget", c.fn)
		}
	}
}
