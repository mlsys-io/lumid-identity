package handler

import (
	"strings"
	"testing"
)

// feedback[].holdout: true -> engine.holdout_step; one step only, and the last
// (twin of LumidOS tests/apps/test_spec_holdout.py).
const holdoutSpec = `
name: lab
workflows:
  - id: backtest
    steps: {python: bt}
  - id: robustness
    steps: {python: rb}
  - id: screen
    steps: {workflows: [backtest, robustness]}
    feedback:
      - {step: backtest, metrics: [{name: sharpe}], gate: "sharpe >= 0.5"}
      - {step: robustness, metrics: [{name: oos_sharpe}], holdout: true}
`

func TestSpecV2HoldoutStepRidesOnTheEngine(t *testing.T) {
	doc := normalizeSpecDoc(parseSpecForTest(t, holdoutSpec), "")
	eng := asMap(loopNamed(doc, "screen")["engine"])
	if eng["holdout_step"] != "robustness" {
		t.Fatalf("engine = %#v", eng)
	}
	if err := specV2ChainError(parseSpecForTest(t, holdoutSpec)); err != nil {
		t.Fatalf("valid spec refused: %v", err)
	}
}

func TestSpecV2HoldoutMustBeOneAndLast(t *testing.T) {
	two := strings.Replace(holdoutSpec, `gate: "sharpe >= 0.5"}`, `gate: "sharpe >= 0.5", holdout: true}`, 1)
	err := specV2ChainError(parseSpecForTest(t, two))
	if err == nil || !strings.Contains(err.Error(), "only one step may read held-out data") {
		t.Fatalf("two holdout steps: %v", err)
	}
	if h := asMap(loopNamed(normalizeSpecDoc(parseSpecForTest(t, two), ""), "screen")["engine"])["holdout_step"]; h != nil {
		t.Fatalf("a refused marking must not be translated: %v", h)
	}
	first := strings.Replace(strings.Replace(two, ", holdout: true}\n", "}\n", 1), `holdout: true}`, `holdout: false}`, 1)
	first = strings.Replace(first, `gate: "sharpe >= 0.5"}`, `gate: "sharpe >= 0.5", holdout: true}`, 1)
	err = specV2ChainError(parseSpecForTest(t, first))
	if err == nil || !strings.Contains(err.Error(), "not the last step") {
		t.Fatalf("non-final holdout step: %v", err)
	}
}
