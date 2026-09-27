package handler

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 2026-09-26: kol_alpha's spec moved real_tape -> realized_pnl_ticks and every
// install whose loop had not run since showed the new hypothesis beside
// "measures real tape" and a verdict about the old metric.
func TestStaleStateIsMarkedNotPresentedAsCurrent(t *testing.T) {
	d := &expDecl{ID: "kol_alpha", Metric: map[string]any{"name": "realized_pnl_ticks", "higher_is_better": true}}
	row := gin.H{"metric_name": "real_tape", "verdict": "no separable winner", "n_results": 6,
		"variants": map[string]any{"current": 1}, "criteria_met": true}
	markStaleState(row, d, map[string]any{"metric": "real_tape"})
	if row["metric_name"] != "realized_pnl_ticks" || row["state_stale"] != true || row["state_metric"] != "real_tape" {
		t.Fatalf("stale state not marked: %v", row)
	}
	for _, k := range []string{"verdict", "variants"} {
		if _, ok := row[k]; ok {
			t.Fatalf("%s from the old metric's state still presented: %v", k, row)
		}
	}
	if row["n_results"] != 0 || row["criteria_met"] != false || !strings.Contains(row["n_zero_reason"].(string), "real_tape") {
		t.Fatalf("counts/criteria from the old metric leaked: %v", row)
	}
}

func TestCurrentStateIsLeftAlone(t *testing.T) {
	d := &expDecl{ID: "x", Metric: map[string]any{"name": "real_tape"}}
	row := gin.H{"metric_name": "real_tape", "verdict": "v", "n_results": 3}
	markStaleState(row, d, map[string]any{"metric": "real_tape"})
	if _, ok := row["state_stale"]; ok || row["verdict"] != "v" || row["n_results"] != 3 {
		t.Fatalf("a current state was altered: %v", row)
	}
}

// strategy_cycles is a self_tenant read: it must go to the inspect ingress as
// the caller, never through the dataapp-proxy (404) with the operator's PAT.
func TestStrategyCyclesIsCallerScoped(t *testing.T) {
	if !lqtReadEndpoints["strategy_cycles"].callerScoped {
		t.Fatal("strategy_cycles must be callerScoped")
	}
	out, ok := toolLqtMailboxRead("user", "", "strategy_cycles", "abc", 5)
	if ok || !strings.Contains(out["error"].(string), "credential") {
		t.Fatalf("without a caller it must refuse, not fall back to the operator PAT: %v", out)
	}
}

func TestUnfedExperimentSaysWhy(t *testing.T) {
	d := &expDecl{ID: "analyst_model_arms", Metric: map[string]any{"name": "avg_question_score"}}
	row := gin.H{"n_results": 0}
	markUnfed(row, d, nil)
	if row["unfed"] != true || !strings.Contains(row["unfed_reason"].(string), "no loop feeds") {
		t.Fatalf("unfed experiment not explained: %v", row)
	}
	fed := gin.H{"n_results": 0}
	markUnfed(fed, d, []string{"case_cycle"})
	if _, ok := fed["unfed"]; ok {
		t.Fatalf("a fed experiment was marked unfed: %v", fed)
	}
	withRows := gin.H{"n_results": 4}
	markUnfed(withRows, d, nil)
	if _, ok := withRows["unfed"]; ok {
		t.Fatalf("an experiment with rows was marked unfed: %v", withRows)
	}
}
