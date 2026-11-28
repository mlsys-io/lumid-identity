package handler

// The gate fields evaluate() writes (LumidOS #190) must reach the client: a
// passthrough that is easy to believe is present and was not.

import "testing"

func TestGateProgressReachesTheClient(t *testing.T) {
	dir := writeExpFixture(t, map[string]any{
		"experiment_id": "e1",
		"metric":        "real_tape_rate",
		"n_results":     3,
		"gate_progress": map[string]any{
			"v1": map[string]any{"reached": "robustness", "index": 3, "passed": false},
		},
		"best_failed_gate":   true,
		"best_stopped_at":    "robustness",
		"not_separable_from": []string{"v2"},
	})
	row := rowForE1(t, dir)
	gp, _ := row["gate_progress"].(map[string]any)
	if v1, _ := gp["v1"].(map[string]any); v1 == nil || v1["reached"] != "robustness" {
		t.Fatalf("gate_progress was dropped on the way out: %v", row["gate_progress"])
	}
	if row["best_failed_gate"] != true || row["best_stopped_at"] != "robustness" {
		t.Fatalf("best_failed_gate/best_stopped_at dropped: %v %v", row["best_failed_gate"], row["best_stopped_at"])
	}
	if arr, _ := row["not_separable_from"].([]any); len(arr) != 1 {
		t.Fatalf("not_separable_from dropped: %v", row["not_separable_from"])
	}
}
