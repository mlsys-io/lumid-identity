package handler

import "testing"

// The cycle's metrics blob is what a scorecard reads later, so it must report
// only what the tools actually said. An invented number is worse than a missing
// one — it looks like evidence.
func TestChatCycleMetrics(t *testing.T) {
	t.Run("reports only facts the tools returned", func(t *testing.T) {
		m := chatCycleMetrics([]toolCallResult{
			{Name: "casebook", OK: true, Result: map[string]any{"app": "mbb-consultant"}},
			{Name: "app_answer", OK: true, Result: map[string]any{
				"case_id": "Case_019_BetaOptics_PK21", "grounded": true, "mode": "casebook", "score": 0.41,
			}},
		})
		if m["case_id"] != "Case_019_BetaOptics_PK21" {
			t.Errorf("case_id = %v", m["case_id"])
		}
		if m["grounded"] != true || m["mode"] != "casebook" {
			t.Errorf("grounded/mode = %v / %v", m["grounded"], m["mode"])
		}
		if m["score"] != 0.41 {
			t.Errorf("score = %v", m["score"])
		}
		if m["tools"] != "casebook,app_answer" {
			t.Errorf("tools = %v", m["tools"])
		}
		if _, present := m["failed_tools"]; present {
			t.Errorf("no tool failed; failed_tools should be absent, got %v", m["failed_tools"])
		}
	})

	t.Run("absent facts stay absent", func(t *testing.T) {
		// An open-mode turn has no case and no ground truth. The keys must not
		// appear at all rather than appear as zero values, which a scorecard
		// would otherwise average in as a real score of 0.
		m := chatCycleMetrics([]toolCallResult{
			{Name: "app_answer", OK: true, Result: map[string]any{"mode": "open"}},
		})
		for _, k := range []string{"case_id", "grounded", "score"} {
			if _, present := m[k]; present {
				t.Errorf("%s should be absent for an open turn, got %v", k, m[k])
			}
		}
		if m["mode"] != "open" {
			t.Errorf("mode = %v", m["mode"])
		}
	})

	t.Run("a failed tool is counted, not hidden", func(t *testing.T) {
		m := chatCycleMetrics([]toolCallResult{
			{Name: "casebook", OK: false, Result: map[string]any{"error": "app not found"}},
		})
		if m["failed_tools"] != 1 {
			t.Errorf("failed_tools = %v", m["failed_tools"])
		}
	})

	t.Run("no tool calls still yields a valid blob", func(t *testing.T) {
		m := chatCycleMetrics(nil)
		if m["interactive"] != true {
			t.Errorf("interactive = %v", m["interactive"])
		}
		if _, present := m["tools"]; present {
			t.Errorf("tools should be absent when nothing ran")
		}
	})
}
