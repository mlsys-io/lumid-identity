package handler

import (
	"encoding/json"
	"testing"
)

// The rollup must decode, not pattern-match. `metrics` is TEXT, so the SQL
// prefilter is a LIKE on "arm" — which also matches an unrelated key such as
// "warm_start" or a value containing the word. The Go decode is what makes the
// count true; without it the panel would over-report arm activity that never
// happened.
func TestArmRollupCountsOnlyRealArms(t *testing.T) {
	rows := []string{
		`{"arm":"panel_median3","experiment":"judge_panel_parity"}`,
		`{"arm":"panel_median3"}`,
		`{"warm_start":true}`, // LIKE matches, decode must reject
		`{"alarm":"fire"}`,    // LIKE matches, decode must reject
		`{"arm":""}`,          // present but empty — not an arm
		`not json at all`,     // must not panic or count
		`{"arm":"panel_single","experiment":"judge_panel_parity"}`,
	}
	armRuns := map[string]int{}
	expRuns := map[string]int{}
	for _, raw := range rows {
		var m map[string]any
		if raw == "" || json.Unmarshal([]byte(raw), &m) != nil {
			continue
		}
		arm, _ := m["arm"].(string)
		if arm == "" {
			continue
		}
		armRuns[arm]++
		if e, _ := m["experiment"].(string); e != "" {
			expRuns[e]++
		}
	}
	if len(armRuns) != 2 {
		t.Fatalf("distinct arms = %d (%v), want 2", len(armRuns), armRuns)
	}
	if armRuns["panel_median3"] != 2 {
		t.Errorf("panel_median3 = %d, want 2", armRuns["panel_median3"])
	}
	if armRuns["panel_single"] != 1 {
		t.Errorf("panel_single = %d, want 1", armRuns["panel_single"])
	}
	if _, bad := armRuns["fire"]; bad {
		t.Error("an `alarm` key was counted as an arm")
	}
	if expRuns["judge_panel_parity"] != 2 {
		t.Errorf("experiment count = %d, want 2 (the bare-arm row declares none)", expRuns["judge_panel_parity"])
	}
}
