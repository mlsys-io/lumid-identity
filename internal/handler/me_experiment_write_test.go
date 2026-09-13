package handler

import (
	"strings"
	"testing"
)

func metric(n string) *experimentMetric { return &experimentMetric{Name: n} }

// The rule this whole feature exists to enforce:
//
//	workflow   = a loop. no metric, no scope. valid, and NOT an experiment.
//	experiment = a loop + a metric + a dataset/case scope.
//
// Both halves have failed in production. A missing metric is how
// quant-research's backtest_evidence reported n=0 across 19 real runs. A missing
// scope is what mbb-consultant's own spec records: "19 early results were measured
// over whatever cases happened to be asked, which no threshold can interpret."
func TestExperimentShapeRequiresMetricAndScope(t *testing.T) {
	ok := []struct {
		name string
		b    experimentWriteBody
	}{
		{"dataset scope", experimentWriteBody{
			ID: "judge_panel_parity", Loop: "case_eval",
			Metric: metric("avg_question_score"), DatasetID: "cases_v1"}},
		{"explicit case scope", experimentWriteBody{
			ID: "spot_check", Loop: "case_eval",
			Metric: metric("avg_question_score"), Cases: []string{"Case_002", "Case_019"}}},
		{"with arms", experimentWriteBody{
			ID: "panel", Loop: "case_eval", Metric: metric("avg_question_score"),
			DatasetID: "cases_v1",
			Arms:      []map[string]any{{"id": "panel_single"}, {"id": "panel_median3"}}}},
	}
	for _, tc := range ok {
		if p := validateExperimentShape(&tc.b); len(p) != 0 {
			t.Errorf("%s: valid experiment rejected: %v", tc.name, p)
		}
	}

	bad := []struct {
		name string
		b    experimentWriteBody
		want string
	}{
		{"no metric = a workflow, not an experiment",
			experimentWriteBody{ID: "x", Loop: "case_eval", DatasetID: "cases_v1"}, "metric.name"},
		{"empty metric name",
			experimentWriteBody{ID: "x", Loop: "case_eval", Metric: metric("  "), DatasetID: "cases_v1"}, "metric.name"},
		{"no scope at all",
			experimentWriteBody{ID: "x", Loop: "case_eval", Metric: metric("avg_question_score")}, "scope"},
		{"no loop to dispatch to",
			experimentWriteBody{ID: "x", Metric: metric("m"), DatasetID: "d"}, "loop"},
		{"no id",
			experimentWriteBody{Loop: "case_eval", Metric: metric("m"), DatasetID: "d"}, "id"},
		{"path traversal in id",
			experimentWriteBody{ID: "../etc", Loop: "l", Metric: metric("m"), DatasetID: "d"}, "id"},
		{"arm with no id",
			experimentWriteBody{ID: "x", Loop: "l", Metric: metric("m"), DatasetID: "d",
				Arms: []map[string]any{{"description": "nameless"}}}, "arms[0].id"},
	}
	for _, tc := range bad {
		p := validateExperimentShape(&tc.b)
		if len(p) == 0 {
			t.Errorf("%s: accepted but should have been rejected", tc.name)
			continue
		}
		found := false
		for _, s := range p {
			if strings.Contains(s, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: rejected, but no problem mentioned %q; got %v", tc.name, tc.want, p)
		}
	}
}

// Lumilake's scope strings must be mintable, and must stay opaque.
//
// Lumilake enforces the literal "lumilake:jobs:read"/"write". parseScope splits
// on the FIRST colon, so those read as level "jobs:read" -- not a valid level --
// and canGrant's `svc == ""` return sits above the admin bypass. Before they were
// added to capabilityScopes, NOBODY could mint them, super_admin included, and
// every credential in the estate got 403 from Lumilake at all three sites.
func TestLumilakeScopesAreGrantableCapabilityTags(t *testing.T) {
	for _, s := range []string{"lumilake:jobs:read", "lumilake:jobs:write"} {
		if !isCapabilityScope(s) {
			t.Errorf("%s must be a grantable capability tag", s)
		}
		// Opaque: it must confer NO platform access, exactly like lqt:strategy.
		if svc, lvl := parseScope(s); svc != "" || lvl != "" {
			t.Errorf("%s must stay invisible to parseScope, got svc=%q lvl=%q", s, svc, lvl)
		}
	}
	// Not a wildcard smuggled in: the bare service scope is still matrix-gated.
	if isCapabilityScope("lumilake:write") {
		t.Error("lumilake:write must remain a matrix-gated service scope, not a capability tag")
	}
}
