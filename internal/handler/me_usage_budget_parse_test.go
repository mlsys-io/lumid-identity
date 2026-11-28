package handler

import "testing"

// A workflow's legacy scalar `compute: lumilake` must not hide the app budget
// (mbb-consultant 0.10.4, 2026-11-28: the $40 budget read as empty, checks failed open).
func TestParseSpecBudgetsSurvivesALegacyComputeScalar(t *testing.T) {
	spec := []byte(`
compute: {budget: {usd: 40, per: total, parallel: 2}}
workflows:
  - id: case_eval
    compute: lumilake
  - id: screen
    compute: {budget: {gpu_minutes: 10}}
  - id: odd
    compute: [a, b]
`)
	b := parseSpecBudgets(spec)
	if b.App.USD != 40 || b.App.Per != "total" || b.App.Parallel != 2 {
		t.Fatalf("app budget lost: %+v", b.App)
	}
	if b.Workflows["screen"].GPUMinutes != 10 {
		t.Fatalf("workflow budget lost: %+v", b.Workflows)
	}
	if _, ok := b.Workflows["case_eval"]; ok {
		t.Fatal("a scalar compute must not become a budget")
	}
}

func TestParseSpecBudgetsAppComputeScalarIsUnreadable(t *testing.T) {
	b := parseSpecBudgets([]byte("compute: lumilake\nworkflows: [{id: a}]\n"))
	if !b.App.empty() || len(b.Unreadable) != 1 {
		t.Fatalf("got %+v", b)
	}
	if got := parseSpecBudgets([]byte("workflows: [{id: a}]\n")); len(got.Unreadable) != 0 {
		t.Fatalf("absent compute is not unreadable: %+v", got)
	}
}
