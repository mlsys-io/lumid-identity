package handler

import (
	"strings"
	"testing"

	"lumid_identity/models"
)

func TestStarvedReason(t *testing.T) {
	fail := models.MeAppRun{Loop: "regression_sweep", Ok: false,
		Metrics: `{"command_engine":{"error":"no inbox cases match. Run seed_inbox first.","ok":false}}`}
	ok := models.MeAppRun{Loop: "regression_sweep", Ok: true, Metrics: `{}`}

	if s, r := starvedReason(nil, []string{"case_cycle"}); !s || !strings.Contains(r, "no run of case_cycle") {
		t.Fatalf("never ran: %v %q", s, r)
	}
	s, r := starvedReason([]models.MeAppRun{fail, fail, fail}, []string{"regression_sweep"})
	if !s || !strings.Contains(r, "regression_sweep failed its last 3 run(s)") || !strings.Contains(r, "seed_inbox") {
		t.Fatalf("all failed: %v %q", s, r)
	}
	if s, _ := starvedReason([]models.MeAppRun{fail, ok}, []string{"regression_sweep"}); s {
		t.Fatal("a successful run means the zero is not the loop's fault")
	}
	top := models.MeAppRun{Loop: "l", Ok: false, Metrics: `{"error":"boom"}`}
	if _, r := starvedReason([]models.MeAppRun{top}, []string{"l"}); !strings.HasSuffix(r, ": boom") {
		t.Fatalf("top-level error: %q", r)
	}
	flagged := models.MeAppRun{Loop: "benchmark", Ok: false,
		Metrics: `{"command_engine":{"flags":["bench_failed: docker build failed"],"ok":false}}`}
	if _, r := starvedReason([]models.MeAppRun{flagged}, []string{"benchmark"}); !strings.HasSuffix(r, ": bench_failed: docker build failed") {
		t.Fatalf("flags as the reason: %q", r)
	}
	long := models.MeAppRun{Loop: "l", Ok: false, Metrics: `{"error":"` + strings.Repeat("x", 500) + `"}`}
	if _, r := starvedReason([]models.MeAppRun{long}, []string{"l"}); len(r) > 260 {
		t.Fatalf("error text not capped: %d", len(r))
	}
}

func TestMarkStarvedSkipsRowsWithResults(t *testing.T) {
	row := map[string]any{"n_results": 3}
	markStarved(row, "sub", "app", []string{"l"})
	if _, has := row["starved"]; has {
		t.Fatal("an experiment with results is not starved")
	}
}
