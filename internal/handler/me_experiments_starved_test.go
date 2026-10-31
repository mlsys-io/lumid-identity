package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

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
	markStarved(row, "sub", "app", "m", []string{"l"})
	if _, has := row["starved"]; has {
		t.Fatal("an experiment with results is not starved")
	}
}

// Every marker's "this one has results, say nothing" guard read n_results as
// an int. The state blob is json.Unmarshal'ed into map[string]any, where the
// number is a float64 — so the guard never fired on the shape production
// actually sends, and a study with hundreds of rows and no feeding loop was
// labelled unfed.
func TestZeroMarkersReadNResultsFromTheStateShape(t *testing.T) {
	for name, n := range map[string]any{
		"float64 (disk/self-report shape)": float64(350),
		"int (expStateFromRuns shape)":     int(350),
		"json.Number":                      json.Number("350"),
		"absent":                           nil,
	} {
		want := 0
		if n != nil {
			want = 350
		}
		row := gin.H{"n_results": n}
		if got := rowNResults(row); got != want {
			t.Errorf("%s: rowNResults = %d, want %d", name, got, want)
		}
	}

	row := gin.H{"n_results": float64(350)}
	markUnfed(row, &expDecl{}, nil)
	if _, has := row["unfed"]; has {
		t.Error("350 rows read as unfed — the guard is still dead for the real shape")
	}
	markUndispatched(row, &expDecl{Dispatch: map[string]any{"ask": "q"}}, nil)
	if _, has := row["starved"]; has {
		t.Error("350 rows read as undispatched")
	}
	markStarved(row, "sub", "app", "m", []string{"l"})
	if _, has := row["starved"]; has {
		t.Error("350 rows read as starved")
	}
}

func TestMarkUndispatched(t *testing.T) {
	d := &expDecl{Dispatch: map[string]any{"ask": "Which model should the analyst use?"}}
	row := map[string]any{"n_results": 0}
	markUndispatched(row, d, nil)
	if row["starved"] != true || !strings.Contains(row["starved_reason"].(string), "only when dispatched") ||
		!strings.Contains(row["starved_reason"].(string), "Which model") {
		t.Fatalf("dispatch-only: %v", row)
	}
	for _, c := range []struct {
		name    string
		d       *expDecl
		row     map[string]any
		feeding []string
	}{
		{"has results", d, map[string]any{"n_results": 4}, nil},
		{"fed by a loop", d, map[string]any{"n_results": 0}, []string{"case_eval"}},
		{"dispatch.loop", &expDecl{Dispatch: map[string]any{"loop": "backtest"}}, map[string]any{"n_results": 0}, nil},
		{"no dispatch", &expDecl{}, map[string]any{"n_results": 0}, nil},
	} {
		markUndispatched(c.row, c.d, c.feeding)
		if _, has := c.row["starved"]; has {
			t.Fatalf("%s: should not be marked", c.name)
		}
	}
}
