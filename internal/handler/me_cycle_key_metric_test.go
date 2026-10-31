package handler

// LQ-20261030-02 — a measured run read `no metric`.
//
// Measured 2026-10-30 against production: run `20261030T143333Z` on
// quant-research/forward_test succeeded and stored
//
//	"primary_metric": {"name": "forward_submit_rate", "value": 1}
//
// in me_app_runs.metrics, and the trajectory endpoint scored it 1 — yet the
// Runs table said `no metric`, because the table's value came from the
// trajectory fetch alone and that fetch's failure was rendered identically to
// "this run was not measured".
//
// Two server-side facts made that possible and are pinned here:
//
//  1. cycleListItem carried no metric at all, so /me/cycles — the list the
//     table is drawn from — could not answer even though every row's metrics
//     blob contained the answer under `primary_metric`.
//  2. loopMetricName resolved a name only from experiments[].metric.name, so a
//     command loop declaring `metrics: {primary: …}` on the loop itself (the
//     custom-study shape, `qa_custom_analyze_20261030`) resolved NOTHING and
//     every one of its runs was scored false.

import (
	"encoding/json"
	"strings"
	"testing"

	"lumid_identity/models"
)

func TestPrimaryMetricFromBlobReadsTheRunnersOwnRecord(t *testing.T) {
	blob := map[string]any{"primary_metric": map[string]any{
		"name": "forward_submit_rate", "value": 1.0,
	}}
	got := primaryMetricFromBlob(blob)
	if got == nil {
		t.Fatal("primary_metric present but not lifted — the row cannot answer the Metric column")
	}
	if got.Name != "forward_submit_rate" || got.Value != 1 {
		t.Errorf("got %+v, want forward_submit_rate=1", *got)
	}
}

func TestPrimaryMetricFromBlobStaysAbsentWhenNothingWasMeasured(t *testing.T) {
	// The three older forward_test runs carry no primary_metric; they must keep
	// saying so rather than defaulting the column to 0.
	for name, blob := range map[string]map[string]any{
		"absent":        {"cost": map[string]any{"cost_usd": 0.1}},
		"null value":    {"primary_metric": map[string]any{"name": "x", "value": nil}},
		"string value":  {"primary_metric": map[string]any{"name": "x", "value": "1"}},
		"not an object": {"primary_metric": 1.0},
		"empty map":     {},
	} {
		if got := primaryMetricFromBlob(blob); got != nil {
			t.Errorf("%s: got %+v, want nil (an unmeasured run must not read as measured)", name, *got)
		}
	}
}

// The row the table is drawn from must carry the value, not merely the blob it
// could be derived from.
func TestCycleRowFromStoreCarriesTheDeclaredMetric(t *testing.T) {
	r := models.MeAppRun{
		App: "quant-research", Loop: "forward_test", RunTs: 1793370813, Ok: true,
		Metrics: `{"forward_submit_rate":1,"primary_metric":{"name":"forward_submit_rate","value":1}}`,
	}
	item, ok := cycleRowFromStore(r)
	if !ok {
		t.Fatal("row rejected")
	}
	if item.KeyMetric == nil {
		t.Fatal("key_metric dropped — /me/cycles still cannot answer the Metric column")
	}
	if item.KeyMetric.Name != "forward_submit_rate" || item.KeyMetric.Value != 1 {
		t.Errorf("key_metric = %+v, want forward_submit_rate=1", *item.KeyMetric)
	}
	// And it must survive JSON, under the name the UI already reads.
	b, err := json.Marshal(item)
	if err != nil || !strings.Contains(string(b), `"key_metric"`) ||
		!strings.Contains(string(b), `"name":"forward_submit_rate"`) ||
		!strings.Contains(string(b), `"value":1`) {
		t.Errorf("marshalled row = %s (err %v)", b, err)
	}
}

// The custom-study shape: the metric is declared on the LOOP, and no
// experiment carries one. Before this fix the name resolved to "" and
// metricFromBlob short-circuited on the empty name, so a run whose blob said
// `strategies_analyzed: 3` was scored false.
func TestLoopMetricNameUsesTheLoopsOwnDeclaration(t *testing.T) {
	spec := []byte(`
loops:
- name: qa_custom_analyze_20261030
  schedule: '@trigger'
  engine:
    type: command
    module: analyze
    args: ["", "200", "10"]
  metrics:
    primary: strategies_analyzed
`)
	m := parseExpManifestBytes(spec)
	if got := loopMetricNameFrom(m, "qa_custom_analyze_20261030"); got != "strategies_analyzed" {
		t.Fatalf("got %q, want strategies_analyzed — the loop declares it itself", got)
	}
	// The value is then found in the run's own blob, which is what turns
	// scored:false into scored:true.
	blob := `{"strategies_analyzed":3,"primary_metric":{"name":"strategies_analyzed","value":3}}`
	v := metricFromBlob(blob, loopMetricNameFrom(m, "qa_custom_analyze_20261030"))
	if v == nil || *v != 3 {
		t.Fatalf("metricFromBlob = %v, want 3", v)
	}
}

// A loop's own declaration must not change the answer for a loop that declares
// nothing itself: the experiment attachment still decides, in declaration order.
func TestLoopMetricNameStillFallsBackToTheAttachedExperiment(t *testing.T) {
	spec := []byte(`
loops:
- name: backtest
  engine:
    type: command
    experiment:
    - backtest_evidence
    - backtest_performance
experiments:
- id: backtest_evidence
  metric: {name: all_axes_real}
- id: backtest_performance
  metric: {name: realized_pnl_ticks_per_lot}
`)
	m := parseExpManifestBytes(spec)
	if got := loopMetricNameFrom(m, "backtest"); got != "all_axes_real" {
		t.Fatalf("got %q, want all_axes_real", got)
	}
}

// ...and a loop that declares its own metric is not overridden by an experiment
// it also feeds: the runner recorded the loop's own primary, so that is the key
// its output actually carries.
func TestLoopMetricNamePrefersTheLoopsOwnOverTheExperiment(t *testing.T) {
	spec := []byte(`
loops:
- name: forward_test
  engine:
    experiment: forward_evidence
  metrics:
    primary: forward_submit_rate
experiments:
- id: forward_evidence
  metric: {name: something_else}
`)
	m := parseExpManifestBytes(spec)
	if got := loopMetricNameFrom(m, "forward_test"); got != "forward_submit_rate" {
		t.Fatalf("got %q, want forward_submit_rate", got)
	}
}
