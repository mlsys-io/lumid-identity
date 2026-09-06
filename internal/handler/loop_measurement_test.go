package handler

import "testing"

// The metric/dataset resolver has to survive BOTH shapes of
// `engine.experiment`, because real apps use both — quant-research's
// `backtest` attaches a list and `kol_strategy` attaches a bare scalar, in the
// same file.
//
// This is pinned because the scalar case has now broken something nine times.
// The first version of this reader used flexStrings, which decodes into []any
// and RETURNS THE ERROR on a scalar. yaml.Unmarshal then failed the whole
// document, so one scalar attachment blanked the metric for all ten loops in
// the app — and the failure was silent: rows rendered, just with no metric,
// which reads as "this loop isn't an experiment" rather than "the parser died".
// It shipped twice before a live check caught it.
func TestReadYamlLoopMeasurement_ScalarAndListExperiments(t *testing.T) {
	spec := []byte(`
loops:
  - name: backtest
    metrics:
      primary: real_tape_rate
    engine:
      experiment:
        - backtest_evidence
        - backtest_performance
  - name: kol_strategy
    metrics:
      primary: real_tape
    engine:
      experiment: kol_alpha
  - name: interview
    dataset_id: cases_v1
  - name: harvest_outbox
    schedule: "*/15 * * * *"
experiments:
  - id: backtest_evidence
    dataset_id: tape_covered_v1
    metric:
      name: real_tape_rate
  - id: backtest_performance
    dataset_id: tape_covered_v1
  - id: kol_alpha
    dataset_id: musk_tweets_v1
    metric:
      name: real_tape
`)
	m := readYamlLoopMeasurementBytes(spec)
	if len(m) == 0 {
		t.Fatal("empty map: one malformed/scalar field must not blank every loop")
	}
	// list form
	if got := m["backtest"]; got.Metric != "real_tape_rate" || got.DatasetID != "tape_covered_v1" {
		t.Errorf("backtest (list experiment) = %+v, want real_tape_rate/tape_covered_v1", got)
	}
	// scalar form — the shape that used to fail the whole document
	if got := m["kol_strategy"]; got.Metric != "real_tape" || got.DatasetID != "musk_tweets_v1" {
		t.Errorf("kol_strategy (scalar experiment) = %+v, want real_tape/musk_tweets_v1", got)
	}
	// a loop naming its own dataset and no experiment still resolves
	if got := m["interview"]; got.DatasetID != "cases_v1" {
		t.Errorf("interview (own dataset_id) = %+v, want cases_v1", got)
	}
	// a plain scheduled loop declares neither and must not appear: absent means
	// "not an experiment", which is what the workflows table renders.
	if _, ok := m["harvest_outbox"]; ok {
		t.Errorf("harvest_outbox should carry no measurement, got %+v", m["harvest_outbox"])
	}
}
