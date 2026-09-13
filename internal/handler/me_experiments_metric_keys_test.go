package handler

// `n_results: 0` must not read the same for two different failures.
//
// An experiment that has never run and one whose declared metric matches
// nothing its rows emit produce the identical row over the API. quant-research
// shipped `real_tape_rate` against rows carrying only `real_tape` and reported
// n=0 for 19 real runs on three tenants; nobody could tell which n=0 it was.
//
// experiments.evaluate() now writes `metric_keys_seen` and `n_zero_reason` into
// state.json. Identity stores that blob verbatim, so the only thing needed here
// is to stop dropping the two keys on the way out -- which is exactly the sort
// of passthrough that is easy to believe is present and is not.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeExpFixture lays out a bundle with one declared experiment and a
// state.json holding the keys-seen diagnostic.
func writeExpFixture(t *testing.T, state map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	// readExpManifest reads the SPEC (.xpcloud.yaml), not the manifest mirror.
	spec := "experiments:\n" +
		"- id: e1\n" +
		"  metric: {name: real_tape_rate, higher_is_better: true}\n"
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	sd := filepath.Join(dir, ".lumid", "experiments", "e1")
	if err := os.MkdirAll(sd, 0o755); err != nil {
		t.Fatal(err)
	}
	sb, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(sd, "state.json"), sb, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func rowForE1(t *testing.T, dir string) map[string]any {
	t.Helper()
	rows := loadAppExperiments(dir)
	if len(rows) != 1 {
		t.Fatalf("expected 1 experiment row, got %d", len(rows))
	}
	return rows[0]
}

func TestKeysSeenReachesTheClient(t *testing.T) {
	dir := writeExpFixture(t, map[string]any{
		"experiment_id":    "e1",
		"metric":           "real_tape_rate",
		"n_results":        0,
		"metric_keys_seen": []string{"real_tape", "trades"},
		"n_zero_reason":    "19 row(s) present but none carries metric 'real_tape_rate'; keys emitted: real_tape, trades",
	})
	row := rowForE1(t, dir)

	ks, ok := row["metric_keys_seen"]
	if !ok {
		t.Fatal("metric_keys_seen was dropped on the way out; the client cannot offer real keys")
	}
	if arr, _ := ks.([]any); len(arr) != 2 {
		t.Fatalf("expected the two emitted keys, got %v", ks)
	}
	reason, _ := row["n_zero_reason"].(string)
	if reason == "" {
		t.Fatal("n_zero_reason was dropped; n=0 is ambiguous again")
	}
	if row["n_results"].(float64) != 0 && row["n_results"].(int) != 0 {
		t.Fatalf("n_results should still be 0: %v", row["n_results"])
	}
}

func TestNeverRunCarriesNoReason(t *testing.T) {
	// A never-run experiment must not claim a metric problem it cannot know
	// about -- the two n=0s stay distinguishable in BOTH directions.
	dir := writeExpFixture(t, map[string]any{
		"experiment_id": "e1", "metric": "real_tape_rate", "n_results": 0,
		"metric_keys_seen": []string{},
	})
	row := rowForE1(t, dir)
	if r, ok := row["n_zero_reason"]; ok && r != nil && r != "" {
		t.Fatalf("never-run must carry no reason, got %v", r)
	}
}

func TestHealthyExperimentStillPassesKeys(t *testing.T) {
	dir := writeExpFixture(t, map[string]any{
		"experiment_id": "e1", "metric": "real_tape_rate", "n_results": 5,
		"metric_keys_seen": []string{"real_tape_rate"},
	})
	row := rowForE1(t, dir)
	if _, ok := row["metric_keys_seen"]; !ok {
		t.Fatal("keys should be available even when the experiment is healthy — define-time reads them to offer choices")
	}
}
