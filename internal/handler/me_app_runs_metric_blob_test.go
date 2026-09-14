package handler

// metricFromBlob picks ONE number out of a run's metrics JSON, and that number
// becomes the run's score on the trajectory and the input to expStateFromRuns'
// criteria_met. Which number it picks was previously undefined when the key
// appeared more than once: the walk recursed depth-first and iterated a Go map
// to reach siblings, and Go randomises map iteration order.

import (
	"encoding/json"
	"testing"
)

// Two siblings carry the key at the same depth. The old walk returned whichever
// one Go's map iteration reached first, so the same stored run could report two
// different scores on two refreshes. Run it enough times that a random pick
// cannot survive by luck.
func TestMetricFromBlobIsDeterministicAcrossSiblings(t *testing.T) {
	blob := `{"a":{"score":1},"b":{"score":2},"c":{"score":3},"d":{"score":4},"e":{"score":5}}`
	first, path := metricFromBlobPath(blob, "score")
	if first == nil {
		t.Fatal("no value found")
	}
	for i := 0; i < 300; i++ {
		got, gotPath := metricFromBlobPath(blob, "score")
		if got == nil || *got != *first || gotPath != path {
			t.Fatalf("iteration %d returned %v at %q, first call returned %v at %q — "+
				"the pick is not deterministic", i, got, gotPath, *first, path)
		}
	}
	// Sorted-key tie-break, so the answer is also PREDICTABLE, not merely stable.
	if path != "a.score" || *first != 1 {
		t.Errorf("tie broken at %q = %v, want a.score = 1", path, *first)
	}
}

// A top-level metric is the run's own; one buried in some payload is somebody
// else's. Depth-first returned the buried one whenever it happened to be
// reached first.
func TestMetricFromBlobPrefersTheShallowest(t *testing.T) {
	blob := `{"nested":{"deeper":{"score":0.1}},"score":0.9}`
	got, path := metricFromBlobPath(blob, "score")
	if got == nil || *got != 0.9 {
		t.Fatalf("got %v at %q, want the top-level 0.9", got, path)
	}
	if path != "score" {
		t.Errorf("path = %q, want %q", path, "score")
	}
}

// Shallowest still means shallowest when the only hit is deep.
func TestMetricFromBlobFindsNestedWhenThatIsTheOnlyHit(t *testing.T) {
	blob := `{"outer":{"inner":{"exact_recall":0.994}},"other":1}`
	got, path := metricFromBlobPath(blob, "exact_recall")
	if got == nil || *got != 0.994 {
		t.Fatalf("got %v, want 0.994", got)
	}
	if path != "outer.inner.exact_recall" {
		t.Errorf("path = %q", path)
	}
}

// A key present but non-numeric must not shadow a numeric one deeper down, and
// must not be returned as a number either.
func TestMetricFromBlobSkipsNonNumeric(t *testing.T) {
	blob := `{"score":"n/a","inner":{"score":0.5}}`
	got, path := metricFromBlobPath(blob, "score")
	if got == nil || *got != 0.5 {
		t.Fatalf("got %v at %q, want the numeric 0.5 from inner", got, path)
	}
}

func TestMetricFromBlobArraysAndMisses(t *testing.T) {
	if v, _ := metricFromBlobPath(`{"rows":[{"x":1},{"score":7}]}`, "score"); v == nil || *v != 7 {
		t.Errorf("array descent failed: %v", v)
	}
	for _, c := range []struct{ blob, name string }{
		{`{"a":1}`, "missing"}, {"", "score"}, {`{"a":1}`, ""}, {"not json", "score"},
	} {
		if v, p := metricFromBlobPath(c.blob, c.name); v != nil || p != "" {
			t.Errorf("metricFromBlobPath(%q,%q) = %v,%q — want nil", c.blob, c.name, v, p)
		}
	}
}

// A blob that nests past the bound must terminate rather than walk forever.
func TestMetricFromBlobIsDepthBounded(t *testing.T) {
	doc := map[string]any{"score": 1.0}
	for i := 0; i < 40; i++ {
		doc = map[string]any{"d": doc}
	}
	b, _ := json.Marshal(doc)
	done := make(chan struct{})
	go func() { metricFromBlob(string(b), "score"); close(done) }()
	<-done // a hang here is the failure
}
