package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

func obs(cli, sdk, node string, n int) models.ClaudeFingerprintObservation {
	return models.ClaudeFingerprintObservation{CLI: cli, SDK: sdk, Node: node, Count: n}
}

// THE property this whole design exists for: two callers must get byte-identical
// pools. Go randomises map iteration order per range, so an aggregation that
// sorts only by count would return equal-count triples in a different order to
// each caller — and the proxy hash-selects by position, so a reordered pool
// means two replicas present DIFFERENT identities for the same box.
//
// Repeated many times because a missing tiebreak fails probabilistically, not
// deterministically: a single comparison would pass by luck most runs.
func TestFingerprintPool_IsDeterministicAcrossCallers(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{
		obs("2.1.228", "0.112.1", "v26.3.0", 40),
		obs("2.1.227", "0.94.0", "v26.3.0", 40), // deliberate exact tie
		obs("2.1.226", "0.94.0", "v26.3.0", 40), // three-way tie
	}
	first, _, _ := computeFingerprintPool(rows, 10, 0.1)
	for i := 0; i < 200; i++ {
		got, _, _ := computeFingerprintPool(rows, 10, 0.1)
		if len(got) != len(first) {
			t.Fatalf("iteration %d: length changed %d -> %d", i, len(first), len(got))
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("iteration %d position %d: pool order is NOT deterministic (%+v vs %+v) — two replicas would present different identities",
					i, j, got[j], first[j])
			}
		}
	}
}

// Thin evidence must produce NO opinion, not a confident wrong one. Adopting
// off a handful of requests would let a single unusual client redefine what
// every field box presents.
func TestFingerprintPool_DeclinesOnThinEvidence(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{obs("9.9.9", "9.9.9", "v9.9.9", 3)}
	pool, total, reason := computeFingerprintPool(rows, 50, 0.15)
	if len(pool) != 0 {
		t.Errorf("adopted a pool from %d samples: %+v", total, pool)
	}
	if reason != "insufficient_samples" {
		t.Errorf("reason = %q, want insufficient_samples", reason)
	}
}

// The min-share floor keeps a long-tail client out of the fleet identity,
// while still admitting a genuine second release.
func TestFingerprintPool_FiltersLongTailButKeepsRealSecondLine(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{
		obs("2.1.228", "0.112.1", "v26.3.0", 70),
		obs("2.1.227", "0.94.0", "v26.3.0", 29),
		obs("0.0.1", "0.0.1", "v0.0.1", 1), // 1% — noise
	}
	pool, _, _ := computeFingerprintPool(rows, 50, 0.15)
	if len(pool) != 2 {
		t.Fatalf("want 2 rows (dominant + real second line), got %d: %+v", len(pool), pool)
	}
	if pool[0].CLI != "2.1.228" {
		t.Errorf("leader = %q, want the most-observed triple", pool[0].CLI)
	}
	for _, r := range pool {
		if r.CLI == "0.0.1" {
			t.Error("long-tail noise entered the pool")
		}
	}
}

// A single dominant release must collapse the pool to one row — that is what
// makes every box present the same current identity.
func TestFingerprintPool_CollapsesWhenOneReleaseDominates(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{
		obs("2.1.228", "0.112.1", "v26.3.0", 95),
		obs("2.1.220", "0.94.0", "v26.3.0", 5),
	}
	pool, _, _ := computeFingerprintPool(rows, 50, 0.15)
	if len(pool) != 1 || pool[0].SDK != "0.112.1" {
		t.Fatalf("want a single row on the dominant line, got %+v", pool)
	}
}

// Components must never be recombined across observations. Counting them
// independently would let a 2.1.228 CLI and a 0.94.0 SDK — seen on different
// machines — be presented together as one client that does not exist.
func TestFingerprintPool_NeverSynthesisesAnUnobservedTriple(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{
		obs("2.1.228", "0.112.1", "v26.3.0", 60),
		obs("2.1.220", "0.94.0", "v26.3.0", 40),
	}
	observed := map[string]bool{"2.1.228|0.112.1|v26.3.0": true, "2.1.220|0.94.0|v26.3.0": true}
	pool, _, _ := computeFingerprintPool(rows, 50, 0.15)
	for _, r := range pool {
		if !observed[r.CLI+"|"+r.SDK+"|"+r.Node] {
			t.Errorf("synthesised an unobserved triple: %s + %s + %s", r.CLI, r.SDK, r.Node)
		}
	}
}

// Partial rows must not dilute shares — a row missing a component cannot be
// presented, so counting it in the denominator would understate every usable
// triple and could push the real leader below the floor.
func TestFingerprintPool_IgnoresPartialRows(t *testing.T) {
	rows := []models.ClaudeFingerprintObservation{
		obs("2.1.228", "0.112.1", "v26.3.0", 60),
		obs("2.1.999", "", "v26.3.0", 500), // no SDK — unusable
		obs("", "0.94.0", "v26.3.0", 500),  // no CLI — unusable
	}
	pool, total, _ := computeFingerprintPool(rows, 50, 0.15)
	if total != 60 {
		t.Errorf("total = %d, want 60 — partial rows must not count toward the denominator", total)
	}
	if len(pool) != 1 || pool[0].CLI != "2.1.228" {
		t.Fatalf("want only the usable triple, got %+v", pool)
	}
}

// The pool is capped so one bad window cannot hand the fleet an unbounded set
// of identities.
func TestFingerprintPool_CapsRowCount(t *testing.T) {
	var rows []models.ClaudeFingerprintObservation
	for i := 0; i < 10; i++ {
		rows = append(rows, obs("2.1.2"+string(rune('0'+i)), "0.112.1", "v26.3.0", 10))
	}
	pool, _, _ := computeFingerprintPool(rows, 10, 0.01)
	if len(pool) > fingerprintMaxRows {
		t.Errorf("pool has %d rows, cap is %d", len(pool), fingerprintMaxRows)
	}
}

// The cross-replica guarantee rests on bucket arithmetic: every process must
// derive the SAME window index from the same wall clock, and it must not
// advance mid-window. Both replicas polling at different moments inside one
// window must therefore be answered from the same closed data set.
func TestFingerprintWindow_IndexIsStableWithinAWindowAndAdvancesAcrossIt(t *testing.T) {
	win := 24 * time.Hour
	secs := int64(win.Seconds())
	base := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)

	idxAt := func(ts time.Time) int64 { return ts.UTC().Unix() / secs }

	start := idxAt(base)
	for _, offset := range []time.Duration{0, time.Second, time.Hour, 12 * time.Hour, win - time.Second} {
		if got := idxAt(base.Add(offset)); got != start {
			t.Fatalf("window index moved within the window at +%v (%d -> %d) — two replicas polling seconds apart could get different pools",
				offset, start, got)
		}
	}
	if got := idxAt(base.Add(win)); got != start+1 {
		t.Errorf("window index did not advance at the boundary: %d -> %d", start, got)
	}
}

// The derived fingerprint must be clearly marked as a GUESS. identity's copy
// of the proxy's pool is only right while the two stay byte-identical, and it
// silently diverged for a day (rendering `Anthropic/JS <sdk>` while the proxy
// sent `claude-cli/<ver> (external, cli)`). Nothing detected it because each
// side was self-consistent, so the flag is what lets a consumer tell an
// observation from a re-derivation instead of trusting both equally.
func TestDerivedFingerprintIsFlaggedAsNotReported(t *testing.T) {
	info := fingerprintInfoForLabel("denmark", time.Now())
	if info.Reported {
		t.Error("locally derived fingerprint claims to be reported — a consumer cannot then tell a guess from an observation")
	}
	if info.ReportedAt != nil {
		t.Error("derived fingerprint carries a ReportedAt timestamp")
	}
}
