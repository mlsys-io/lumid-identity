package handler

import (
	"strings"
	"testing"
)

// Four stat widgets in one section rendered as four block-level fences, so the
// live Strategies page showed four stacked lines of number-over-label and
// pushed the registry below the fold. A stat is a small fixed-width badge; a
// run of them belongs on one line.
func TestConsecutiveStatsShareARow(t *testing.T) {
	spec := []byte(`
title: Strategies
sections:
- heading: Overview
  widgets:
  - { type: stat, source: "x://a", path: p1, label: Registered }
  - { type: stat, source: "x://a", path: p2, label: Awaiting the field }
  - { type: stat, source: "x://a", path: p3, label: Results harvested }
  - { type: stat, source: "x://a", path: p4, label: Telemetry rows }
`)
	md, err := compilePageSpec(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if n := strings.Count(md, "```lumid:columns"); n != 1 {
		t.Fatalf("lumid:columns blocks = %d, want 1\n%s", n, md)
	}
	if n := strings.Count(md, "```lumid:stat"); n != 0 {
		t.Fatalf("%d stats still emitted as their own fence; they should be grouped\n%s", n, md)
	}
	if !strings.Contains(md, "columns: 4") {
		t.Fatalf("want a 4-column row for 4 stats\n%s", md)
	}
	for _, label := range []string{"Registered", "Awaiting the field", "Results harvested", "Telemetry rows"} {
		if !strings.Contains(md, label) {
			t.Fatalf("label %q lost in grouping\n%s", label, md)
		}
	}
}

// Grouping must not swallow neighbours: only stats group, and only the
// consecutive run — a table between two stats keeps its own full-width fence.
func TestOnlyConsecutiveStatsGroup(t *testing.T) {
	spec := []byte(`
title: Mixed
sections:
- heading: S
  widgets:
  - { type: stat,  source: "x://a", path: p1, label: One }
  - { type: stat,  source: "x://a", path: p2, label: Two }
  - { type: table, source: "x://a", path: rows }
  - { type: stat,  source: "x://a", path: p3, label: Alone }
`)
	md, err := compilePageSpec(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if n := strings.Count(md, "```lumid:columns"); n != 1 {
		t.Fatalf("columns blocks = %d, want exactly 1 (the leading pair)\n%s", n, md)
	}
	if !strings.Contains(md, "columns: 2") {
		t.Fatalf("the run of two should ask for 2 columns\n%s", md)
	}
	if n := strings.Count(md, "```lumid:table"); n != 1 {
		t.Fatalf("table fences = %d, want 1 — the table must not be absorbed\n%s", n, md)
	}
	// The trailing single stat stays its own fence: a one-cell grid is noise.
	if n := strings.Count(md, "```lumid:stat"); n != 1 {
		t.Fatalf("standalone stat fences = %d, want 1\n%s", n, md)
	}
}

// An author who wrote `columns:` meant it — that path is untouched.
func TestExplicitColumnsStillWins(t *testing.T) {
	spec := []byte(`
title: Explicit
sections:
- heading: S
  columns: 2
  widgets:
  - { type: stat, source: "x://a", path: p1, label: One }
  - { type: stat, source: "x://a", path: p2, label: Two }
  - { type: stat, source: "x://a", path: p3, label: Three }
`)
	md, err := compilePageSpec(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(md, "columns: 2") {
		t.Fatalf("author asked for 2 columns; auto-grouping must not override\n%s", md)
	}
}

// More stats than the renderer can grid: clamp the request, keep every widget.
func TestLongStatRunClampsToFourButKeepsAll(t *testing.T) {
	spec := []byte(`
title: Many
sections:
- heading: S
  widgets:
  - { type: stat, source: "x://a", path: p1, label: A }
  - { type: stat, source: "x://a", path: p2, label: B }
  - { type: stat, source: "x://a", path: p3, label: C }
  - { type: stat, source: "x://a", path: p4, label: D }
  - { type: stat, source: "x://a", path: p5, label: E }
  - { type: stat, source: "x://a", path: p6, label: F }
`)
	md, err := compilePageSpec(spec)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !strings.Contains(md, "columns: 4") {
		t.Fatalf("want the request clamped to 4\n%s", md)
	}
	for _, label := range []string{"A", "B", "C", "D", "E", "F"} {
		if !strings.Contains(md, "label: "+label) {
			t.Fatalf("stat %q dropped by clamping\n%s", label, md)
		}
	}
}
