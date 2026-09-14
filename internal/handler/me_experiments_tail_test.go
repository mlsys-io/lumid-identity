package handler

// The ledger is served as a TAIL, and until now it never said so.
//
// expResultsTailCap was applied AFTER parsing the whole file and reported
// nowhere, so a long experiment served `n_results: 3000` — computed by
// evaluate() over every row — beside a 500-point series, two views of one
// experiment disagreeing by construction with nothing on screen to explain it.
// The per-case drill and the chat tool were clipped the same way.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLedger(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	expDir := filepath.Join(dir, ".lumid", "experiments", "e1")
	if err := os.MkdirAll(expDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		row, _ := json.Marshal(map[string]any{
			"ts":         fmt.Sprintf("2026-09-14T00:%02d:%02dZ", i/60, i%60),
			"variant_id": "arm_a",
			"metrics":    map[string]float64{"score": float64(i)},
		})
		b.Write(row)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(expDir, "results.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadExpRowsCountedReportsTheTrueTotal(t *testing.T) {
	dir := writeLedger(t, 1200)
	rows, total := readExpRowsCounted(dir, "e1", 500)
	if total != 1200 {
		t.Errorf("total = %d, want 1200 — the caller cannot say the view is a window", total)
	}
	if len(rows) != 500 {
		t.Fatalf("rows = %d, want the 500-row cap", len(rows))
	}
	// The TAIL, not the head: a window onto the oldest rows would be worse than
	// no window, because the series would look frozen.
	if rows[len(rows)-1].Metrics["score"] != 1199 {
		t.Errorf("last row score = %v, want 1199 (the newest row)", rows[len(rows)-1].Metrics["score"])
	}
	if rows[0].Metrics["score"] != 700 {
		t.Errorf("first row score = %v, want 700 (1200-500)", rows[0].Metrics["score"])
	}
}

func TestReadExpRowsCountedUnderTheCap(t *testing.T) {
	dir := writeLedger(t, 12)
	rows, total := readExpRowsCounted(dir, "e1", 500)
	if total != 12 || len(rows) != 12 {
		t.Errorf("rows=%d total=%d, want 12/12", len(rows), total)
	}
	if total > len(rows) {
		t.Error("a short ledger must not report itself truncated")
	}
}

func TestReadExpRowsCountedMissingLedger(t *testing.T) {
	rows, total := readExpRowsCounted(t.TempDir(), "nope", 500)
	if rows != nil || total != 0 {
		t.Errorf("rows=%v total=%d, want nil/0", rows, total)
	}
}

// Unparseable and arm-less lines are skipped, but they are still ROWS in the
// file — the total must count the file, not the survivors, or "why is my
// series short" has a second invisible cause.
func TestReadExpRowsCountedCountsEveryLine(t *testing.T) {
	dir := writeLedger(t, 5)
	p := filepath.Join(dir, ".lumid", "experiments", "e1", "results.jsonl")
	body, _ := os.ReadFile(p)
	body = append(body, []byte("{not json}\n{\"metrics\":{\"score\":1}}\n")...)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	rows, total := readExpRowsCounted(dir, "e1", 500)
	if total != 7 {
		t.Errorf("total = %d, want 7 (every non-blank line)", total)
	}
	if len(rows) != 5 {
		t.Errorf("rows = %d, want the 5 usable ones", len(rows))
	}
}
