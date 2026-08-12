package common

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// The pool quota counts COST, not raw tokens: Opus is 5x Sonnet and ~19x Haiku.
// The weight exists in TWO implementations — ClaudeModelWeight (Go, for the
// in-flight increment) and ClaudeModelWeightSQL (for the stored history the
// increment is added to). If they drift apart, a user's counted usage changes
// depending on which side of the request boundary it is measured from, and the
// admin table stops agreeing with the gate. These tests pin both.

func TestClaudeModelWeight(t *testing.T) {
	cases := []struct {
		model string
		want  float64
	}{
		{"claude-opus-5", claudeWeightOpus},
		{"claude-opus-4-8", claudeWeightOpus},
		{"claude-sonnet-5", claudeWeightSonnet},
		{"claude-haiku-4-5-20251001", claudeWeightHaiku},
		// Case-insensitive: the proxy lowercases, but usage_events stores what
		// the client sent, and a capital-C "Claude-Opus-5" must not fall through
		// to the cheap default and undercharge the most expensive model.
		{"Claude-Opus-5", claudeWeightOpus},
		{"CLAUDE-SONNET-5", claudeWeightSonnet},
		// Unknown / empty bill at the conservative default rather than free.
		{"", claudeWeightDefault},
		{"kimi-k3", claudeWeightDefault},
		{"some-future-model", claudeWeightDefault},
	}
	for _, c := range cases {
		if got := ClaudeModelWeight(c.model); got != c.want {
			t.Errorf("ClaudeModelWeight(%q) = %v, want %v", c.model, got, c.want)
		}
	}
}

// Opus must stay the normalisation point. The operator-set caps were measured
// against an Opus-dominated workload, so if Opus ever stopped being 1.0 every
// configured cap would silently change meaning.
func TestOpusIsTheNormalisationPoint(t *testing.T) {
	if ClaudeModelWeight("claude-opus-5") != 1.0 {
		t.Fatalf("Opus weight must be exactly 1.0, got %v", ClaudeModelWeight("claude-opus-5"))
	}
	if w := ClaudeModelWeight("claude-sonnet-5"); w >= 1.0 {
		t.Fatalf("Sonnet must be cheaper than Opus, got %v", w)
	}
	if ClaudeModelWeight("claude-haiku-4-5") >= ClaudeModelWeight("claude-sonnet-5") {
		t.Fatal("Haiku must be cheaper than Sonnet")
	}
}

// The SQL twin must embed the same constants and match on the same prefixes.
func TestClaudeModelWeightSQLMatchesGo(t *testing.T) {
	sql := ClaudeModelWeightSQL("model")

	for _, want := range []float64{claudeWeightOpus, claudeWeightSonnet, claudeWeightHaiku, claudeWeightDefault} {
		if !strings.Contains(sql, fmt.Sprintf("%v", want)) {
			t.Errorf("SQL expression is missing weight %v — Go and SQL have drifted:\n%s", want, sql)
		}
	}
	for _, prefix := range []string{"claude-opus", "claude-sonnet", "claude-haiku"} {
		if !strings.Contains(sql, prefix) {
			t.Errorf("SQL expression does not match %q — that model would fall through to the default", prefix)
		}
	}
	// Must lower-case the column for the same reason the Go side does.
	if !strings.Contains(strings.ToUpper(sql), "LOWER(") {
		t.Error("SQL expression must LOWER() the model column, or mixed-case models fall through to the default")
	}
	// Must be a self-contained expression: it is interpolated into a larger
	// SELECT and wrapped in arithmetic, so an unbalanced CASE would corrupt the
	// surrounding query rather than fail visibly.
	if strings.Count(strings.ToUpper(sql), "CASE") != strings.Count(strings.ToUpper(sql), "END") {
		t.Errorf("unbalanced CASE/END in SQL expression:\n%s", sql)
	}
}

// The column argument must be honoured — the admin table interpolates a
// qualified column ("ue.model") into a joined query, and silently ignoring it
// would reference the wrong table.
func TestClaudeModelWeightSQLQualifiesColumn(t *testing.T) {
	sql := ClaudeModelWeightSQL("ue.model")
	if !strings.Contains(sql, "ue.model") {
		t.Fatalf("qualified column not propagated into SQL:\n%s", sql)
	}
	if strings.Contains(sql, "LOWER(model)") {
		t.Fatalf("unqualified column leaked into SQL despite a qualified argument:\n%s", sql)
	}
}

// The quota unit folds raw token classes together by price ratio, then scales by
// model. These pin the arithmetic and, critically, the BACKWARD-COMPATIBILITY
// property that lets the schema change ship without a backfill.
func TestClaudeWeightedTokens(t *testing.T) {
	cases := []struct {
		name                   string
		model                  string
		in, out, cRead, cWrite int
		want                   int
	}{
		// A Claude Code turn: tiny fresh input, huge cached context. This is the
		// shape that made raw-token counting meaningless and weighted counting
		// necessary — 118k cache reads cost a tenth of 118k fresh tokens.
		{"opus cached turn", "claude-opus-5", 4, 350, 118000, 0, 4 + 350 + 11800},
		// Same turn on Sonnet costs a fifth again.
		{"sonnet cached turn", "claude-sonnet-5", 4, 350, 118000, 0, 2431}, // (4+350+11800)*0.2 = 2430.8, rounded
		// Cache WRITES are more expensive than fresh input, not less.
		{"cache write premium", "claude-opus-5", 0, 0, 0, 1000, 1250},
		{"haiku is nearly free", "claude-haiku-4-5", 0, 0, 100000, 0, 530}, // 100000*0.1*0.053
		// Unknown model bills at the conservative default, never free.
		{"unknown model", "some-future-model", 1000, 0, 0, 0, 200},
	}
	for _, c := range cases {
		got := ClaudeWeightedTokens(c.model, c.in, c.out, c.cRead, c.cWrite)
		if got != c.want {
			t.Errorf("%s: ClaudeWeightedTokens = %d, want %d", c.name, got, c.want)
		}
	}
}

// Rows written before the cache columns existed folded the already-weighted
// total into input_tokens and leave both cache columns at 0. The read-time
// formula must pass those through unchanged — otherwise shipping this schema
// change would silently re-scale every historical row and either wipe out or
// double-count usage that users are currently being capped on.
func TestClaudeWeightedTokensLegacyRowsPassThrough(t *testing.T) {
	const legacyWeightedInput = 39812 // what an old row stored for one Opus turn

	// Old row: everything in input_tokens, cache columns 0.
	old := ClaudeWeightedTokens("claude-opus-5", legacyWeightedInput, 0, 0, 0)
	if old != legacyWeightedInput {
		t.Fatalf("legacy Opus row changed value: %d -> %d; a schema change must not "+
			"re-scale history", legacyWeightedInput, old)
	}

	// And the model weight still applies to legacy rows exactly as it did before
	// the cache columns were added.
	oldSonnet := ClaudeWeightedTokens("claude-sonnet-5", legacyWeightedInput, 0, 0, 0)
	want := int(math.Round(float64(legacyWeightedInput) * 0.2))
	if oldSonnet != want {
		t.Fatalf("legacy Sonnet row = %d, want %d", oldSonnet, want)
	}
}

// The SQL twin must reference every raw column and both cache weights, or stored
// cached usage silently stops counting toward the cap.
func TestClaudeWeightedTokensSQLCoversAllColumns(t *testing.T) {
	sql := ClaudeWeightedTokensSQL("ue.")
	for _, col := range []string{"ue.input_tokens", "ue.output_tokens", "ue.cache_read_tokens", "ue.cache_creation_tokens"} {
		if !strings.Contains(sql, col) {
			t.Errorf("SQL is missing %s — that usage would not count toward the cap:\n%s", col, sql)
		}
	}
	for _, w := range []float64{claudeCacheReadWeight, claudeCacheWriteWeight} {
		if !strings.Contains(sql, fmt.Sprintf("%v", w)) {
			t.Errorf("SQL is missing cache weight %v:\n%s", w, sql)
		}
	}
	if !strings.Contains(sql, "ue.model") {
		t.Errorf("SQL does not apply the model weight:\n%s", sql)
	}
}
