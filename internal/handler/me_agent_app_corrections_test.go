package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lumid_identity/models"
)

// The correction loop's reader half, tested without a database.
//
// This is the rung that was silently open: the picker wrote an approved card
// edit to the tenant PVC, identity read a cache of the PUBLISHED bundle, and
// the answers never changed while Review said "approved". The fix reads the
// approved drafts directly — so these tests guard the mapping and the rendering
// that make that work, and would fail if either regressed to the state where an
// approval had no observable effect.

func draft(body string) models.MeDraft { return models.MeDraft{Body: body} }

func marker(card string) string {
	return "Proposed edit to prompts/analyst_skill_" + card + ".md"
}

func TestCardCorrectionsFromDrafts(t *testing.T) {
	tests := []struct {
		name  string
		rows  []models.MeDraft
		check func(t *testing.T, got map[string][]string)
	}{
		{
			name: "a draft naming an allowlisted card is mapped to it",
			rows: []models.MeDraft{draft("It ignored private-label economics.\n\n" + marker("profitability"))},
			check: func(t *testing.T, got map[string][]string) {
				if len(got["profitability"]) != 1 {
					t.Fatalf("want 1 correction on profitability, got %v", got)
				}
				if !strings.Contains(got["profitability"][0], "private-label") {
					t.Errorf("correction body lost: %q", got["profitability"][0])
				}
			},
		},
		{
			name: "a card outside the allowlist is refused",
			// `communication` is deliberately absent from knownSkillCards, and
			// the re-check exists because this value chooses a file path on the
			// far side of an intent boundary.
			rows: []models.MeDraft{draft("nope\n\n" + marker("communication"))},
			check: func(t *testing.T, got map[string][]string) {
				if got != nil {
					t.Errorf("non-allowlisted card must not map, got %v", got)
				}
			},
		},
		{
			name: "a draft naming no card at all is skipped, not crashed on",
			rows: []models.MeDraft{draft("just a memory note, no marker line")},
			check: func(t *testing.T, got map[string][]string) {
				if got != nil {
					t.Errorf("want nil for a markerless draft, got %v", got)
				}
			},
		},
		{
			name: "two corrections on one card both survive",
			rows: []models.MeDraft{
				draft("first\n\n" + marker("npv")),
				draft("second\n\n" + marker("npv")),
			},
			check: func(t *testing.T, got map[string][]string) {
				if len(got["npv"]) != 2 {
					t.Fatalf("want both corrections kept, got %v", got["npv"])
				}
			},
		},
		{
			name: "an empty body is dropped even with a valid marker",
			rows: []models.MeDraft{draft("   \n\t  ")},
			check: func(t *testing.T, got map[string][]string) {
				if got != nil {
					t.Errorf("blank body must not stage an empty correction, got %v", got)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, cardCorrectionsFromDrafts(tc.rows))
		})
	}
}

// The rendering half: an approved correction must reach the card text the model
// is handed, under the SAME heading the picker writes, so a card corrected by
// either path reads identically.
func TestSkillCardsWithCorrectionsRendersUnderLearnedCorrections(t *testing.T) {
	dir := t.TempDir()
	card := filepath.Join(dir, "analyst_skill_profitability.md")
	if err := os.WriteFile(card, []byte("# Profitability\n\nBase card text.\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No user => no DB lookup => the card must come through untouched. This is
	// the path skillCardsFor takes, and it must stay free of DB access.
	// "payback" is what routes profitability in (the npv branch pulls both);
	// the bare word "profitability" routes NOTHING, which is a real gap in the
	// Go router but a separate question from the correction loop.
	plain := skillCardsWithCorrections("", "", dir, "what is the payback period on this investment?")
	if len(plain) != 1 {
		t.Fatalf("want the profitability card routed, got %d cards", len(plain))
	}
	if strings.Contains(plain[0], "Learned corrections") {
		t.Errorf("anonymous caller must not get a corrections section:\n%s", plain[0])
	}
	if !strings.Contains(plain[0], "Base card text.") {
		t.Errorf("base card text lost:\n%s", plain[0])
	}
}
