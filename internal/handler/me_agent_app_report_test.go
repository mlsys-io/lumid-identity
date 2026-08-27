package handler

// Two things worth pinning here.
//
// The skill router: two cards shipped in the bundle and were allowlisted for
// corrections, but no branch of the router could ever select them. A card that
// nothing loads is invisible — the answers are simply worse, with no error
// anywhere — so the reachability of the full set is the assertion, not the
// routing of any one question.
//
// The scorecard's buckets: an open-mode score comes from keypoints the judge
// invented for that turn and runs near ceiling; a casebook score is measured
// against the dataset. Averaging them produces a number that is neither, and
// the same hazard applies to a human candidate's score landing in the model's
// mean. The split is the contract.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// knownSkillCards is the allowlist a correction may name. Every one of them
// must be reachable by SOME question, or a user can correct a card that never
// loads and watch nothing change.
func TestEverySkillCardIsReachable(t *testing.T) {
	probes := []string{
		"what is the NPV of this investment?",
		"how many units could they sell?",
		"which of these three options should they take?",
		"what are the risks here?",
		"how could they grow revenue with adjacent products?",
		"based on this price, what other factors matter?",
		"how should they think about this problem?",
	}
	reached := map[string]bool{}
	for _, p := range probes {
		for _, c := range skillCardNamesFor(p) {
			reached[c] = true
		}
	}
	for card := range knownSkillCards {
		if !reached[card] {
			t.Errorf("skill card %q can be corrected but no question routes to it — "+
				"it ships in the bundle and is loaded by nothing", card)
		}
	}
}

// The router is additive: a question can be about a price AND about risk, and
// answering it needs both cards. The switch it replaced stopped at the first
// arm, so the pricing cards never loaded for exactly this phrasing.
func TestSkillRouterIsAdditive(t *testing.T) {
	got := skillCardNamesFor("based on this price, what other factors should they weigh?")
	has := func(want string) bool {
		for _, c := range got {
			if c == want {
				return true
			}
		}
		return false
	}
	if !has("value_to_customer") {
		t.Errorf("pricing question did not reach value_to_customer: %v", got)
	}
	if !has("risk_mece") {
		t.Errorf("additive routing lost the risk cards: %v", got)
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatalf("router returned %q twice: %v", c, got)
		}
		seen[c] = true
	}
}

// An approved correction has to reach the prompt the model actually reads.
// The picker writes it to the tenant PVC, which identity does not mount, so
// the reader is where it has to land.
func TestSkillCardsCarryNoCorrectionsForAnonymousCaller(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"communication", "issue_tree", "hypothesis_first"} {
		if err := os.WriteFile(filepath.Join(dir, "analyst_skill_"+n+".md"), []byte("card "+n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.Join(skillCardsWithCorrections("", "", dir, "how should they approach this?"), "\n")
	if strings.Contains(got, "Learned corrections") {
		t.Fatal("a caller with no user id got a corrections section")
	}
	if !strings.Contains(got, "card communication") {
		t.Fatal("base cards missing")
	}
}

func TestReportRequiresApp(t *testing.T) {
	if _, ok := toolAppReport("someone", ""); ok {
		t.Fatal("accepted an empty app")
	}
}
