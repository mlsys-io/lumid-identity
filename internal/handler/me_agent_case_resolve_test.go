package handler

// `case_id` in the corpus is only the NUMBER, so Case_001 exists three times:
// DieselTruck_PK20, LasioVirus_PK23, PremierOil_PK21. Globbing caseID+"*.json"
// and taking matches[0] after a lexical sort resolved a bare "Case_001" to
// DieselTruck no matter which case the caller meant.
//
// Observed live, and worse than a wrong lookup: an interview opened on Premier
// Oil with the full id, a follow-up passed the bare "Case_001", and it silently
// landed on the diesel-truck case. The model noticed mid-interview, announced it
// had "mislabeled the case", and restarted on the wrong one — so the candidate
// was being scored against a case they were never given.

import "testing"

var threeOhOnes = []string{
	"/s/Case_001_DieselTruck_PK20_v5.json",
	"/s/Case_001_LasioVirus_PK23_v3.json",
	"/s/Case_001_PremierOil_PK21_v5.json",
}

func TestResolveUniqueCase_RefusesAnAmbiguousPrefix(t *testing.T) {
	if p, ok := resolveUniqueCase("Case_001", threeOhOnes); ok {
		t.Fatalf("bare Case_001 resolved to %q — it names three different cases", p)
	}
}

func TestResolveUniqueCase_ExactStemWins(t *testing.T) {
	got, ok := resolveUniqueCase("Case_001_PremierOil_PK21_v5", threeOhOnes)
	if !ok || got != "/s/Case_001_PremierOil_PK21_v5.json" {
		t.Fatalf("exact stem = %q, %v", got, ok)
	}
}

func TestResolveUniqueCase_ExactCaseIgnoringVersion(t *testing.T) {
	// The roster and the chat verb disagree on whether _vN is part of the name.
	got, ok := resolveUniqueCase("Case_001_PremierOil_PK21", threeOhOnes)
	if !ok || got != "/s/Case_001_PremierOil_PK21_v5.json" {
		t.Fatalf("versionless id = %q, %v", got, ok)
	}
}

func TestResolveUniqueCase_UnambiguousPrefixIsAllowed(t *testing.T) {
	// One case, two version files — still one case, so honour it.
	got, ok := resolveUniqueCase("Case_019", []string{
		"/s/Case_019_BetaOptics_PK21_v10.json",
	})
	if !ok || got == "" {
		t.Fatalf("unambiguous prefix should resolve, got %q %v", got, ok)
	}
}

func TestResolveUniqueCase_PrefersExactOverLexicalFirst(t *testing.T) {
	// The regression in one line: DieselTruck sorts first, PremierOil is meant.
	got, _ := resolveUniqueCase("Case_001_PremierOil_PK21_v5", threeOhOnes)
	if got == "/s/Case_001_DieselTruck_PK20_v5.json" {
		t.Fatal("resolved to the lexically-first case instead of the named one")
	}
}
