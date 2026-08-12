package handler

import "testing"

// The hint must fire on a case id and stay silent otherwise — a bare
// administrative turn should not drag a case into the prompt.
func TestCaseIDRe(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Let's work case Case_001_DieselTruck_PK20_v5. Give me the opening.", "Case_001_DieselTruck_PK20_v5"},
		{"Let's work case Case_019_BetaOptics_PK21.", "Case_019_BetaOptics_PK21"},
		{"run the workflow", ""},
		{"what cases are there?", ""},
		// Traversal yields NO match at all: the charclass admits no "." or "/",
		// and + needs at least one character after the prefix.
		{"Case_../../etc/passwd", ""},
		{"Case_001/../../etc", "Case_001"}, // truncated at the slash
	} {
		if got := caseIDRe.FindString(tc.in); got != tc.want {
			t.Errorf("caseIDRe(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
