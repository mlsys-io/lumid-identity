package handler

import (
	"encoding/json"
	"testing"
)

// Studio sends the tool catalog on EVERY turn and it is ~91% of the ~16.3k-token
// prefix. Simple view trades the authoring/operator surface for time-to-first-
// token; this pins the trade and the two ways it silently breaks.
func TestSimpleModeShrinksTheCatalog(t *testing.T) {
	full := buildToolDefsForRole("user")
	simple := filterSimpleTools(full)
	fb, _ := json.Marshal(full)
	sb, _ := json.Marshal(simple)
	t.Logf("full=%d tools %d chars (~%d tok) | simple=%d tools %d chars (~%d tok) | saved %.0f%%",
		len(full), len(fb), len(fb)/4, len(simple), len(sb), len(sb)/4,
		100*float64(len(fb)-len(sb))/float64(len(fb)))

	if len(simple) >= len(full) {
		t.Fatalf("Simple did not narrow the catalog (%d vs %d)", len(simple), len(full))
	}

	// A typo in the allowlist is INVISIBLE: the tool is simply never advertised
	// and Simple quietly loses a capability until a user asks for it.
	have := map[string]bool{}
	for _, d := range full {
		n, _ := d["name"].(string)
		have[n] = true
	}
	for want := range simpleModeTools {
		if !have[want] {
			t.Errorf("simpleModeTools lists %q, absent from the role=user catalog — typo or renamed tool", want)
		}
	}

	// The system prompt ORDERS these by name. A prompt that commands a tool the
	// catalog does not carry is a turn that cannot succeed.
	for _, must := range []string{
		"run_loop_now", "app_answer", "remember_about_me", "generate_image",
		"text_to_speech", "data_catalog", "data_query", "query_findata",
		"web_search", "web_fetch", "deep_research",
	} {
		if !simpleModeTools[must] {
			t.Errorf("%q is named imperatively in the system prompt but missing from Simple", must)
		}
	}
}

// Simple NARROWS an experience; it must never widen access.
func TestSimpleModeNeverWidensAccess(t *testing.T) {
	for _, role := range []string{"user", "admin", "super_admin"} {
		granted := map[string]bool{}
		for _, d := range buildToolDefsForRole(role) {
			n, _ := d["name"].(string)
			granted[n] = true
		}
		for _, d := range filterSimpleTools(buildToolDefsForRole(role)) {
			n, _ := d["name"].(string)
			if !granted[n] {
				t.Errorf("role=%s: Simple surfaced %q which the role does not grant", role, n)
			}
		}
	}
}
