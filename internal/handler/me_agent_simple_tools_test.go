package handler

import (
	"encoding/json"
	"testing"
)

// No chip uses simpleTools after Flint's removal (2026-11-06); the mechanism stays for small
// on-prem models. The default chip must never be slimmed.
func TestDefaultChipKeepsFullCatalog(t *testing.T) {
	for _, p := range llmProviders {
		if p.id == defaultProvider().id && p.simpleTools {
			t.Fatalf("the default chip %q must keep the full catalog", p.id)
		}
	}
}

// The simple set must be a strict, much smaller subset of the role's catalog and keep
// the tools the system prompt names imperatively.
func TestSimpleToolsShrinksCatalog(t *testing.T) {
	full := buildToolDefsForRole("user")
	simple := filterSimpleTools(full)
	fb, _ := json.Marshal(full)
	sb, _ := json.Marshal(simple)
	t.Logf("user catalog: full %d tools / %d bytes; simple %d tools / %d bytes", len(full), len(fb), len(simple), len(sb))
	if len(simple) == 0 || len(simple) >= len(full) || len(sb) >= len(fb) {
		t.Fatalf("simple set not smaller: %d vs %d tools", len(simple), len(full))
	}
	names := map[string]bool{}
	for _, d := range simple {
		n, _ := d["name"].(string)
		names[n] = true
	}
	for _, must := range []string{"app_answer", "workflow_run", "web_search", "data_query"} {
		if !names[must] {
			t.Errorf("simple set lost load-bearing tool %q", must)
		}
	}
}
