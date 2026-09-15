package handler

import "testing"

// The drift guard is an init() panic, which a test cannot observe directly —
// so assert the same invariant explicitly. This is the check that keeps the
// token page from falling behind the allowlist a third time.
func TestCapabilityCatalogCoversAllowlist(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range capabilityCatalog {
		if !capabilityScopes[c.Scope] {
			t.Errorf("catalog lists %q which is not on the allowlist", c.Scope)
		}
		if seen[c.Scope] {
			t.Errorf("catalog lists %q twice", c.Scope)
		}
		if c.Label == "" || c.Desc == "" {
			t.Errorf("catalog entry %q has an empty label or description", c.Scope)
		}
		seen[c.Scope] = true
	}
	for scope := range capabilityScopes {
		if !seen[scope] {
			t.Errorf("allowlist allows %q but the catalog does not describe it — "+
				"the token UI would never offer it", scope)
		}
	}
	if len(capabilityCatalog) != len(capabilityScopes) {
		t.Errorf("catalog has %d entries, allowlist has %d",
			len(capabilityCatalog), len(capabilityScopes))
	}
}

// flowmesh:workflows:write is the specific scope a user needs to run a job end
// to end, and the one the complaint was about. It must be on both lists.
func TestFlowmeshWorkflowsWriteIsOfferable(t *testing.T) {
	if !capabilityScopes["flowmesh:workflows:write"] {
		t.Fatal("flowmesh:workflows:write is not on the allowlist")
	}
	for _, c := range capabilityCatalog {
		if c.Scope == "flowmesh:workflows:write" {
			return
		}
	}
	t.Fatal("flowmesh:workflows:write has no catalog entry, so no UI control")
}
