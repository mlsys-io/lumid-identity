package handler

import (
	"testing"

	"lumid_identity/models"
)

func TestCardSpecPrefersInstalledSpec(t *testing.T) {
	calls := 0
	published := func() ([]byte, bool) {
		calls++
		return []byte("name: mlsys-research\ntitle: MLSys Research\nui:\n  sidebar:\n    section: Research\n"), true
	}
	stored := &models.MeAppSpec{SpecYAML: "name: mlsys-research\nui:\n  sidebar:\n    section: Research\n    label: MLSys Research (e2e test)\n"}

	b, ok := cardSpecForParse(stored, published)
	if !ok || calls != 0 {
		t.Fatalf("installed spec should win without fetching the published one (ok=%v calls=%d)", ok, calls)
	}
	ui := parseAppUI(b)
	if ui == nil || ui.Sidebar == nil || ui.Sidebar.Label != "MLSys Research (e2e test)" {
		t.Fatalf("sidebar label should come from the installed spec, got %+v", ui)
	}

	if _, ok := cardSpecForParse(nil, published); !ok || calls != 1 {
		t.Fatalf("no installed spec → published fallback (ok=%v calls=%d)", ok, calls)
	}
	if _, ok := cardSpecForParse(&models.MeAppSpec{}, published); !ok || calls != 2 {
		t.Fatalf("empty installed spec → published fallback (ok=%v calls=%d)", ok, calls)
	}
}
