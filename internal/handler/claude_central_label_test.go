package handler

// The central sentinel must report as a ROUTING label in identity, so an
// operator allocating an account there is not warned that it is unwired. This
// pins claudeLabelRoutes (which feeds relay_configured) and IsClaudeCentralLabel.

import "testing"

func TestClaudeLabelRoutesCentral(t *testing.T) {
	for _, label := range []string{"central", "CENTRAL", "direct", " Direct "} {
		if !claudeLabelRoutes(label) {
			t.Errorf("claudeLabelRoutes(%q) = false; central must route", label)
		}
	}
}

// The empty label routes too — claude-proxy adopts an unlabeled account onto a
// hashed field box, so it is not an unwired label.
func TestClaudeLabelRoutesEmpty(t *testing.T) {
	if !claudeLabelRoutes("") {
		t.Error("claudeLabelRoutes(\"\") = false; unlabeled accounts are adopted onto a box")
	}
}

// A real configured box routes; a typo does not. This is the quiet-failure
// surface the predicate exists to protect.
func TestClaudeLabelRoutesKnownBoxAndTypo(t *testing.T) {
	saved := fieldRelays
	t.Cleanup(func() { fieldRelays = saved })
	fieldRelays = map[string]string{"denmark": "http://d:8091"}

	if !claudeLabelRoutes("denmark") {
		t.Error("claudeLabelRoutes(\"denmark\") = false; a configured box must route")
	}
	if claudeLabelRoutes("denmrak") {
		t.Error("claudeLabelRoutes(\"denmrak\") = true; a typo must be flagged as unwired")
	}
}

func TestIsClaudeCentralLabel(t *testing.T) {
	for _, label := range []string{"central", "CENTRAL", "direct", "Direct"} {
		if !IsClaudeCentralLabel(label) {
			t.Errorf("IsClaudeCentralLabel(%q) = false", label)
		}
	}
	for _, label := range []string{"", "denmark", "centralx", "centra"} {
		if IsClaudeCentralLabel(label) {
			t.Errorf("IsClaudeCentralLabel(%q) = true; only central/direct are central", label)
		}
	}
}
