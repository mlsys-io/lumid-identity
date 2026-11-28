package handler

import (
	"strings"
	"testing"
)

func TestDiscardBodyRules(t *testing.T) {
	one := []discardMatch{{VariantID: "v1", CycleTS: "20261128T031819Z"}}
	cases := []struct {
		action, reason string
		m              []discardMatch
		want           string
	}{
		{"discard", "wrong design", one, ""},
		{"restore", "", one, ""},
		{"discard", "", one, "say why"},
		{"delete", "x", one, "action must be"},
		{"discard", "x", nil, "1 to 200"},
		{"discard", "x", []discardMatch{{}}, "every match needs"},
		{"discard", "x", []discardMatch{{Stage: "a\nb"}}, "line break"},
	}
	for _, c := range cases {
		got := discardBodyError(c.action, c.reason, c.m)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s/%q -> %q, want %q", c.action, c.reason, got, c.want)
		}
	}
}

func TestDiscardRouteIsRegistered(t *testing.T) {
	if !strings.Contains(loopPatchSrc(t, "router.go"), `"/apps/:app/experiments/:id/discard", MeAppExperimentDiscard`) {
		t.Fatal("discard route missing")
	}
}
