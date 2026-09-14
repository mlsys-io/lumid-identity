package handler

// An experiment that lands upstream AFTER you installed is invisible: the tab
// lists what the local bundle declares and has no way to say "there is another
// one you do not have".
//
// Note what this deliberately does NOT compare. The divergence measured on the
// scheduler volume was across TENANTS — three mbb-consultant installs with three
// different experiment sets and two different UI surfaces — and that comparison
// is not one this endpoint may make. One user's installs are not another's
// business, and every read here is scoped to the caller for that reason. The
// comparison a user can actually act on is against upstream.

import (
	"reflect"
	"testing"
)

func TestCompareExperimentIDs(t *testing.T) {
	cases := []struct {
		name             string
		local, upstream  []string
		missing, localOn []string
	}{
		{"in step", []string{"a", "b"}, []string{"a", "b"}, nil, nil},
		{"upstream gained one", []string{"a"}, []string{"a", "b"}, []string{"b"}, nil},
		{"defined locally, never published", []string{"a", "mine"}, []string{"a"}, nil, []string{"mine"}},
		{"both directions", []string{"a", "mine"}, []string{"a", "theirs"}, []string{"theirs"}, []string{"mine"}},
		{"nothing installed", nil, []string{"a"}, []string{"a"}, nil},
		{"nothing upstream", []string{"a"}, nil, nil, []string{"a"}},
	}
	for _, c := range cases {
		got := compareExperimentIDs(c.local, c.upstream)
		if !reflect.DeepEqual(got.MissingHere, c.missing) {
			t.Errorf("%s: missing_here = %v, want %v", c.name, got.MissingHere, c.missing)
		}
		if !reflect.DeepEqual(got.LocalOnly, c.localOn) {
			t.Errorf("%s: local_only = %v, want %v", c.name, got.LocalOnly, c.localOn)
		}
	}
}

func TestExperimentIDsFromSpec(t *testing.T) {
	ids, ok := experimentIDsFromSpec([]byte(`
name: demo
experiments:
- id: analyst_local_gpu
  metric: {name: score}
- id: judge_panel_parity
- description: "an entry with no id is skipped, not fatal"
`))
	if !ok {
		t.Fatal("a valid spec failed to parse")
	}
	if !reflect.DeepEqual(ids, []string{"analyst_local_gpu", "judge_panel_parity"}) {
		t.Errorf("ids = %v", ids)
	}
}

func TestExperimentIDsFromSpecTolerates(t *testing.T) {
	// An app with no experiments is the common case, not an error.
	if ids, ok := experimentIDsFromSpec([]byte("name: demo\n")); !ok || len(ids) != 0 {
		t.Errorf("ids=%v ok=%v, want empty/true", ids, ok)
	}
	if _, ok := experimentIDsFromSpec([]byte("{{{ not yaml")); ok {
		t.Error("unparseable yaml reported success")
	}
}

// An empty result must not be mistaken for agreement: an app that was never
// published has nothing to compare against, and saying nothing would read as
// "you are in step".
func TestUnreadableUpstreamSaysSoRatherThanNothing(t *testing.T) {
	var d experimentDivergence
	if d.Unavailable {
		t.Fatal("zero value should not claim unavailable")
	}
	d = experimentDivergence{Unavailable: true}
	if len(d.MissingHere) != 0 || len(d.LocalOnly) != 0 {
		t.Error("an unavailable comparison must not also assert differences")
	}
}
