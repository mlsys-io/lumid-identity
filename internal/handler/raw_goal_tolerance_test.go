package handler

import (
	"encoding/json"
	"testing"
)

// The bug these guard against is not "a goal decodes wrong" — it is that ONE
// malformed goal took every loop in the app off /me/workflows, the Workflows
// tab, the lumid:workflow canvas and chat dispatch at once, because both row
// builders swallow the unmarshal error with `continue`. So every case here
// asserts the SIBLING loop survives, not just that the goal parsed.

const goalSpecBareString = `
loops:
  - name: vla_curate
    schedule: "@trigger"
    goal: Curate droid_100 robot episodes into a VLA training manifest.
  - name: sibling
    schedule: "0 9 * * *"
    goal:
      primary: Something else entirely
      tracked:
        - rows written
`

func TestRawGoal_BareStringDoesNotSinkTheList(t *testing.T) {
	loops, err := readYamlLoopsBytes([]byte(goalSpecBareString))
	if err != nil {
		t.Fatalf("a bare-string goal must not fail the whole loops list: %v", err)
	}
	if len(loops) != 2 {
		t.Fatalf("want 2 loops, got %d — a sibling loop was lost", len(loops))
	}
	if loops[0].Name != "vla_curate" {
		t.Fatalf("loop 0 name = %q", loops[0].Name)
	}
	want := "Curate droid_100 robot episodes into a VLA training manifest."
	if loops[0].Goal.Primary != want {
		t.Errorf("bare string should coerce to primary\n got %q\nwant %q",
			loops[0].Goal.Primary, want)
	}
	if len(loops[0].Goal.Tracked) != 0 {
		t.Errorf("bare string carries no tracked metrics, got %v", loops[0].Goal.Tracked)
	}
	// The object form must be untouched by the tolerance.
	if loops[1].Goal.Primary != "Something else entirely" {
		t.Errorf("object-form primary = %q", loops[1].Goal.Primary)
	}
	if len(loops[1].Goal.Tracked) != 1 || loops[1].Goal.Tracked[0] != "rows written" {
		t.Errorf("object-form tracked = %v", loops[1].Goal.Tracked)
	}
	// Schedule is what the row builder keys on; prove tolerance didn't eat it.
	if loops[0].Schedule != "@trigger" {
		t.Errorf("schedule lost: %q", loops[0].Schedule)
	}
}

func TestRawGoal_ShapesThatMustNeverError(t *testing.T) {
	cases := []struct {
		name        string
		spec        string
		wantPrimary string
		wantTracked int
	}{
		{
			name:        "null goal",
			spec:        "loops:\n  - name: a\n    goal:\n  - name: b\n",
			wantPrimary: "",
		},
		{
			name:        "empty string goal",
			spec:        "loops:\n  - name: a\n    goal: \"\"\n  - name: b\n",
			wantPrimary: "",
		},
		{
			name:        "goal is a sequence (unknown shape)",
			spec:        "loops:\n  - name: a\n    goal: [one, two]\n  - name: b\n",
			wantPrimary: "",
		},
		{
			name:        "multiline folded string",
			spec:        "loops:\n  - name: a\n    goal: >-\n      keep the fleet\n      green\n  - name: b\n",
			wantPrimary: "keep the fleet green",
		},
		{
			name: "object-form tracked entries get salvaged",
			spec: "loops:\n  - name: a\n    goal:\n      primary: p\n      tracked:\n" +
				"        - name: episodes curated\n        - plain metric\n  - name: b\n",
			wantPrimary: "p",
			wantTracked: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loops, err := readYamlLoopsBytes([]byte(tc.spec))
			if err != nil {
				t.Fatalf("must not error (it would hide every loop): %v", err)
			}
			if len(loops) != 2 {
				t.Fatalf("want 2 loops (sibling must survive), got %d", len(loops))
			}
			if loops[0].Goal.Primary != tc.wantPrimary {
				t.Errorf("primary = %q, want %q", loops[0].Goal.Primary, tc.wantPrimary)
			}
			if len(loops[0].Goal.Tracked) != tc.wantTracked {
				t.Errorf("tracked = %v, want %d entries",
					loops[0].Goal.Tracked, tc.wantTracked)
			}
		})
	}
}

// manifest.json is the legacy mirror and the fallback the row builders reach
// for when the spec is unreadable — it must tolerate the same shapes, or the
// fallback fails identically to the primary path and the app stays invisible.
func TestRawGoal_JSONMirrorToleratesBothForms(t *testing.T) {
	var doc struct {
		Loops []rawLoop `json:"loops"`
	}
	raw := `{"loops":[
	  {"name":"a","goal":"a bare string goal"},
	  {"name":"b","goal":{"primary":"p","tracked":["m1","m2"]}},
	  {"name":"c","goal":{"primary":"q","tracked":[{"name":"m3"},"m4"]}},
	  {"name":"d","goal":null},
	  {"name":"e","goal":["unknown","shape"]}
	]}`
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("manifest mirror must not fail the list: %v", err)
	}
	if len(doc.Loops) != 5 {
		t.Fatalf("want 5 loops, got %d", len(doc.Loops))
	}
	if got := doc.Loops[0].Goal.Primary; got != "a bare string goal" {
		t.Errorf("bare string primary = %q", got)
	}
	if got := doc.Loops[1].Goal.Primary; got != "p" {
		t.Errorf("object primary = %q", got)
	}
	if len(doc.Loops[1].Goal.Tracked) != 2 {
		t.Errorf("object tracked = %v", doc.Loops[1].Goal.Tracked)
	}
	if got := doc.Loops[2].Goal.Primary; got != "q" {
		t.Errorf("salvaged primary = %q", got)
	}
	if len(doc.Loops[2].Goal.Tracked) != 2 {
		t.Errorf("salvaged tracked = %v, want 2", doc.Loops[2].Goal.Tracked)
	}
	if doc.Loops[4].Name != "e" {
		t.Errorf("unknown-shape goal must not drop its loop")
	}
}
