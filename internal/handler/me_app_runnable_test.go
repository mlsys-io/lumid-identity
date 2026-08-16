package handler

// repoIsRunnable decides whether a kind=agent repo gets "install" or the
// "subscribe instead" pointer. The gap this pins: a SURFACE-ONLY app — a
// read-only viewer whose whole value is its Studio tabs — legitimately
// declares `loops: []` and `tools: []`, so a loops-or-tools test could not
// tell it from a knowledge bank and sent users to the wrong verb.
//
// The yaml shape is asserted directly rather than through repoIsRunnable
// itself, which needs a live repo fetch.

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// runnableFromSpec mirrors the decision in repoIsRunnable after the fetch.
func runnableFromSpec(t *testing.T, spec string) bool {
	t.Helper()
	var doc struct {
		Loops []map[string]any `yaml:"loops"`
		Tools []map[string]any `yaml:"tools"`
		UI    struct {
			Surface  map[string]any `yaml:"surface"`
			Surfaces map[string]any `yaml:"surfaces"`
		} `yaml:"ui"`
	}
	if err := yaml.Unmarshal([]byte(spec), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.UI.Surface) > 0 || len(doc.UI.Surfaces) > 0 {
		return true
	}
	return len(doc.Loops) > 0 || len(doc.Tools) > 0
}

func TestRepoIsRunnableSpecShapes(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want bool
	}{
		{
			// The regression: lumid-data-lake's exact shape. Empty loops AND
			// tools, but two real Studio tabs.
			name: "surface-only viewer is runnable",
			spec: `
kind: agent
loops: []
tools: []
ui:
  sidebar: {label: Data Lake Explorer}
  surface:
    markdown: ui/home.md
  surfaces:
    home: ui/home.md
    explorer: ui/explorer.md
  nav:
  - {surface: home, label: Catalog}
  - {surface: explorer, label: Explorer}
`,
			want: true,
		},
		{
			// A knowledge bank: no ui: block at all. Must still be told to
			// subscribe, or the fix would swallow the whole distinction.
			name: "knowledge bank is NOT runnable",
			spec: `
kind: agent
loops: []
tools: []
memory_agents: [some-bank]
`,
			want: false,
		},
		{
			name: "loop-bearing app stays runnable",
			spec: `
kind: agent
loops:
- {name: match_cycle, schedule: "0 */2 * * *"}
tools: []
`,
			want: true,
		},
		{
			name: "tool-bearing app stays runnable",
			spec: `
kind: agent
loops: []
tools:
- {name: monitor}
`,
			want: true,
		},
		{
			name: "sidebar alone is not a surface",
			spec: `
kind: agent
loops: []
tools: []
ui:
  sidebar: {label: Just A Label}
`,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := runnableFromSpec(t, tc.spec); got != tc.want {
				t.Fatalf("runnable = %v, want %v", got, tc.want)
			}
		})
	}
}
