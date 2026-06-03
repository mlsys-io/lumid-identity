package common

import (
	"reflect"
	"sort"
	"testing"
)

func TestExpandFlowmeshScopes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		// `want` is compared as a sorted set so we don't fight ordering.
		want []string
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "no flowmesh shortcuts — passthrough",
			in:   []string{"qa:read", "lumilake:*"},
			want: []string{"qa:read", "lumilake:*"},
		},
		{
			name: "flowmesh:read expands to all *:read",
			in:   []string{"flowmesh:read"},
			want: []string{
				"flowmesh:workflows:read", "flowmesh:tasks:read",
				"flowmesh:results:read", "flowmesh:nodes:read",
				"flowmesh:workers:read", "flowmesh:system:read",
			},
		},
		{
			name: "flowmesh:write expands to read+write across writable resources",
			in:   []string{"flowmesh:write"},
			want: []string{
				"flowmesh:workflows:read", "flowmesh:tasks:read",
				"flowmesh:results:read", "flowmesh:nodes:read",
				"flowmesh:workers:read", "flowmesh:system:read",
				"flowmesh:workflows:write", "flowmesh:results:write",
				"flowmesh:nodes:write", "flowmesh:workers:write",
			},
		},
		{
			name: "flowmesh:admin passes through (plugin admin alias)",
			in:   []string{"flowmesh:admin"},
			want: []string{"flowmesh:admin"},
		},
		{
			name: "fine-grained input is preserved + deduped",
			in:   []string{"flowmesh:workflows:read", "flowmesh:read"},
			want: []string{
				"flowmesh:workflows:read", "flowmesh:tasks:read",
				"flowmesh:results:read", "flowmesh:nodes:read",
				"flowmesh:workers:read", "flowmesh:system:read",
			},
		},
		{
			name: "mixed: other-service scopes survive, flowmesh shortcuts expand",
			in:   []string{"qa:write", "flowmesh:read", "*"},
			want: []string{
				"qa:write",
				"flowmesh:workflows:read", "flowmesh:tasks:read",
				"flowmesh:results:read", "flowmesh:nodes:read",
				"flowmesh:workers:read", "flowmesh:system:read",
				"*",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExpandFlowmeshScopes(tc.in)
			gotSorted := append([]string(nil), got...)
			wantSorted := append([]string(nil), tc.want...)
			sort.Strings(gotSorted)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(gotSorted, wantSorted) {
				t.Errorf("ExpandFlowmeshScopes(%v):\n  got  %v\n  want %v", tc.in, gotSorted, wantSorted)
			}
		})
	}
}
