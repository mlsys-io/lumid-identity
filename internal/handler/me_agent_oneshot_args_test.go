package handler

import "testing"

// run_loop_now could pass a loop only `cases`, so a parameterised loop ran bare:
// quant-research's backtest submitted an EMPTY strategy and reported success,
// while the Backtest page and the onboarding doc both promised the action was
// available in chat. These lock the merge that closed that gap.
func TestOneshotArgsFrom(t *testing.T) {
	tests := []struct {
		name string
		in   map[string]any
		want map[string]any
	}{
		{
			name: "nothing to pass stays nil so the runner gets no empty --arg",
			in:   map[string]any{"app": "quant-research", "loop": "backtest"},
			want: nil,
		},
		{
			name: "legacy cases shorthand still works",
			in:   map[string]any{"cases": "Case_019"},
			want: map[string]any{"cases": "Case_019"},
		},
		{
			name: "a backtest reaches the loop with its subject",
			in: map[string]any{"args": map[string]any{
				"action": "submit", "symbol": "KXBTCD-26SEP0211-T77099.99",
				"strategy": "strategy s { params { t: 1500 } }",
			}},
			want: map[string]any{
				"action": "submit", "symbol": "KXBTCD-26SEP0211-T77099.99",
				"strategy": "strategy s { params { t: 1500 } }",
			},
		},
		{
			name: "explicit args.cases beats the shorthand rather than being clobbered",
			in: map[string]any{
				"cases": "Case_001",
				"args":  map[string]any{"cases": "Case_019"},
			},
			want: map[string]any{"cases": "Case_019"},
		},
		{
			name: "shorthand and args coexist when they do not collide",
			in: map[string]any{
				"cases": "Case_019",
				"args":  map[string]any{"model": "sonnet"},
			},
			want: map[string]any{"cases": "Case_019", "model": "sonnet"},
		},
		{
			name: "non-string values survive; the SDK coerces them at the argv edge",
			in:   map[string]any{"args": map[string]any{"limit": float64(200), "dry": true}},
			want: map[string]any{"limit": float64(200), "dry": true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oneshotArgsFrom(tc.in)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %v", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q: want %v, got %v", k, v, got[k])
				}
			}
		})
	}
}
