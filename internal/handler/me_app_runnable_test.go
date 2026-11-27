package handler

import "testing"

func TestSpecIsRunnable(t *testing.T) {
	cases := map[string]bool{
		// v2 simple scheme (Quant Research's shape): workflows + pages.
		"name: q\nkind: agent\nworkflows:\n- id: backtest\n  run: manual\n  steps: {python: backtest}\npages:\n- id: strategies\n  title: Strategies\n  file: ui/strategies.yaml\n": true,
		// legacy loops
		"name: a\nloops:\n- name: x\n": true,
		// a knowledge bank: no loops, tools or surfaces
		"name: bank\nkind: agent\nmemory_agent: notes\n": false,
	}
	for spec, want := range cases {
		if got := specIsRunnable([]byte(spec)); got != want {
			t.Errorf("specIsRunnable(%q) = %v, want %v", spec[:20], got, want)
		}
	}
}
