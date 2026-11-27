package handler

import (
	"strings"
	"testing"
)

func TestRebindPageApp(t *testing.T) {
	spec := `sections:
- widgets:
  - type: table
    source: me://app-data?app=quant-research&tool=runs&loop=backtest
    row_href: /studio/apps/quant-research/w/backtest/r/{cycle_id}
    actions:
    - label: Deploy
      run_loop:
        app: quant-research
        loop: send_strategy
    - label: Other app
      run_loop:
        app: 'quant-research-pro'
        loop: x
    - label: Stat
      source: me://app-data?app=quant-research
      run_loop: {app: quant-research, loop: forward_test}
`
	got := string(rebindPageApp([]byte(spec), "quant-research", "quant-research-e2e"))
	for _, want := range []string{
		"me://app-data?app=quant-research-e2e&tool=runs",
		"/studio/apps/quant-research-e2e/w/backtest",
		"        app: quant-research-e2e\n",
		"source: me://app-data?app=quant-research-e2e\n",
		"run_loop: {app: quant-research-e2e, loop: forward_test}",
		"app: 'quant-research-pro'", // another app's name is left alone
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if got := string(rebindPageApp([]byte(spec), "quant-research", "quant-research")); got != spec {
		t.Error("an install under its own name must be unchanged")
	}
	if got := string(rebindPageApp([]byte(spec), "", "x")); got != spec {
		t.Error("no spec name → unchanged")
	}
}
