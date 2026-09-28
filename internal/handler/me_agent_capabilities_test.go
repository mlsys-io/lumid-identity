package handler

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// A capability naming a tool no catalog defines would print "NO" forever and
// send users away from a surface that can in fact do the thing.
func TestCapabilityToolsExistInCatalog(t *testing.T) {
	have := map[string]bool{}
	for _, d := range buildToolDefsForRole("super_admin") {
		if n, _ := d["name"].(string); n != "" {
			have[n] = true
		}
	}
	for _, c := range chatCapabilities {
		for _, tool := range c.tools {
			if !have[tool] {
				t.Errorf("capability %q names unknown tool %q", c.label, tool)
			}
		}
	}
}

func TestCapabilityHintReflectsFilteredTools(t *testing.T) {
	full := capabilityHint(buildToolDefsForRole("user"))
	if !strings.Contains(full, "Submit backtests / run an app's workflows: yes") {
		t.Fatalf("user catalog should submit backtests:\n%s", full)
	}
	simple := capabilityHint(filterSimpleTools(buildToolDefsForRole("user")))
	if !strings.Contains(simple, "strategy_cycles): NO here") {
		t.Fatalf("Simple mode lacks lqt_mailbox_read and must say so:\n%s", simple)
	}
	if capabilityHint(nil) != "" {
		t.Fatal("no tools (claude-code path) -> no summary")
	}
}

const strategiesPageFixture = `
sections:
- heading: Your strategies
  widgets:
  - type: table
    source: me://strategies
    row_actions:
    - label: Backtest
      run_loop:
        app: quant-research
        loop: backtest
        args:
          action: submit
          strategy_id: '{strategy_id}'
          until: '{until}'
      fields:
      - key: until
        label: Window ends
    - label: Discuss
      href: /studio/chat
`

// FLB-QR-01: page.yaml surfaces reported no actions, so the chat could not
// discover the strategy row's Backtest.
func TestCollectPageSpecPrimitives(t *testing.T) {
	var doc any
	if err := yaml.Unmarshal([]byte(strategiesPageFixture), &doc); err != nil {
		t.Fatal(err)
	}
	reads := map[string]bool{}
	var acts []map[string]any
	collectPageSpecPrimitives(doc, "strategies", reads, &acts)
	if !reads["me://strategies"] {
		t.Fatalf("source not collected: %v", reads)
	}
	if len(acts) != 1 || acts[0]["label"] != "Backtest" || acts[0]["loop"] != "backtest" {
		t.Fatalf("want the one run_loop action, got %+v", acts)
	}
	args, _ := acts[0]["args"].(map[string]any)
	if args["action"] != "submit" || acts[0]["fields"] == nil {
		t.Fatalf("args/fields lost: %+v", acts[0])
	}
}

// FLB-QR-01: app_read had no case for the Strategies page's own source.
func TestAppReadAcceptsStrategies(t *testing.T) {
	t.Setenv("LQT_CORE_DSN", "")
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	res, err := appReadSource(c, "11111111-1111-1111-1111-111111111111", "me://strategies")
	if err != nil {
		t.Fatalf("me://strategies refused: %v", err)
	}
	data, _ := res.(gin.H)
	if data["available"] != false || !strings.Contains(data["reason"].(string), "LQT_CORE_DSN") {
		t.Fatalf("want the unconfigured-registry state, got %+v", res)
	}
}
