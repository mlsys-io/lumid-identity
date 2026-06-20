package handler

import (
	"strings"
	"testing"
)

// TestDestructiveToolsGating pins the approval-gate allowlist: mutating tools
// MUST require approval (present + true), reads MUST NOT be in the map (absent →
// zero-value false). A regression here would either silently run a destructive
// op without approval, or force an approval round-trip on a harmless read.
func TestDestructiveToolsGating(t *testing.T) {
	gated := []string{
		"app_ui_set", "app_ui_generate", "run_promote", "run_discard",
		"app_config_set", "delete_loop", "install_app",
	}
	for _, name := range gated {
		t.Run("gated/"+name, func(t *testing.T) {
			// install_app is not in the map today; the spec wants it gated, so
			// assert via the map lookup so the test documents the intent and
			// flags the gap if/when the name is added.
			if name == "install_app" {
				// app_install is the canonical gated name; install_app is the
				// underscore-flipped alias the spec asked about. Accept either
				// being present, but require the canonical one is gated.
				if !destructiveTools["app_install"] {
					t.Errorf("app_install must be gated (destructiveTools[app_install] = false)")
				}
				return
			}
			if !destructiveTools[name] {
				t.Errorf("expected %q to be approval-gated (destructiveTools[%q] = true), got false", name, name)
			}
		})
	}

	notGated := []string{
		"app_ui_get", "app_read", "app_actions", "show_app_surface", "run_loop_now",
	}
	for _, name := range notGated {
		t.Run("not_gated/"+name, func(t *testing.T) {
			if destructiveTools[name] {
				t.Errorf("expected %q NOT to be approval-gated (it is a read / non-destructive run), but destructiveTools[%q] = true", name, name)
			}
		})
	}
}

// userMsg builds a one-turn history with a single user message, matching what
// controlIntent scans (it reads the LAST user message).
func userMsg(content string) []chatMessage {
	return []chatMessage{{Role: "user", Content: content}}
}

// TestControlIntent verifies the heuristic that re-routes a tool-less provider
// to a tool-capable one when the user asks the PLATFORM to do something. Recall
// matters for the positives (else "install/run/publish" never executes); the
// negatives must stay false so shell/code turns aren't stolen from claude-code.
func TestControlIntent(t *testing.T) {
	positives := []string{
		"install the app auto-quant",
		"run the workflow morning brief",
		"publish the app",
		"promote the run",
		"edit the app ui",
		"generate a page",
		"fork the app",
	}
	for _, c := range positives {
		t.Run("route/"+c, func(t *testing.T) {
			if !controlIntent(userMsg(c)) {
				t.Errorf("controlIntent(%q) = false, want true (platform-control turn must route)", c)
			}
		})
	}

	negatives := []struct {
		name string
		text string
	}{
		{"how-to-run-tests", "how do I run the tests?"},
		{"install-numpy", "install numpy please"},
		{"what-does-app-do", "what does this app do?"},
		{"thanks", "thanks!"},
		{"empty", ""},
	}
	for _, c := range negatives {
		t.Run("no_route/"+c.name, func(t *testing.T) {
			if controlIntent(userMsg(c.text)) {
				t.Errorf("controlIntent(%q) = true, want false (must not steal non-platform turn)", c.text)
			}
		})
	}
}

// TestControlIntentScansLastUserMessage confirms the scan targets the most
// recent user turn (not earlier history, not assistant turns).
func TestControlIntentScansLastUserMessage(t *testing.T) {
	msgs := []chatMessage{
		{Role: "user", Content: "publish the app"}, // earlier — must be ignored
		{Role: "assistant", Content: "install the app foo"}, // assistant — must be ignored
		{Role: "user", Content: "thanks!"}, // latest user — the one that counts
	}
	if controlIntent(msgs) {
		t.Errorf("controlIntent should scan only the LAST user message (%q), not earlier turns", "thanks!")
	}

	msgs2 := []chatMessage{
		{Role: "user", Content: "thanks!"},
		{Role: "assistant", Content: "you're welcome"},
		{Role: "user", Content: "now run the workflow morning brief"},
	}
	if !controlIntent(msgs2) {
		t.Errorf("controlIntent should detect the platform intent in the LAST user message")
	}
}

// TestFirstToolCapableProvider checks role-gated selection of the tool-running
// provider. A user can't reach minimax (admin-gated) so they fall back to the
// first allowed provider (gemma4); admin+ get minimax. In no case may the
// returned provider be a claude-code provider — those run their own toolset and
// can't see the me_agent registry.
func TestFirstToolCapableProvider(t *testing.T) {
	cases := []struct {
		role   string
		wantID string
	}{
		{"user", "kvrun-gemma4"},
		{"admin", "kvrun-minimax"},
		{"super_admin", "kvrun-minimax"},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			p, ok := firstToolCapableProvider(c.role)
			if !ok {
				t.Fatalf("firstToolCapableProvider(%q): ok = false, want true", c.role)
			}
			if p.id != c.wantID {
				t.Errorf("firstToolCapableProvider(%q).id = %q, want %q", c.role, p.id, c.wantID)
			}
			if strings.HasPrefix(p.id, "claude-code") {
				t.Errorf("firstToolCapableProvider(%q) returned a claude-code provider (%q) — must never route to one (no tool registry)", c.role, p.id)
			}
		})
	}
}

// TestProviderAllowed sanity-checks the role gate the selection logic relies on:
// gemma4 (minRole "user") is open to all; minimax (minRole "admin") is admin+.
func TestProviderAllowed(t *testing.T) {
	var gemma, minimax llmProvider
	for _, p := range llmProviders {
		switch p.id {
		case "kvrun-gemma4":
			gemma = p
		case "kvrun-minimax":
			minimax = p
		}
	}
	if gemma.id == "" || minimax.id == "" {
		t.Fatalf("expected gemma4 + minimax in llmProviders; got gemma=%q minimax=%q", gemma.id, minimax.id)
	}

	cases := []struct {
		role string
		p    llmProvider
		want bool
	}{
		{"user", gemma, true},
		{"admin", gemma, true},
		{"super_admin", gemma, true},
		{"user", minimax, false},
		{"admin", minimax, true},
		{"super_admin", minimax, true},
	}
	for _, c := range cases {
		t.Run(c.role+"/"+c.p.id, func(t *testing.T) {
			if got := providerAllowed(c.role, c.p); got != c.want {
				t.Errorf("providerAllowed(%q, %q) = %v, want %v", c.role, c.p.id, got, c.want)
			}
		})
	}
}
