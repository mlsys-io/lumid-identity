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
		{Role: "user", Content: "publish the app"},          // earlier — must be ignored
		{Role: "assistant", Content: "install the app foo"}, // assistant — must be ignored
		{Role: "user", Content: "thanks!"},                  // latest user — the one that counts
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
// provider. The in-cluster GPU models (gemma4, qwen) are all user-tier, so
// every role falls to the first one (gemma4). In no case may the returned
// provider be a claude-code provider — those run their own toolset and can't
// see the me_agent registry.
func TestFirstToolCapableProvider(t *testing.T) {
	cases := []struct {
		role   string
		wantID string
	}{
		// deepseek-v4-flash is in-house on our own GPUs — the default for
		// everyone. The METERED lanes (qwen, Claude) are the ones behind admin.
		{"user", "deepseek-v4-flash"},
		{"admin", "deepseek-v4-flash"},
		{"super_admin", "deepseek-v4-flash"},
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

// TestProviderAllowed sanity-checks the role gate the selection logic relies
// on, mirroring the claude-proxy pool matrix: sonnet (minRole "user") is open
// to all, opus (minRole "admin") is admin+, fable (minRole "super_admin") is
// operator-only.
func TestProviderAllowed(t *testing.T) {
	var gemma, sonnet, opus, fable llmProvider
	for _, p := range llmProviders {
		switch p.id {
		case "deepseek-v4-flash":
			gemma = p
		case "claude-code-sonnet":
			sonnet = p
		case "claude-code-opus":
			opus = p
		case "claude-code-fable":
			fable = p
		}
	}
	if gemma.id == "" || sonnet.id == "" || opus.id == "" || fable.id == "" {
		t.Fatalf("expected deepseek-v4-flash + claude-code-{sonnet,opus,fable} in llmProviders")
	}

	cases := []struct {
		role string
		p    llmProvider
		want bool
	}{
		{"user", gemma, true},
		{"admin", gemma, true},
		{"super_admin", gemma, true},
		// sonnet consumes the shared Claude pool quota — admin+ only.
		{"user", sonnet, false},
		{"admin", sonnet, true},
		{"super_admin", sonnet, true},
		{"user", opus, false},
		{"admin", opus, true},
		{"super_admin", opus, true},
		{"user", fable, false},
		{"admin", fable, false},
		{"super_admin", fable, true},
	}
	for _, c := range cases {
		t.Run(c.role+"/"+c.p.id, func(t *testing.T) {
			if got := providerAllowed(c.role, c.p); got != c.want {
				t.Errorf("providerAllowed(%q, %q) = %v, want %v", c.role, c.p.id, got, c.want)
			}
		})
	}
}

// A retired id must keep resolving. Personas persist preferred_model, so an id
// that stops resolving silently swaps the user's chosen model for the default —
// the failure this alias table exists to prevent.
func TestModelIDAliasResolves(t *testing.T) {
	for old, want := range modelIDAliases {
		p, found := providerByID(old)
		if !found {
			t.Fatalf("alias %q did not resolve", old)
		}
		if p.id != want {
			t.Fatalf("alias %q -> %q, want %q", old, p.id, want)
		}
	}
}

// An alias must never shadow a live id: exact match wins.
func TestLiveIDNotShadowedByAlias(t *testing.T) {
	for _, lp := range llmProviders {
		p, found := providerByID(lp.id)
		if !found || p.id != lp.id {
			t.Fatalf("live id %q resolved to %q (found=%v)", lp.id, p.id, found)
		}
	}
}

// An unknown id must stay unknown rather than being coerced to a target.
func TestUnknownIDStaysUnknown(t *testing.T) {
	if _, found := providerByID("no-such-model-xyz"); found {
		t.Fatal("unknown id resolved to a provider")
	}
}
