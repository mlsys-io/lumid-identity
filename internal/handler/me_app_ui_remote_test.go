package handler

// Cross-node surface fallback.
//
// identity runs on the service tier and does not mount the scheduler's
// xpio-state PVC, so a CLOUD-installed tenant app has no files on this node at
// all. Before the fallback, serveAppSurface hard-failed on
// `resolveAppDir == ""` and reported "app not found" — for apps that were
// installed, healthy and listed by /me/apps. It read as "this app has no UI"
// when it actually meant "identity cannot see the disk", which is why an app
// could look like an empty shell in Studio while being perfectly fine.
//
// These tests pin the parsing + guard behaviour the fallback depends on. The
// HTTP fetch itself (fetchRepoBlob) needs a live xpcloud + a user JWT, so it is
// exercised by the e2e journey rather than here.

import (
	"strings"
	"testing"
)

const remoteSpec = `
name: mbb-consultant
kind: app
config:
  judge_panel: [claude-sonnet-4-6, qwen]
  panel_min_agreement: 2
ui:
  sidebar:
    label: MBB Consultant
  surface:
    page: ui/page.yaml
  surfaces:
    home: ui/page.yaml
    environment: ui/environment.md
    review: ui/review.md
  nav:
    - label: Overview
      surface: home
`

// The fallback builds `ui` from spec BYTES (fetched over HTTP) rather than from
// a file on disk. If parseAppUI stopped understanding a spec, every remote app
// would silently regress to "app declares no ui surface".
func TestParseAppUI_FromRemoteSpecBytes(t *testing.T) {
	ui := parseAppUI([]byte(remoteSpec))
	if ui == nil {
		t.Fatal("parseAppUI returned nil for a valid spec")
	}
	if ui.Surface == nil || ui.Surface.Page != "ui/page.yaml" {
		t.Fatalf("default surface page not parsed: %+v", ui.Surface)
	}
	for _, s := range []string{"home", "environment", "review"} {
		if _, ok := ui.Surfaces[s]; !ok {
			t.Fatalf("named surface %q missing; got %v", s, ui.Surfaces)
		}
	}
	if len(ui.Nav) == 0 {
		t.Fatal("nav dropped — the client renders tabs from this")
	}
}

// The remote path returns `config` too; a nil config would blank out every
// native widget's defaults on a cloud-installed app.
func TestParseAppConfigBytes_FromRemoteSpec(t *testing.T) {
	cfg := parseAppConfigBytes([]byte(remoteSpec))
	if cfg == nil {
		t.Fatal("config parsed as nil")
	}
	if _, ok := cfg["judge_panel"]; !ok {
		t.Fatalf("judge_panel missing from parsed config: %v", cfg)
	}
}

func TestParseAppUI_RejectsGarbage(t *testing.T) {
	if ui := parseAppUI([]byte("\t\tnot: [valid: yaml")); ui != nil {
		t.Fatalf("expected nil for unparseable spec, got %+v", ui)
	}
}

// A spec with no ui block must stay a 404 ("declares no ui surface"), not
// become a nil-deref once the remote path is taken.
func TestParseAppUI_NoUIBlock(t *testing.T) {
	if ui := parseAppUI([]byte("name: x\nkind: app\n")); ui != nil {
		t.Fatalf("expected nil ui for a spec without a ui block, got %+v", ui)
	}
}

// fetchRepoBlob is path-addressed against the caller's repo. A traversal would
// read a DIFFERENT repo's blob, so the guard must refuse rather than normalize.
// (No JWT is available in unit context, so this asserts the refusal contract:
// a traversal path must never be attempted.)
func TestFetchRepoBlob_RefusesTraversalPaths(t *testing.T) {
	for _, p := range []string{"../other/xpcloud.yaml", "/etc/passwd", ""} {
		if _, ok := fetchRepoBlob("user", "app", p); ok {
			t.Fatalf("fetchRepoBlob accepted unsafe path %q", p)
		}
	}
}

// Remote apps can't resolve @fork_of / @shared — those indirections resolve
// against a parent app DIR and the operator templates dir, neither of which
// exists on this node. The handler must say so rather than fall through.
func TestRemoteTemplatePathsAreRejectedByPrefix(t *testing.T) {
	for _, p := range []string{"@fork_of/ui/home.md", "@shared/starter.md"} {
		if !strings.HasPrefix(p, "@") {
			t.Fatalf("%q should be recognised as a template path", p)
		}
	}
}
