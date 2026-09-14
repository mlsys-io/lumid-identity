package handler

// An empty result that means OUTAGE must not read like an empty result that
// means "nothing yet". They are opposite answers — one says wait, the other
// says waiting will not help — and every runtime-artifact handler on this pod
// returned the first while meaning the second.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeArtifactsReachable(t *testing.T) {
	if runtimeArtifactsReachable("") {
		t.Error("an empty appDir cannot be reachable")
	}
	// A bundle with NO runtime tree — exactly what materialiseTenantApp
	// produces on a pod: the published files, none of the runtime ones. This is
	// the case that must read as unreachable, because it is the one that looked
	// like an app that had never run.
	bundle := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bundle, "prompts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(bundle, "xpcloud.yaml"), []byte("name: demo\n"), 0o644)
	if runtimeArtifactsReachable(bundle) {
		t.Error("a published bundle with no cycles/journal reported itself reachable")
	}

	// The same bundle once a runtime tree exists.
	if err := os.MkdirAll(filepath.Join(bundle, ".lumid", "cycles"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !runtimeArtifactsReachable(bundle) {
		t.Error("a bundle with a cycles dir reported itself unreachable")
	}
}

func TestUnavailableReasonIsSilentWhenTheEmptinessIsGenuine(t *testing.T) {
	bundle := t.TempDir()
	os.MkdirAll(filepath.Join(bundle, ".lumid", "cycles"), 0o755)
	if why := unavailableReason(bundle, "the transcript"); why != "" {
		t.Errorf("a readable-but-empty tree must say nothing, got %q", why)
	}
}

func TestUnavailableReasonNamesTheArtifactAndTheCause(t *testing.T) {
	why := unavailableReason(t.TempDir(), "this cycle's LLM transcript")
	if why == "" {
		t.Fatal("an unreachable tree produced no reason")
	}
	if !strings.Contains(why, "this cycle's LLM transcript") {
		t.Error("the reason does not say WHAT is missing")
	}
	if !strings.Contains(why, "does not mount") {
		t.Error("the reason does not say WHY; 'not available' alone sends the reader debugging their app")
	}
	// And it must point at what DOES work, or the reader concludes nothing does.
	if !strings.Contains(why, "run store") {
		t.Error("the reason does not say what is still available")
	}
}
