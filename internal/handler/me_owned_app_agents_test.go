package handler

import (
	"os"
	"path/filepath"
	"testing"
)

// 2026-09-27: resolveOwnedAppDir looked only in the tenant's .xp/apps, so an
// owner's own `kind: agent` install (.xp/agents/<app>) read as not-owned and
// every owner write (prompts, config, UI) failed 1403 "operator-shared".
func TestOwnedAppDirFindsAgentKindInstalls(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	sub := "tenant-under-test"
	agentDir := filepath.Join(home, ".tenants", sub, ".xp", "agents", "quant-research")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, owned, shared := resolveOwnedAppDir(sub, "quant-research")
	if !owned || shared || dir != agentDir {
		t.Fatalf("agent-kind install not owned: dir=%q owned=%v shared=%v", dir, owned, shared)
	}
	// the legacy apps/ layout still resolves
	appDir := filepath.Join(home, ".tenants", sub, ".xp", "apps", "legacy-app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, owned, _ := resolveOwnedAppDir(sub, "legacy-app"); !owned || dir != appDir {
		t.Fatalf("legacy apps/ install broke: dir=%q owned=%v", dir, owned)
	}
	// and traversal is still refused
	if _, owned, _ := resolveOwnedAppDir(sub, "../x"); owned {
		t.Fatal("traversal accepted")
	}
}
