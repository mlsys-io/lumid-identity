package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A non-admin's chat reads its own installed app by name (2026-11-28: the
// Quant Research researcher's chat could not read notes/bar_backtest.md).
func TestReadFileOwnInstalledApp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	user := "u-123"
	app := filepath.Join(tenantAppsDir(user), "quant-research")
	for rel, body := range map[string]string{
		"notes/bar_backtest.md": "spec language",
		".xpcloud.yaml":         "name: quant-research\n",
		".lumid/secret.json":    "{}",
		".env":                  "TOKEN=x",
	} {
		p := filepath.Join(app, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The operator's copy holds runtime state; a user must not reach it by name.
	op := filepath.Join(home, ".xp", "apps", "operator-only", "notes.md")
	_ = os.MkdirAll(filepath.Dir(op), 0o755)
	_ = os.WriteFile(op, []byte("operator"), 0o644)

	res, ok := toolReadFile(user, "user", "quant-research/notes/bar_backtest.md")
	if !ok || res["content"] != "spec language" {
		t.Fatalf("own app file: ok=%v res=%v", ok, res)
	}
	res, ok = toolReadFile(user, "user", "quant-research/")
	if !ok || res["is_dir"] != true {
		t.Fatalf("own app listing: ok=%v res=%v", ok, res)
	}
	for _, p := range []string{
		"quant-research/.lumid/secret.json",
		"quant-research/.env",
		"quant-research/../../other/.xp/apps/x",
		"operator-only/notes.md",
	} {
		if r, ok := toolReadFile(user, "user", p); ok {
			t.Errorf("%s must not be readable, got %v", p, r)
		} else if c, _ := r["content"].(string); strings.Contains(c, "operator") {
			t.Errorf("%s leaked operator content", p)
		}
	}
}
