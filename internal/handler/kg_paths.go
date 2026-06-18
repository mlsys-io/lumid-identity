package handler

// Dual-path resolver for KG knowledge-bank directories during the
// "agents -> memories" rename.
//
// A knowledge bank is just the memory of an agent, so the on-disk store is
// migrating:
//
//	~/.xp/kg/agents/<id>/   ->   ~/.xp/kg/memories/<id>/
//
// The operator handles the actual data move plus a transition symlink
// separately; this code MUST NOT move files. It only resolves which path to
// touch:
//
//	READS prefer ~/.xp/kg/memories/<id> when it exists, falling back to the
//	legacy ~/.xp/kg/agents/<id> so a half-migrated host keeps working.
//	WRITES always target the canonical ~/.xp/kg/memories/<id>.
//
// Every handler that touches a bank dir should route through here instead of
// hard-coding "agents" / "memories" so the migration is enforced in one place.

import (
	"os"
	"path/filepath"
)

// Sub-directory names under ~/.xp/kg. The first entry is the canonical write
// target; the rest are legacy names accepted on READ.
const (
	kgMemoriesDir = "memories" // canonical (write target)
	kgAgentsDir   = "agents"   // legacy (read fallback)
)

// xpRoot returns the ~/.xp state root. It resolves via $HOME; the legacy
// ~/.xp symlink (or real dir) is expected to already be in place on the host.
// Falls back to a literal "~/.xp" only when $HOME is unset (degraded, but
// keeps callers total).
func xpRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if home = os.Getenv("HOME"); home == "" {
			return filepath.Join("~", ".xp")
		}
	}
	return filepath.Join(home, ".xp")
}

// KGRoot returns the KG root directory to READ, preferring
// ~/.xp/kg/memories over the legacy ~/.xp/kg/agents. The bool is true when an
// existing directory was found; when false the returned path is the canonical
// "memories" root (a read will simply miss).
func KGRoot() (string, bool) {
	base := filepath.Join(xpRoot(), "kg")
	for _, sub := range []string{kgMemoriesDir, kgAgentsDir} {
		p := filepath.Join(base, sub)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p, true
		}
	}
	return filepath.Join(base, kgMemoriesDir), false
}

// KGBankDir returns the bank directory to READ for the given agent/memory id,
// preferring ~/.xp/kg/memories/<id> over the legacy ~/.xp/kg/agents/<id>. The
// bool is true when an existing directory was found; when false the returned
// path is the canonical memories path (a read will simply miss).
func KGBankDir(agentID string) (string, bool) {
	base := filepath.Join(xpRoot(), "kg")
	for _, sub := range []string{kgMemoriesDir, kgAgentsDir} {
		p := filepath.Join(base, sub, agentID)
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p, true
		}
	}
	return filepath.Join(base, kgMemoriesDir, agentID), false
}

// KGBankWriteDir returns the canonical bank directory to WRITE for the given
// agent/memory id — always ~/.xp/kg/memories/<id> — and ensures its parent
// directories exist (MkdirAll). It returns the path and any mkdir error.
func KGBankWriteDir(agentID string) (string, error) {
	dir := filepath.Join(xpRoot(), "kg", kgMemoriesDir, agentID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return dir, err
	}
	return dir, nil
}
