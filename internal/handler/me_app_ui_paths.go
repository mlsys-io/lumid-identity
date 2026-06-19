package handler

// Dual-read resolution for an app bundle's UI directory.
//
// A ui/→.ui/ migration renames the canonical UI directory to the dotfile
// ".ui/", but existing tenant installs still carry a legacy "ui/". Both must
// work, so READS prefer ".ui/" and fall back to legacy "ui/", while WRITES go
// to the canonical ".ui/" (matching the xpcloud.yaml/manifest.json dotfile
// convention in manifest_paths.go).

import (
	"os"
	"path/filepath"
)

const (
	uiDirDotted = ".ui" // canonical UI directory (dotfile)
	uiDirLegacy = "ui"  // legacy UI directory (pre-migration)
)

// appUIDir returns the UI directory to READ for the bundle at appDir: the
// canonical ".ui/" if it exists, else legacy "ui/" if THAT exists, else the
// canonical ".ui/" (so a fresh read simply misses and a fresh write lands in
// the dotfile). Robust to a missing/odd appDir — os.Stat errors fall through.
func appUIDir(appDir string) string {
	dotted := filepath.Join(appDir, uiDirDotted)
	if st, err := os.Stat(dotted); err == nil && st.IsDir() {
		return dotted
	}
	legacy := filepath.Join(appDir, uiDirLegacy)
	if st, err := os.Stat(legacy); err == nil && st.IsDir() {
		return legacy
	}
	return dotted
}

// appUIFile returns the path to a named file inside the resolved UI directory
// (canonical ".ui/" preferred, legacy "ui/" fallback). For reads that should
// try both regardless of which dir exists, use readAppUIFile instead.
func appUIFile(appDir, name string) string {
	return filepath.Join(appUIDir(appDir), name)
}

// readAppUIFile reads a UI file by name, trying ".ui/<name>" first and falling
// back to legacy "ui/<name>". Returns the bytes from whichever exists; if
// neither does, returns the error from the legacy attempt.
func readAppUIFile(appDir, name string) ([]byte, error) {
	if b, err := os.ReadFile(filepath.Join(appDir, uiDirDotted, name)); err == nil {
		return b, nil
	}
	return os.ReadFile(filepath.Join(appDir, uiDirLegacy, name))
}

// appUIWriteDir returns the canonical ".ui/" directory for the bundle at
// appDir — always the dotfile, regardless of which legacy dir exists. Used for
// NEW writes (generated page.yaml/home.md) so freshly-generated UI lands in
// ".ui/". Pair with appUIWriteRef for the xpcloud.yaml surface reference.
func appUIWriteDir(appDir string) string {
	return filepath.Join(appDir, uiDirDotted)
}

// appUIWriteRef returns the bundle-relative surface reference to persist into
// xpcloud.yaml for a file written via appUIWriteDir — always dotted
// (".ui/<name>").
func appUIWriteRef(name string) string {
	return uiDirDotted + "/" + name
}
