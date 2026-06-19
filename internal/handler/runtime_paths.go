package handler

// Dual-path resolver for app runtime artifacts during the .lumid/ migration.
//
// Runtime artifacts are moving out of the bundle's legacy "data/" directory
// (and a couple of bundle-root files) into a dedicated ".lumid/" state dir:
//
//	data/cycles       -> .lumid/cycles
//	data/experiments  -> .lumid/experiments
//	data/outbox       -> .lumid/outbox
//	data/inbox        -> .lumid/inbox
//	data/reflections  -> .lumid/reflections
//	data/proposals    -> .lumid/proposals
//	data/control      -> .lumid/control
//	data/journal.jsonl-> .lumid/journal.jsonl
//	data/history.jsonl-> .lumid/history.jsonl
//	data/memories.jsonl-> .lumid/memories.jsonl
//	origin.json       -> .lumid/origin.json
//
// The <name> under .lumid/ is derived by stripping a leading "data/" from the
// legacy relative path; bundle-root files (e.g. "origin.json") keep their name.
// Real datasets like "data/seed" are CONTENT, not runtime artifacts, and must
// NOT be routed through here — they stay under data/.
//
// READS must accept both shapes so a half-migrated install keeps working:
// prefer the canonical ".lumid/<name>" when it EXISTS, else fall back to the
// legacy path. WRITES always target the canonical ".lumid/<name>" (creating
// parent dirs) so new content lands in the migrated shape.
//
// This mirrors the dual-read pattern in manifest_paths.go; route every handler
// that touches these runtime artifacts through here instead of hard-coding
// "data/..." so the migration is enforced in one place.

import (
	"os"
	"path/filepath"
	"strings"
)

// RuntimeStateDir is the canonical per-app runtime state directory.
const RuntimeStateDir = ".lumid"

// canonicalRel maps a legacy relative path to its canonical ".lumid/<name>"
// relative path by stripping a single leading "data/" segment. Paths that are
// not under "data/" (e.g. "origin.json") keep their name under ".lumid/".
func canonicalRel(legacyRel string) string {
	legacyRel = filepath.Clean(legacyRel)
	name := strings.TrimPrefix(legacyRel, "data"+string(filepath.Separator))
	// TrimPrefix is a no-op when legacyRel had no "data/" prefix (bundle-root
	// files like origin.json), so name is just the legacy name in that case.
	return filepath.Join(RuntimeStateDir, name)
}

// ResolveRuntimeReadPath returns the path to READ for a runtime artifact in the
// bundle at appDir. It prefers the canonical ".lumid/<name>" when that path
// EXISTS on disk, otherwise it falls back to the legacy path so existing
// installs keep working. The bool is true when an existing file/dir was found;
// when false the returned path is the legacy path (a read will simply miss).
func ResolveRuntimeReadPath(appDir, legacyRel string) (string, bool) {
	// Bundle-root dual-read (Phase 4 app -> agent): try each bundle-root
	// candidate (canonical ".../agents/<name>" first, legacy ".../apps/<name>"
	// fallback), and within each, prefer the canonical ".lumid/<name>" over the
	// legacy "data/..." path. See manifest_paths.go::bundleRootCandidates.
	roots := bundleRootCandidates(appDir)
	for _, root := range roots {
		canonical := filepath.Join(root, canonicalRel(legacyRel))
		if _, err := os.Stat(canonical); err == nil {
			return canonical, true
		}
		legacy := filepath.Join(root, filepath.Clean(legacyRel))
		if _, err := os.Stat(legacy); err == nil {
			return legacy, true
		}
	}
	// None found: default to the legacy path under the canonical bundle root.
	return filepath.Join(roots[0], filepath.Clean(legacyRel)), false
}

// ResolveRuntimeWritePath returns the canonical ".lumid/<name>" path to WRITE
// for a runtime artifact in the bundle at appDir, regardless of which legacy
// path currently exists. Parent directories are created so the caller can write
// immediately. New runtime writes always land under ".lumid/".
func ResolveRuntimeWritePath(appDir, legacyRel string) (string, error) {
	// Write into the EXISTING bundle root (canonical ".../agents/<name>" when
	// present, else legacy ".../apps/<name>") so runtime artifacts land next to
	// the bundle the rest of the stack reads, not a phantom sibling.
	canonical := filepath.Join(resolveBundleDir(appDir), canonicalRel(legacyRel))
	if err := os.MkdirAll(filepath.Dir(canonical), 0o755); err != nil {
		return "", err
	}
	return canonical, nil
}
