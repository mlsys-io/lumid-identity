package handler

// Dual-read resolver for app/repo bundle metadata paths during the
// dotfile migration.
//
// Canonical platform files are migrating to dot-prefixed names:
//
//	xpcloud.yaml                -> .xpcloud.yaml      (runtime spec, source of truth)
//	manifest.yaml/manifest.json -> .manifest.json    (static metadata mirror)
//
// READS must accept both shapes so a half-migrated host keeps working:
// prefer the dotfile, fall back to the legacy name(s), return whichever
// EXISTS on disk. WRITES always target the canonical dotfile so new
// content lands in the migrated shape.
//
// Every other handler that touches these files (me_casebook,
// me_workflows, me_agent_agents, me_agent_helpers, admin_loops, ...)
// should route through here instead of hard-coding "xpcloud.yaml" /
// "manifest.json" so the migration is enforced in one place.

import (
	"os"
	"path/filepath"
)

// Canonical dot-prefixed names — the migration targets, used for WRITES.
const (
	SpecDotfile     = ".xpcloud.yaml"
	ManifestDotfile = ".manifest.json"
)

// Search order for READS: dotfile first, then legacy name(s). The first
// entry of each list is the canonical write target.
var (
	specCandidates     = []string{SpecDotfile, "xpcloud.yaml"}
	manifestCandidates = []string{ManifestDotfile, "manifest.json", "manifest.yaml"}
)

// firstExisting returns the path of the first candidate that exists under
// appDir, plus true. When none exist it returns the dotfile (canonical)
// path with false, so a caller that ignores the bool still gets a sane
// default to attempt a read against (the read just misses).
func firstExisting(appDir string, candidates []string) (string, bool) {
	for _, name := range candidates {
		p := filepath.Join(appDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return filepath.Join(appDir, candidates[0]), false
}

// ResolveSpecPath returns the runtime spec (xpcloud) path to READ for the
// bundle at appDir, preferring ".xpcloud.yaml" over legacy "xpcloud.yaml".
// The bool is true when an existing file was found; when false the returned
// path is the canonical dotfile (a read will simply miss).
func ResolveSpecPath(appDir string) (string, bool) {
	return firstExisting(appDir, specCandidates)
}

// ResolveManifestPath returns the manifest path to READ for the bundle at
// appDir, preferring ".manifest.json" over legacy "manifest.json" /
// "manifest.yaml". The bool is true when an existing file was found.
func ResolveManifestPath(appDir string) (string, bool) {
	return firstExisting(appDir, manifestCandidates)
}

// SpecWritePath returns the canonical spec path to WRITE for the bundle at
// appDir — always the ".xpcloud.yaml" dotfile, regardless of which legacy
// file currently exists.
func SpecWritePath(appDir string) string {
	return filepath.Join(appDir, SpecDotfile)
}

// ManifestWritePath returns the canonical manifest path to WRITE for the
// bundle at appDir — always the ".manifest.json" dotfile.
func ManifestWritePath(appDir string) string {
	return filepath.Join(appDir, ManifestDotfile)
}
