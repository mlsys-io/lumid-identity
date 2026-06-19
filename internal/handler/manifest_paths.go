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

// ── Bundle-root dual-read: ~/.xp/agents/<name> over legacy ~/.xp/apps/<name> ──
//
// Phase 4 (app -> agent) renames the deployable-unit bundle dir:
//
//	~/.xp/apps/<name>/   ->   ~/.xp/agents/<name>/
//
// Callers throughout the codebase still construct bundle dirs ending in
// ".../apps/<name>". Rather than touch every call site, the bundle-aware path
// resolvers below transparently prefer the canonical ".../agents/<name>"
// sibling when it EXISTS, falling back to the legacy ".../apps/<name>". This
// mirrors the kg_paths.go "agents -> memories" and the dotfile dual-read
// patterns: prefer canonical, fall back to legacy, never move files.
const (
	bundleAgentsDir = "agents" // canonical (Phase 4 target)
	bundleAppsDir   = "apps"   // legacy (read fallback)
)

// bundleRootCandidates returns the appDir plus its dual-read sibling, in
// read-preference order (canonical "agents" first). When appDir's parent dir
// is the legacy "apps", the canonical "agents" sibling is prepended; when it is
// already "agents", the legacy "apps" sibling is appended as a fallback. For
// any other shape it returns just appDir unchanged.
func bundleRootCandidates(appDir string) []string {
	parent := filepath.Dir(appDir)
	base := filepath.Base(appDir)
	switch filepath.Base(parent) {
	case bundleAppsDir:
		agents := filepath.Join(filepath.Dir(parent), bundleAgentsDir, base)
		return []string{agents, appDir} // prefer canonical
	case bundleAgentsDir:
		apps := filepath.Join(filepath.Dir(parent), bundleAppsDir, base)
		return []string{appDir, apps} // canonical first, legacy fallback
	default:
		return []string{appDir}
	}
}

// resolveBundleDir returns the existing bundle dir for appDir, preferring the
// canonical ".../agents/<name>" over legacy ".../apps/<name>". When neither
// exists it returns appDir unchanged so a caller still has a sane default.
func resolveBundleDir(appDir string) string {
	cands := bundleRootCandidates(appDir)
	for _, d := range cands {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return appDir
}

// firstExisting returns the path of the first candidate that exists under
// appDir (or its dual-read bundle-root sibling), plus true. When none exist it
// returns the dotfile (canonical) path under the canonical bundle root with
// false, so a caller that ignores the bool still gets a sane default to attempt
// a read against (the read just misses).
func firstExisting(appDir string, candidates []string) (string, bool) {
	roots := bundleRootCandidates(appDir)
	for _, root := range roots {
		for _, name := range candidates {
			p := filepath.Join(root, name)
			if _, err := os.Stat(p); err == nil {
				return p, true
			}
		}
	}
	// None found: default to the canonical dotfile under the canonical bundle
	// root (first candidate root).
	return filepath.Join(roots[0], candidates[0]), false
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
// file currently exists. The bundle root is resolved dual-read so the write
// lands in the existing ".../agents/<name>" (or legacy ".../apps/<name>")
// bundle rather than creating a phantom sibling.
func SpecWritePath(appDir string) string {
	return filepath.Join(resolveBundleDir(appDir), SpecDotfile)
}

// ManifestWritePath returns the canonical manifest path to WRITE for the
// bundle at appDir — always the ".manifest.json" dotfile. The bundle root is
// resolved dual-read (see SpecWritePath).
func ManifestWritePath(appDir string) string {
	return filepath.Join(resolveBundleDir(appDir), ManifestDotfile)
}
