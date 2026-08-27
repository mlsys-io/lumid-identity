package handler

import (
	"path/filepath"
	"strings"
	"testing"
)

// The list endpoints walked only the first two roots, so a cloud tenant whose
// apps live in the materialised cache saw an empty inventory — and the chat
// told them they had no apps installed. Order matters as much as membership:
// it must match resolveAppDir, or a per-app read and a list of apps would
// disagree about which copy of a same-named app is authoritative.
func TestAppListRootsOrderMatchesResolveAppDir(t *testing.T) {
	roots := appListRoots("sub-123")
	if len(roots) != 3 {
		t.Fatalf("want 3 roots, got %d: %v", len(roots), roots)
	}
	if roots[0] != tenantAppsDir("sub-123") {
		t.Errorf("root[0] must be the caller's tenant install, got %q", roots[0])
	}
	if !strings.HasSuffix(filepath.ToSlash(roots[1]), "/.xp/apps") {
		t.Errorf("root[1] must be the operator-shared bundles, got %q", roots[1])
	}
	// The cache is LAST, exactly as resolveAppDir falls back to it last: a
	// materialised copy must never shadow a real local bundle.
	if roots[2] != filepath.Join(tenantCacheRoot(), "sub-123") {
		t.Errorf("root[2] must be this user's materialised cache, got %q", roots[2])
	}
}

// The cache root is per-user. Leaking another tenant's directory into the scan
// would list their apps to the caller.
func TestAppListRootsCacheIsPerUser(t *testing.T) {
	a := appListRoots("sub-aaa")
	b := appListRoots("sub-bbb")
	if a[2] == b[2] {
		t.Fatalf("cache root must differ per user, both were %q", a[2])
	}
	if !strings.Contains(a[2], "sub-aaa") || strings.Contains(a[2], "sub-bbb") {
		t.Errorf("cache root for sub-aaa is wrong: %q", a[2])
	}
}

// installedAppNames drives materialisation, so its newest-intent-wins decision
// is what keeps a list endpoint from resurrecting an uninstalled app or hiding
// a live one. Same rule as cardsFromIntents; tested here without a DB by
// exercising the decision on ordered rows.
func TestInstalledAppNamesDecision(t *testing.T) {
	// Mirrors the loop in installedAppNames: rows are newest-first.
	decide := func(rows []struct {
		name, action, status string
	}) []string {
		seen := map[string]bool{}
		var out []string
		for _, r := range rows {
			if r.name == "" || seen[r.name] {
				continue
			}
			seen[r.name] = true
			if r.action == "uninstall" && r.status != "failed" {
				continue
			}
			out = append(out, r.name)
		}
		return out
	}
	type row = struct{ name, action, status string }

	got := decide([]row{{"a", "install", "done"}})
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("plain install should be listed, got %v", got)
	}
	// Newest is an uninstall — the older install must not resurrect it.
	got = decide([]row{{"a", "uninstall", "done"}, {"a", "install", "done"}})
	if len(got) != 0 {
		t.Errorf("uninstalled app must not be listed, got %v", got)
	}
	// A FAILED uninstall means the app is still there; hiding it would strand
	// the user with no way to retry.
	got = decide([]row{{"a", "uninstall", "failed"}, {"a", "install", "done"}})
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("failed uninstall should keep the app listed, got %v", got)
	}
	// Reinstalled after an uninstall: newest wins again.
	got = decide([]row{{"a", "install", "done"}, {"a", "uninstall", "done"}})
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("reinstall should win over the older uninstall, got %v", got)
	}
}
