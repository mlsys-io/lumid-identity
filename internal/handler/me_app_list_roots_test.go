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
