package handler

// The materialiser writes files whose paths come from a REMOTE tree listing, on
// behalf of one tenant, into a shared cache root. Both of those are reasons to
// pin the guards: a name that escapes the cache dir would let one tenant's
// bundle overwrite another's, and the TTL is what stops a single chat turn
// refetching the whole bundle once per tool call.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaterialiseRejectsUnsafeIdentifiers(t *testing.T) {
	// No network happens for any of these — they must be rejected on shape
	// alone, before a JWT is minted or a request is made.
	for _, tc := range []struct{ sub, app string }{
		{"sub", "../escape"},
		{"sub", "a/b"},
		{"../victim", "app"},
		{"sub/x", "app"},
		{"", "app"},
		{"sub", ""},
	} {
		if got := materialiseTenantApp(tc.sub, tc.app); got != "" {
			t.Fatalf("materialiseTenantApp(%q,%q) = %q, want \"\"", tc.sub, tc.app, got)
		}
	}
}

func TestCacheFreshHonoursTTL(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, tenantCacheMarker)

	if cacheFresh(dir) {
		t.Fatal("a dir with no marker must not read as fresh")
	}
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !cacheFresh(dir) {
		t.Fatal("a just-written marker must read as fresh")
	}
	// Age it past the TTL.
	old := time.Now().Add(-tenantCacheTTL - time.Minute)
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}
	if cacheFresh(dir) {
		t.Fatal("a marker older than the TTL must not read as fresh")
	}
}

// The cache root is shared across tenants, so one tenant's path must never
// resolve inside another's.
func TestCacheDirIsTenantScoped(t *testing.T) {
	a := tenantCacheDir("sub-a", "app")
	b := tenantCacheDir("sub-b", "app")
	if a == b {
		t.Fatal("two tenants resolved to the same cache dir")
	}
	for _, d := range []string{a, b} {
		if !strings.HasPrefix(d, tenantCacheRoot()+string(os.PathSeparator)) {
			t.Fatalf("%q escaped the cache root", d)
		}
	}
}

// resolveAppDir must still prefer a REAL local bundle; the cache is a last
// resort. A regression here would serve a stale copy of an app that is present
// on disk.
func TestResolveAppDirPrefersLocalOverCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	app := "local-app"
	real := filepath.Join(home, ".xp", "apps", app)
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := resolveAppDir("some-sub", app); got != real {
		t.Fatalf("resolveAppDir = %q, want the local bundle %q", got, real)
	}
}

// Path traversal is rejected by resolveAppDir itself, before the cache is
// consulted — the shared sink, not each of the 39 callers.
func TestResolveAppDirRejectsTraversal(t *testing.T) {
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	for _, app := range []string{"../other", "a/b", "..", ""} {
		if got := resolveAppDir("sub", app); got != "" {
			t.Fatalf("resolveAppDir(%q) = %q, want \"\"", app, got)
		}
	}
}
