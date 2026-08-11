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

// The mount target and repo slug are both interpolated into filesystem paths
// under the staging dir, and both come from a spec the app author controls.
func TestParseMountedDatasets(t *testing.T) {
	spec := []byte(`
datasets:
  - id: cases_v1
    repo: 70f192ce-owner/mbb-ai-cases
    mount_at: data/seed
  - id: local_only
    local_path: data/seed
  - id: traversal
    repo: owner/x
    mount_at: ../../etc
  - id: absolute
    repo: owner/x
    mount_at: /etc
  - id: bad_repo
    repo: too/many/segments
    mount_at: data/x
  - id: no_mount
    repo: owner/x
`)
	got := parseMountedDatasets(spec)
	if len(got) != 1 {
		t.Fatalf("want exactly the one valid mount, got %d: %+v", len(got), got)
	}
	if got[0].repo != "70f192ce-owner/mbb-ai-cases" || got[0].mountAt != "data/seed" {
		t.Fatalf("unexpected mount: %+v", got[0])
	}
	if len(parseMountedDatasets([]byte("\t\tnot: [yaml"))) != 0 {
		t.Fatal("unparseable spec must yield no mounts")
	}
}

// A dataset repo must keep records under a directory (the publisher drops
// root-level .json), so mounting its tree verbatim buries them one level below
// where consumers glob. Stripping the shared top dir is what makes
// "mount this dataset at data/seed" mean what an app author expects.
func TestCommonTopDir(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"all under one dir", []string{"data/a.json", "data/b.json"}, "data"},
		{"marker at root is ignored", []string{".xpcloud.yaml", "data/a.json"}, "data"},
		{"a record at root -> no strip", []string{"a.json", "data/b.json"}, ""},
		{"two top dirs -> no strip", []string{"data/a.json", "other/b.json"}, ""},
		{"nested deeper still strips one", []string{"data/x/a.json", "data/y/b.json"}, "data"},
		{"empty", nil, ""},
	} {
		if got := commonTopDir(tc.in); got != tc.want {
			t.Fatalf("%s: commonTopDir(%v) = %q want %q", tc.name, tc.in, got, tc.want)
		}
	}
}
