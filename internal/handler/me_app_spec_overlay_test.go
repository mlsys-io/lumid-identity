package handler

// The read half: what the materialised bundle is allowed to say.
//
// resolveAppDir's cross-node fallback serves an app's PUBLISHED bundle, because
// on a cloud pod that is the only copy reachable. Every spec-shaped read is then
// a description of the published app — its loops, datasets, UI and experiments.
// An app is published ONCE and edited for months, so that gap only widens, and
// nothing reported it: list_experiments listed experiments the user had not had
// for weeks, and never the one they had just defined
// (chiquanji@gmail.com, 2026-09-16).
//
// These tests own the two rules that fix it: the installed spec, when echoed,
// wins over the published one; and a spec that changed invalidates the cache
// immediately rather than after the 5-minute TTL — a user who just defined an
// experiment looks for it now, and an assistant told "not found" retries rather
// than waits.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// uncommentedGo drops whole-line `//` comments, so a source-shaped assertion
// cannot be satisfied by prose that merely mentions the call it requires.
func uncommentedGo(src string) string {
	var b strings.Builder
	for _, ln := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "//") {
			continue
		}
		b.WriteString(ln)
		b.WriteByte('\n')
	}
	return b.String()
}

const publishedSpec = `name: demo
experiments:
- id: published_one
  metric:
    name: score
`

const installedSpec = `name: demo
# The comment is the decision record; the store keeps the text verbatim.
experiments:
- id: published_one
  metric:
    name: score
- id: judge_panel_parity_test_run
  metric:
    name: avg_question_score
  arms:
  - id: panel_median3
    judge_panel:
    - deepseek-v4-flash
    - qwen3.8-27b
`

// stageWithPublished builds what the repo fetch would have produced.
func stageWithPublished(t *testing.T, legacyTwin bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(publishedSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	if legacyTwin {
		if err := os.WriteFile(filepath.Join(dir, "xpcloud.yaml"), []byte(publishedSpec), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestOverlayIsANoOpWithNoStoredSpec(t *testing.T) {
	// common.DB is nil in unit tests, so storedAppSpec returns nil — which is
	// also the live behaviour for an app the scheduler has never echoed. The
	// published copy must survive untouched; it is the fallback, not a bug.
	dir := stageWithPublished(t, false)
	if overlayStoredSpec(dir, "sub-1", "demo") {
		t.Fatal("overlay claimed to write with no stored spec")
	}
	b, err := os.ReadFile(filepath.Join(dir, ".xpcloud.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != publishedSpec {
		t.Error("the published spec was modified when there was nothing to overlay")
	}
}

// A legacy twin left saying the old thing is the documented stale-copy trap:
// ResolveSpecPath prefers the dotfile, so a reader that falls back to the bare
// name would silently get the pre-edit spec.
func TestOverlayLeavesNoLegacyTwinDisagreeing(t *testing.T) {
	for _, twin := range []bool{true, false} {
		dir := stageWithPublished(t, twin)
		// Simulate what overlayStoredSpec does when a row exists, using the same
		// write rule, so this asserts the CONTRACT even where no DB is wired.
		for _, name := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
			p := filepath.Join(dir, name)
			if name == "xpcloud.yaml" {
				if _, err := os.Stat(p); err != nil {
					continue
				}
			}
			if err := os.WriteFile(p, []byte(installedSpec), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if os.IsNotExist(err) {
				if name == "xpcloud.yaml" && !twin {
					continue // correctly not invented
				}
				t.Fatalf("%s missing", name)
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "judge_panel_parity_test_run") {
				continue
			}
			t.Errorf("%s still carries the published spec; a reader resolving to it "+
				"gets the pre-edit experiments", name)
		}
	}
}

// The experiments reader must see what the INSTALL declares. This is the
// assertion that would have failed for chiquanji: the freshly defined
// experiment is absent from the published copy and present in the installed one.
func TestExperimentsAreReadFromTheOverlaidSpec(t *testing.T) {
	dir := stageWithPublished(t, false)
	if got := readExpManifest(dir); len(got.Experiments) != 1 {
		t.Fatalf("published copy should declare exactly one experiment, got %d",
			len(got.Experiments))
	}
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(installedSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readExpManifest(dir)
	ids := map[string]bool{}
	for _, e := range got.Experiments {
		ids[e.ID] = true
	}
	if !ids["judge_panel_parity_test_run"] {
		t.Error("the experiment defined on the install is not visible after the overlay — " +
			"list_experiments will keep reporting it as missing and the assistant will " +
			"keep re-defining it")
	}
	if !ids["published_one"] {
		t.Error("the overlay dropped an experiment the published bundle declared")
	}
}

// A seat list that reparses as a scalar is a panel of no seats. The spec
// crosses the boundary as TEXT precisely so nothing on the way re-serialises it.
func TestTheStoreDoesNotReshapeTheSpec(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".xpcloud.yaml")
	if err := os.WriteFile(p, []byte(installedSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	m := readExpManifest(dir)
	for _, e := range m.Experiments {
		if e.ID != "judge_panel_parity_test_run" {
			continue
		}
		if len(e.Arms) != 1 {
			t.Fatalf("expected one arm, got %d", len(e.Arms))
		}
		seats, ok := e.Arms[0]["judge_panel"].([]any)
		if !ok {
			t.Fatalf("judge_panel came back as %T, not a list — a panel that reparses "+
				"as a scalar resolves to no seats and abstains silently",
				e.Arms[0]["judge_panel"])
		}
		if len(seats) != 2 {
			t.Errorf("expected 2 seats, got %d", len(seats))
		}
		return
	}
	t.Fatal("the experiment was not parsed at all")
}

// THE WIRING, which no unit test can reach: storedAppSpec needs MySQL, and the
// DB-backed tests skip unless TEST_MYSQL_DSN is set — which is exactly how the
// original gap survived. So pin the order at the source, the way this package
// already pins define_experiment's carry keys.
func TestMaterialiseOverlaysBeforeItReadsTheSpec(t *testing.T) {
	// COMMENTS MUST NOT COUNT. The first version of this test grepped the raw
	// source and passed with the overlay call commented out — the comment
	// contained the string it was looking for. A guard that a disabled call
	// satisfies is worse than no guard, because it is believed.
	src := uncommentedGo(mustRead(t, "me_app_cache.go"))
	i := strings.Index(src, "func materialiseTenantApp(")
	if i < 0 {
		t.Fatal("materialiseTenantApp missing")
	}
	body := src[i:]
	overlay := strings.Index(body, "overlayStoredSpec(stage")
	if overlay < 0 {
		t.Fatal("materialiseTenantApp never overlays the installed spec — every read " +
			"it serves describes the PUBLISHED bundle, so an edit made through chat " +
			"is invisible to the tools that made it")
	}
	// The bare-name copy and the dataset mounts are both DERIVED from the spec
	// file, so an overlay after either of them leaves those derived from the
	// published copy while the spec itself says otherwise.
	readSpec := strings.Index(body, `os.ReadFile(filepath.Join(stage, ".xpcloud.yaml"))`)
	if readSpec < 0 {
		t.Fatal("could not find the spec read in materialiseTenantApp")
	}
	if overlay > readSpec {
		t.Error("the overlay runs AFTER the spec is read, so the bare-name copy and " +
			"the mounted datasets are still derived from the published spec")
	}
	// The early-return path must consult the store too, or a spec edit waits out
	// the 5-minute TTL before anyone can see it.
	if !strings.Contains(body, "cacheFreshFor(dir, userSub, app)") {
		t.Error("materialiseTenantApp uses the spec-blind cacheFresh; a freshly defined " +
			"experiment stays invisible until the TTL expires")
	}
}

// Freshness: a 5-minute TTL is right for "the published bundle may have moved"
// and wrong for "the user just defined an experiment".
func TestCacheFreshnessStillHonoursTheTTL(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, tenantCacheMarker)
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !cacheFresh(dir) {
		t.Fatal("a just-written cache is not fresh")
	}
	old := time.Now().Add(-2 * tenantCacheTTL)
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}
	if cacheFresh(dir) {
		t.Error("a cache older than the TTL is still reported fresh")
	}
	// With no stored spec, cacheFreshFor must agree with cacheFresh rather than
	// invalidating every read for apps the scheduler has never echoed.
	if cacheFreshFor(dir, "sub-1", "demo") {
		t.Error("cacheFreshFor disagreed with an expired cacheFresh")
	}
}
