package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A second published app: one public module, one public but refused (tag
// only), one private.
const testPubSpec = `name: tok-tools
modules:
- id: count
  title: Token counter
  about: Counts tokens.
  image: ` + testModuleImage + `
  run: python -m tok.count
  inputs: {text: "the text"}
  limits: {cpu: 1, memory: 8Gi}
  public: true
- id: tagged_pub
  image: ghcr.io/acme/tok:latest
  run: python -m tok.count
  public: true
- id: hidden
  image: ` + testModuleImage + `
  run: python -m tok.hidden
`

// fakeXPCloud serves the public listing and the blobs the index reads.
type fakeXPCloud struct {
	mu       sync.Mutex
	repos    []map[string]any
	specs    map[string]string // "<owner>/<app>" -> spec
	listCode int
	lists    atomic.Int32
	blobs    atomic.Int32
	paths    []string // blob paths read, "<owner>/<app>/<path>"
}

func (f *fakeXPCloud) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "" && r.URL.Path == "/api/v1/repos" {
		http.Error(w, "the index must read the listing anonymously", http.StatusBadRequest)
		return
	}
	switch {
	case r.URL.Path == "/api/v1/repos":
		f.lists.Add(1)
		if r.URL.Query().Get("kind") != "app" {
			http.Error(w, "kind", http.StatusBadRequest)
			return
		}
		if f.listCode != 0 {
			w.WriteHeader(f.listCode)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"repos": f.repos})
	case strings.Contains(r.URL.Path, "/blob/main/"):
		f.blobs.Add(1)
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/repos/")
		i := strings.Index(rest, "/blob/main/")
		key, path := rest[:i], rest[i+len("/blob/main/"):]
		f.paths = append(f.paths, key+"/"+path)
		spec, has := f.specs[key]
		if !has || path != ".xpcloud.yaml" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"path": path, "ref": "main", "content": spec})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeXPCloud) set(fn func(f *fakeXPCloud)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func repoRow(owner, name, head, vis string) map[string]any {
	return map[string]any{"owner_sub": owner, "name": name, "display_name": name + " app", "head_sha": head,
		"visibility": vis, "kind": "app"}
}

// publicIndexSetup points xpcloud at a fake and gives the index a clock the
// test moves.
func publicIndexSetup(t *testing.T) (*fakeXPCloud, *time.Time) {
	t.Helper()
	good := strings.Replace(testModuleSpec, "ghcr.io/acme/prompt-mod:latest", testModuleImage, 1)
	f := &fakeXPCloud{
		repos: []map[string]any{
			repoRow("pub-owner", "trace-lab", "h1", "public"),
			repoRow("tok-owner", "tok-tools", "t1", "public"),
			repoRow("sec-owner", "secret-lab", "s1", "private"), // never listed by an anonymous read
			repoRow("gone-owner", "no-spec", "g1", "public"),    // spec unreadable
		},
		specs: map[string]string{
			"pub-owner/trace-lab":  good,
			"tok-owner/tok-tools":  testPubSpec,
			"sec-owner/secret-lab": good,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv("XPCLOUD_URL", srv.URL)
	resetPublicModules()
	t.Cleanup(resetPublicModules)
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	prevNow := publicModuleNow
	publicModuleNow = func() time.Time { return now }
	t.Cleanup(func() { publicModuleNow = prevNow })
	return f, &now
}

func indexNames() []string {
	publicModules.mu.Lock()
	defer publicModules.mu.Unlock()
	var out []string
	for _, pm := range publicModules.list {
		out = append(out, pm.Name)
	}
	return out
}

// waitRefresh waits for a background refresh, if one is running.
func waitRefresh(t *testing.T) {
	t.Helper()
	publicModules.mu.Lock()
	done := publicModules.inflight
	publicModules.mu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not finish")
	}
}

func TestPublicModuleIndexBuildsOnlyCallablePublicModules(t *testing.T) {
	f, _ := publicIndexSetup(t)
	publicModules.refresh(context.Background())
	got := strings.Join(indexNames(), ",")
	if got != "pub-owner/trace-lab.open_one,tok-owner/tok-tools.count" {
		t.Fatalf("index = %s", got)
	}
	publicModules.mu.Lock()
	pm := publicModules.byName["tok-owner/tok-tools.count"]
	skipped := publicModules.skipped
	publicModules.mu.Unlock()
	if pm.Owner != "tok-owner" || pm.App != "tok-tools" || pm.AppTitle != "tok-tools app" ||
		pm.Module.Limits.MemoryMi != moduleMaxMemoryMi || pm.Module.digest() != testModuleImage[strings.Index(testModuleImage, "@")+1:] {
		t.Fatalf("entry = %+v", pm)
	}
	if len(skipped) != 1 || !strings.HasPrefix(skipped[0], "gone-owner/no-spec") {
		t.Fatalf("skipped = %v", skipped)
	}
	// The private row is dropped before any fetch: 3 public repos, the one
	// without a spec tried at both paths.
	if n := f.blobs.Load(); n != 4 {
		t.Fatalf("blob reads = %d, want 4", n)
	}
}

func TestPublicModuleIndexRefreshesOnTTLAndOnlyChangedApps(t *testing.T) {
	f, now := publicIndexSetup(t)
	// The first listing on a pod waits for the first build.
	mods, status := publicModules.snapshot()
	if len(mods) != 2 || status["count"] != 2 || status["stale"] != nil || f.lists.Load() != 1 {
		t.Fatalf("first snapshot = %d %v (lists %d)", len(mods), status, f.lists.Load())
	}
	blobs := f.blobs.Load()
	// Within the TTL: no request reaches xpcloud, however many there are.
	for i := 0; i < 20; i++ {
		*now = now.Add(20 * time.Second)
		publicModules.snapshot()
		publicModules.lookup("tok-owner", "tok-tools", "count")
	}
	if f.lists.Load() != 1 || f.blobs.Load() != blobs {
		t.Fatalf("within TTL: lists %d blobs %d", f.lists.Load(), f.blobs.Load())
	}
	// Past the TTL: one refresh; an unchanged head is not re-fetched, a moved
	// one is.
	f.set(func(f *fakeXPCloud) {
		f.repos[1]["head_sha"] = "t2"
		f.specs["tok-owner/tok-tools"] = strings.Replace(testPubSpec, "id: hidden", "id: hidden\n  public: true", 1)
	})
	*now = now.Add(publicModuleTTL)
	publicModules.snapshot()
	waitRefresh(t)
	if f.lists.Load() != 2 {
		t.Fatalf("lists after TTL = %d", f.lists.Load())
	}
	// tok-tools re-read (1), no-spec re-tried (2 paths, it has no good entry);
	// trace-lab kept by its head.
	if d := f.blobs.Load() - blobs; d != 3 {
		t.Fatalf("blob reads on refresh = %d, want 3", d)
	}
	if got := strings.Join(indexNames(), ","); got !=
		"pub-owner/trace-lab.open_one,tok-owner/tok-tools.count,tok-owner/tok-tools.hidden" {
		t.Fatalf("after refresh = %s", got)
	}
}

func TestPublicModuleIndexKeepsLastGoodOnFailure(t *testing.T) {
	f, now := publicIndexSetup(t)
	publicModules.refresh(context.Background())
	f.set(func(f *fakeXPCloud) { f.listCode = http.StatusBadGateway })
	*now = now.Add(publicModuleTTL)
	mods, _ := publicModules.snapshot()
	waitRefresh(t)
	mods, status := publicModules.snapshot()
	if len(mods) != 2 || status["stale"] != true || !strings.Contains(status["refresh_error"].(string), "HTTP 502") ||
		!strings.Contains(status["note"].(string), "showing the last good one") {
		t.Fatalf("after failure = %d %v", len(mods), status)
	}
	// Retried after publicModuleRetry, not on every request.
	lists := f.lists.Load()
	for i := 0; i < 5; i++ {
		publicModules.snapshot()
	}
	waitRefresh(t)
	if f.lists.Load() != lists {
		t.Fatalf("retried before the backoff: %d -> %d", lists, f.lists.Load())
	}
	// A failing app keeps its previous entry while the listing works again.
	f.set(func(f *fakeXPCloud) {
		f.listCode = 0
		f.repos[1]["head_sha"] = "t9"
		delete(f.specs, "tok-owner/tok-tools")
	})
	*now = now.Add(publicModuleRetry)
	publicModules.snapshot()
	waitRefresh(t)
	mods, status = publicModules.snapshot()
	if f.lists.Load() != lists+1 || len(mods) != 2 || status["stale"] != nil || status["unreadable_apps"] != 2 {
		t.Fatalf("recovered = %d %v (lists %d)", len(mods), status, f.lists.Load())
	}
	// A pod that never built one says so, and lists nothing.
	resetPublicModules()
	f.set(func(f *fakeXPCloud) { f.listCode = http.StatusInternalServerError })
	mods, status = publicModules.snapshot()
	if len(mods) != 0 || status["stale"] != true || !strings.Contains(status["note"].(string), "could not be built") {
		t.Fatalf("never built = %d %v", len(mods), status)
	}
}

func TestPublicModuleListingShapeAndShadowing(t *testing.T) {
	publicIndexSetup(t)
	publicModules.refresh(context.Background())
	items, status := publicModuleListing("me", map[string]bool{})
	if len(items) != 2 || status["count"] != 2 {
		t.Fatalf("listing = %v %v", items, status)
	}
	it := items[1]
	lim := it["limits"].(gin.H)
	if it["name"] != "tok-owner/tok-tools.count" || it["kind"] != "module" || it["public"] != true ||
		it["owner"] != "tok-owner" || it["app"] != "tok-tools" || it["app_title"] != "tok-tools app" ||
		it["title"] != "Token counter" || it["about"] != "Counts tokens." || it["share"] != "tenant" ||
		it["image"] != testModuleImage || !strings.HasPrefix(it["digest"].(string), "sha256:") ||
		lim["memory"] != "4096Mi" || lim["gpu"] != false || lim["network"] != "none" ||
		it["inputs"].(map[string]string)["text"] != "the text" || it["refused"] != nil {
		t.Fatalf("item = %v", it)
	}
	if notes, _ := it["notes"].([]string); len(notes) != 1 {
		t.Fatalf("clamp notes = %v", it["notes"])
	}
	// The caller's own install of trace-lab shadows pub-owner's trace-lab.
	items, status = publicModuleListing("me", map[string]bool{"trace-lab": true})
	if len(items) != 1 || items[0]["name"] != "tok-owner/tok-tools.count" || status["shadowed"] != 1 {
		t.Fatalf("shadowed = %v %v", items, status)
	}
	// The publisher's own public modules are not repeated owner-qualified.
	items, _ = publicModuleListing("tok-owner", map[string]bool{})
	if len(items) != 1 || items[0]["name"] != "pub-owner/trace-lab.open_one" {
		t.Fatalf("own app listed as public = %v", items)
	}
}

func TestResolvePublicModuleUsesTheIndex(t *testing.T) {
	publicIndexSetup(t)
	publicModules.refresh(context.Background())
	good := strings.Replace(testModuleSpec, "ghcr.io/acme/prompt-mod:latest", testModuleImage, 1)
	var fetches atomic.Int32
	prev := moduleSpecSource
	t.Cleanup(func() { moduleSpecSource = prev })
	moduleSpecSource = func(sub, owner, app string) ([]byte, bool) {
		fetches.Add(1)
		switch {
		case owner == "pub-owner" && app == "trace-lab":
			return []byte(good), true
		case owner == "" && app == "trace-lab":
			return []byte(good), true
		case owner == "tok-owner" && app == "tok-tools":
			return []byte(testPubSpec), true
		}
		return nil, false
	}
	// A hit: no fetch, the indexed (clamped) module.
	m, app, isModule, ref := resolveModule("me", "tok-owner/tok-tools.count", "mine")
	if !isModule || ref != nil || app != "tok-tools" || m.ID != "count" || m.Limits.MemoryMi != moduleMaxMemoryMi ||
		fetches.Load() != 0 {
		t.Fatalf("hit = %+v %s %v %+v (fetches %d)", m, app, isModule, ref, fetches.Load())
	}
	// Misses fall through to the live read and refuse in the same words.
	cases := []struct {
		name  string
		code  int
		words string
	}{
		{"pub-owner/trace-lab.private_one", http.StatusForbidden, "not public"},
		{"tok-owner/tok-tools.tagged_pub", http.StatusBadRequest, "not pinned"},
		{"tok-owner/tok-tools.nope", http.StatusNotFound, "declares no module"},
		{"nobody/trace-lab.open_one", http.StatusNotFound, "publishes no app"},
	}
	for i, tc := range cases {
		_, _, _, ref := resolveModule("me", tc.name, "mine")
		if ref == nil || ref.code != tc.code || !strings.Contains(ref.why, tc.words) || fetches.Load() != int32(i+1) {
			t.Errorf("%s = %+v (fetches %d)", tc.name, ref, fetches.Load())
		}
	}
	// Own-install names never consult the index; private stays private.
	fetches.Store(0)
	if _, _, _, ref := resolveModule("me", "trace-lab.private_one", "other-app"); ref == nil ||
		ref.code != http.StatusForbidden || fetches.Load() != 1 {
		t.Fatalf("own private from another app = %+v (fetches %d)", ref, fetches.Load())
	}
	if _, _, _, ref := resolveModule("pub-owner", "pub-owner/trace-lab.open_one", ""); ref != nil ||
		fetches.Load() != 2 {
		t.Fatalf("owner == caller must read the install = %+v (fetches %d)", ref, fetches.Load())
	}
	// An index older than publicModuleMaxServe is not trusted: back to fetching.
	fetches.Store(0)
	publicModules.mu.Lock()
	publicModules.builtAt = publicModuleNow().Add(-publicModuleMaxServe - time.Second)
	publicModules.lastErr, publicModules.triedAt = "down", publicModuleNow() // no refresh kicked
	publicModules.mu.Unlock()
	if _, _, _, ref := resolveModule("me", "tok-owner/tok-tools.count", "mine"); ref != nil || fetches.Load() != 1 {
		t.Fatalf("stale index = %+v (fetches %d)", ref, fetches.Load())
	}
}

// Through the route, with a real DB: ?public=1 adds the public modules after
// the app's own, shadowed by the caller's install, and /me/measure resolves a
// public one from the index without reading its spec.
func TestPublicModulesThroughTheRoute(t *testing.T) {
	f, owner, _ := moduleTestSetup(t)
	xp, _ := publicIndexSetup(t)
	prevInstalled := moduleInstalledApps
	t.Cleanup(func() { moduleInstalledApps = prevInstalled })
	moduleInstalledApps = func(string) []string { return nil }

	code, list := measureCall(t, "GET", "/api/v1/me/measure/instruments?app=trace-lab&public=1", "", owner)
	if code != 200 {
		t.Fatalf("listing = %d %v", code, list)
	}
	names := map[string]map[string]any{}
	for _, it := range list["instruments"].([]any) {
		m := it.(map[string]any)
		names[m["name"].(string)] = m
	}
	if names["trace-lab.prompt_stats"] == nil || names["tok-owner/tok-tools.count"] == nil {
		t.Fatalf("names = %v", names)
	}
	if names["pub-owner/trace-lab.open_one"] != nil {
		t.Fatal("the caller's trace-lab install must shadow pub-owner/trace-lab")
	}
	if names["tok-owner/tok-tools.tagged_pub"] != nil || names["tok-owner/tok-tools.hidden"] != nil {
		t.Fatal("refused or private public-app modules listed")
	}
	if pm := names["tok-owner/tok-tools.count"]; pm["public"] != true || pm["owner"] != "tok-owner" {
		t.Fatalf("public item = %v", pm)
	}
	if st, _ := list["public_modules"].(map[string]any); st == nil || st["count"] != 2.0 || st["shadowed"] != 1.0 {
		t.Fatalf("public_modules = %v", list["public_modules"])
	}
	// Without public=1 the listing is what it was.
	_, plain := measureCall(t, "GET", "/api/v1/me/measure/instruments?app=trace-lab", "", owner)
	if plain["public_modules"] != nil {
		t.Fatal("public modules listed without ?public=1")
	}
	for _, it := range plain["instruments"].([]any) {
		if strings.Contains(it.(map[string]any)["name"].(string), "/") {
			t.Fatalf("public module without ?public=1: %v", it)
		}
	}
	// Calling the public module: answered from the index, no read of the
	// publisher's spec (the caller's own app may still be read, for its budget).
	xp.set(func(f *fakeXPCloud) { f.paths = nil })
	body := `{"instrument":"tok-owner/tok-tools.count","app":"mine","inputs":{"text":"a b c"}}`
	code, got := measureCall(t, "POST", "/api/v1/me/measure", body, owner)
	var read []string
	xp.set(func(f *fakeXPCloud) { read = append(read, f.paths...) })
	for _, p := range read {
		if strings.HasPrefix(p, "tok-owner/") {
			t.Fatalf("the publisher's spec was read on a cached call: %v", read)
		}
	}
	if code != http.StatusAccepted || f.posts != 1 {
		t.Fatalf("public call = %d %v (posts %d)", code, got, f.posts)
	}
	if !strings.Contains(f.posted, `"memory":"4096Mi"`) || !strings.Contains(f.posted, `"network":"none"`) {
		t.Fatalf("posted = %s", f.posted)
	}
}
