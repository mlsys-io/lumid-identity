package handler

// Cross-node bundle cache.
//
// identity runs on the service tier and does not mount the scheduler's
// xpio-state PVC, so a CLOUD-installed tenant app has no files on this node.
// Every domain tool the chat agent has — casebook, experiment_case,
// review_action, the dataset/cycle/config readers — resolves through
// resolveAppDir and so answered "app not found" for apps that /me/apps reports
// installed and ready. 39 call sites, one cause.
//
// serveAppSurface (v0.5.1) solved its own version of this by fetching a single
// blob from the caller's xp.io repo. That does not generalise: these callers
// want a DIRECTORY they can walk (loopExperiments, dataset listing, cycle
// outputs). So materialise the published bundle to local disk once and let
// resolveAppDir hand it back like any other bundle dir.
//
// READ PATH ONLY. resolveOwnedAppDir (the write resolver) deliberately does not
// use this: a write into a materialised copy would be silently discarded on the
// next refresh, and failing loudly is the correct behaviour there.

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// How long a materialised copy is trusted before refetching. A single chat turn
// fires several tools; without this each one would refetch the whole bundle.
const tenantCacheTTL = 5 * time.Minute

const tenantCacheMarker = ".materialised"

// Bundles are small (a well-formed app mounts its dataset by reference rather
// than shipping it). This is a guard against a pathological repo, not a budget.
const tenantCacheMaxFiles = 512
const tenantCacheMaxBytes = 32 << 20 // 32 MB

// One fetch per (sub, app) in flight. Concurrent tool calls in the same turn
// must not race each other into a half-written directory.
var tenantCacheFlight sync.Map // key -> *sync.Mutex

func tenantCacheRoot() string {
	return filepath.Join(operatorHome(), ".xp", "_tenant-cache")
}

func tenantCacheDir(userSub, app string) string {
	return filepath.Join(tenantCacheRoot(), userSub, app)
}

// cacheFresh reports whether a materialised copy exists and is within TTL.
func cacheFresh(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, tenantCacheMarker))
	if err != nil {
		return false
	}
	return time.Since(st.ModTime()) < tenantCacheTTL
}

// repoTree lists every blob path in the caller's published bundle.
func repoTree(owner, userSub, app, sub string) []string {
	bearer, err := xpcloudUserJWT(userSub)
	if err != nil {
		return nil
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + owner + "/" + app + "/tree/main"
	if sub != "" {
		url += "/" + sub
	}
	code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
	if err != nil || code >= 300 || resp == nil {
		return nil
	}
	entries, _ := resp["entries"].([]any)
	var out []string
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		kind, _ := m["type"].(string)
		if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
			continue // the tree is remote data; never let a name escape the cache dir
		}
		path := name
		if sub != "" {
			path = sub + "/" + name
		}
		if kind == "tree" {
			out = append(out, repoTree(owner, userSub, app, path)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// materialiseTenantApp writes the published bundle to a local cache dir and
// returns it, or "" if the app has no reachable bundle.
func materialiseTenantApp(userSub, app string) string {
	if userSub == "" || app == "" ||
		strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") ||
		strings.ContainsAny(userSub, "/\\") || strings.Contains(userSub, "..") {
		return ""
	}
	dir := tenantCacheDir(userSub, app)
	if cacheFresh(dir) {
		return dir
	}

	key := userSub + "/" + app
	muAny, _ := tenantCacheFlight.LoadOrStore(key, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	// Another caller may have finished while we waited on the lock.
	if cacheFresh(dir) {
		return dir
	}

	// WHOSE repo? Not necessarily the caller's. An app installed from someone
	// else lives under its AUTHOR's sub, so fetching repos/<caller>/<app> 404s
	// and every surface and tool reports "app not found" — for an app /me/apps
	// says is ready. The whole cross-node fallback worked only for an app's own
	// author until now, which is why owner-only testing never saw it.
	owner := repoOwnerFor(userSub, app)
	paths := repoTree(owner, userSub, app, "")
	if len(paths) == 0 {
		// RESCUE for a bare-slug install. repoOwnerFor recovers the author from
		// the install intent's "<owner>/<name>" slug; an install recorded as the
		// bare "<name>" carries no owner, so it falls back to the CALLER's sub,
		// whose repo does not exist, and every surface 404s "app not found" for
		// an app /me/apps reports ready.
		//
		// Bare slugs are not an edge case: /onboarding/domain installs
		// auto-quant / personal-agent / mbb-ai by bare name, the apps page's
		// retryInstall passes a bare name, and the chat's install_app tool takes
		// whatever slug the model produced. The scheduler resolves shorthand on
		// its own side, so those paths look fine wherever the PVC is readable —
		// but identity mounts only signing-keys, so THIS fallback is the only
		// path a cloud identity pod has, and it was the one that could not.
		//
		// Placed here rather than inside repoOwnerFor on purpose: it runs only
		// where the existing code has already failed outright, so no currently
		// working resolution changes behaviour.
		if alt := resolvePublishedOwner(userSub, app); alt != "" && alt != owner {
			owner = alt
			paths = repoTree(owner, userSub, app, "")
		}
	}
	if len(paths) == 0 {
		return ""
	}
	if len(paths) > tenantCacheMaxFiles {
		paths = paths[:tenantCacheMaxFiles]
	}

	// Stage into a sibling and swap, so a concurrent reader never sees a
	// partially-written bundle even if this fetch dies midway.
	stage := dir + ".stage"
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return ""
	}
	total := 0
	wrote := 0
	for _, p := range paths {
		body, ok := fetchRepoBlobAt(userSub, owner+"/"+app, p)
		if !ok {
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(string(body)); err == nil && len(b) > 0 {
			body = b
		}
		total += len(body)
		if total > tenantCacheMaxBytes {
			break
		}
		dst := filepath.Join(stage, filepath.FromSlash(p))
		// Belt-and-braces: the path came from a remote tree.
		if !strings.HasPrefix(dst, stage+string(os.PathSeparator)) {
			continue
		}
		if os.MkdirAll(filepath.Dir(dst), 0o755) != nil {
			continue
		}
		if os.WriteFile(dst, body, 0o644) == nil {
			wrote++
		}
	}
	if wrote == 0 {
		_ = os.RemoveAll(stage)
		return ""
	}
	// The publisher stores the spec dot-prefixed; readAppUI/ResolveSpecPath look
	// for the bare name too, so provide both rather than teach every reader.
	spec, specErr := os.ReadFile(filepath.Join(stage, ".xpcloud.yaml"))
	if specErr == nil {
		_ = os.WriteFile(filepath.Join(stage, "xpcloud.yaml"), spec, 0o644)
	}
	// Mounted datasets. A well-formed app declares `datasets: [{repo, mount_at}]`
	// and does NOT ship the data in its bundle — shipping it blows the upload cap
	// and forks the ground truth away from the source repo. So the bundle alone
	// gives a materialised app zero records: casebook resolved but answered
	// `cases: []`. Pull each mounted repo in beside the code.
	if specErr == nil {
		for _, ds := range parseMountedDatasets(spec) {
			materialiseDataset(userSub, ds.repo, filepath.Join(stage, filepath.FromSlash(ds.mountAt)), stage)
		}
	}
	_ = os.WriteFile(filepath.Join(stage, tenantCacheMarker), []byte(time.Now().UTC().Format(time.RFC3339)), 0o644)

	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return ""
	}
	if err := os.Rename(stage, dir); err != nil {
		_ = os.RemoveAll(stage)
		return ""
	}
	return dir
}

// ─── mounted datasets ────────────────────────────────────────────────────

type mountedDataset struct{ repo, mountAt string }

// parseMountedDatasets pulls {repo, mount_at} pairs out of an app spec. Only
// entries with BOTH are mountable; a `local_path` dataset ships in the bundle
// and is already on disk.
func parseMountedDatasets(spec []byte) []mountedDataset {
	var doc struct {
		Datasets []struct {
			Repo    string `yaml:"repo"`
			MountAt string `yaml:"mount_at"`
		} `yaml:"datasets"`
	}
	if yaml.Unmarshal(spec, &doc) != nil {
		return nil
	}
	var out []mountedDataset
	for _, d := range doc.Datasets {
		if d.Repo == "" || d.MountAt == "" {
			continue
		}
		// mount_at is interpolated into a path under the staging dir.
		if strings.Contains(d.MountAt, "..") || strings.HasPrefix(d.MountAt, "/") {
			continue
		}
		// repo is "<owner-sub>/<name>" — exactly two segments, no traversal.
		parts := strings.Split(d.Repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(d.Repo, "..") {
			continue
		}
		out = append(out, mountedDataset{repo: d.Repo, mountAt: d.MountAt})
	}
	return out
}

// materialiseDataset copies one mounted repo's blobs into `dst`.
//
// Best-effort: a dataset the caller cannot read (or that has moved) must leave
// the app itself usable rather than fail the whole materialisation — the app's
// code and surfaces are still worth serving without its data.
func materialiseDataset(userSub, repo, dst, stageRoot string) {
	if !strings.HasPrefix(dst, stageRoot+string(os.PathSeparator)) {
		return
	}
	paths := repoTreeAt(userSub, repo, "")
	if len(paths) == 0 {
		log.Printf("[app-cache] dataset %s: tree empty or unreadable — mounting nothing", repo)
		return
	}
	if len(paths) > tenantCacheMaxFiles {
		paths = paths[:tenantCacheMaxFiles]
	}
	// Graft the dataset's CONTENT at mount_at, not the repo's own layout.
	//
	// The publisher drops root-level .json (it reads them as marker files), so a
	// dataset repo has to keep its records under a directory — conventionally
	// data/. Mounting the tree verbatim then lands them at
	// <mount_at>/data/*.json while every consumer globs <mount_at>/*.json:
	// casebook reported `cases: 0` while the files were present one level down.
	// When every record shares one top-level directory, strip it — that is what
	// "mount this dataset at data/seed" means to the app.
	strip := commonTopDir(paths)
	if os.MkdirAll(dst, 0o755) != nil {
		return
	}
	total := 0
	wrote := 0
	var firstErr string
	// Silence here is the failure mode this logging exists for: the loop below
	// skips quietly on a bad fetch or write, so a dataset that fetches 0 of 52
	// left an EMPTY mount dir that is indistinguishable from success. Count what
	// actually landed and say so.
	defer func() {
		if wrote < len(paths) {
			log.Printf("[app-cache] dataset %s: wrote %d/%d files into %s%s",
				repo, wrote, len(paths), dst, firstErr)
		}
	}()
	for _, p := range paths {
		body, ok := fetchRepoBlobAt(userSub, repo, p)
		if !ok {
			if firstErr == "" {
				firstErr = " (first failure: fetch " + p + ")"
			}
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(string(body)); err == nil && len(b) > 0 {
			body = b
		}
		total += len(body)
		if total > tenantCacheMaxBytes {
			return
		}
		rel := p
		if strip != "" {
			rel = strings.TrimPrefix(rel, strip+"/")
		}
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if !strings.HasPrefix(out, dst+string(os.PathSeparator)) {
			if firstErr == "" {
				firstErr = " (first failure: path escaped dst: " + p + ")"
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			if firstErr == "" {
				firstErr = " (first failure: mkdir " + filepath.Dir(out) + ": " + err.Error() + ")"
			}
			continue
		}
		if err := os.WriteFile(out, body, 0o644); err != nil {
			if firstErr == "" {
				firstErr = " (first failure: write " + out + ": " + err.Error() + ")"
			}
			continue
		}
		wrote++
	}
}

// repoTreeAt / fetchRepoBlobAt are the cross-owner forms: a mounted dataset
// lives in ANOTHER account's repo, so the path is "<owner>/<name>" rather than
// "<caller>/<app>". The caller's JWT still authorises the read.
func repoTreeAt(userSub, repo, sub string) []string {
	bearer, err := xpcloudUserJWT(userSub)
	if err != nil {
		return nil
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + repo + "/tree/main"
	if sub != "" {
		url += "/" + sub
	}
	code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
	if err != nil || code >= 300 || resp == nil {
		return nil
	}
	entries, _ := resp["entries"].([]any)
	var out []string
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		kind, _ := m["type"].(string)
		if name == "" || strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
			continue
		}
		path := name
		if sub != "" {
			path = sub + "/" + name
		}
		if kind == "tree" {
			out = append(out, repoTreeAt(userSub, repo, path)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

func fetchRepoBlobAt(userSub, repo, path string) ([]byte, bool) {
	if path == "" || strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return nil, false
	}
	bearer, err := xpcloudUserJWT(userSub)
	if err != nil {
		return nil, false
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + repo + "/blob/main/" + path
	code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
	if err != nil || code >= 300 || resp == nil {
		return nil, false
	}
	content, _ := resp["content"].(string)
	if content == "" {
		return nil, false
	}
	if dec, derr := base64.StdEncoding.DecodeString(content); derr == nil && len(dec) > 0 {
		return dec, true
	}
	return []byte(content), true
}

// commonTopDir returns the single top-level directory shared by every path, or
// "" when they do not all share one (or when some sit at the root already).
// Platform files the publisher adds (.xpcloud.yaml, .manifest.json) are ignored
// so one marker at the root does not defeat the check.
func commonTopDir(paths []string) string {
	top := ""
	for _, p := range paths {
		if strings.HasPrefix(p, ".") {
			continue // publisher marker at the root
		}
		i := strings.Index(p, "/")
		if i <= 0 {
			return "" // a record sits at the root — nothing to strip
		}
		d := p[:i]
		if top == "" {
			top = d
		} else if top != d {
			return "" // more than one top-level dir — keep the layout as-is
		}
	}
	return top
}

// repoIsRunnable reports whether a published repo declares loops[] or tools[] —
// i.e. it is something you INSTALL and run, not a knowledge bank you subscribe
// to. Used to tell a migrated app (kind rewritten to `agent` by app_push) from a
// genuine knowledge agent, which the `kind` label alone cannot do.
//
// Fails OPEN like the gate it serves: if the spec cannot be fetched we return
// false and the caller keeps its existing behaviour, rather than guessing.
func repoIsRunnable(userSub, slug string) bool {
	if !strings.Contains(slug, "/") {
		return false
	}
	spec, ok := fetchRepoBlobAt(userSub, slug, ".xpcloud.yaml")
	if !ok {
		if spec, ok = fetchRepoBlobAt(userSub, slug, "xpcloud.yaml"); !ok {
			return false
		}
	}
	var doc struct {
		Loops []map[string]any `yaml:"loops"`
		Tools []map[string]any `yaml:"tools"`
		UI    struct {
			Surface  map[string]any `yaml:"surface"`
			Surfaces map[string]any `yaml:"surfaces"`
		} `yaml:"ui"`
	}
	if yaml.Unmarshal(spec, &doc) != nil {
		return false
	}
	// A declared UI surface counts as runnable. loops/tools alone misses the
	// SURFACE-ONLY app — a read-only viewer whose entire value is its Studio
	// tabs, so it legitimately declares `loops: []` and `tools: []` and was
	// indistinguishable here from a knowledge bank. lumid-data-lake is exactly
	// that shape and was told to "subscribe instead", which is the wrong verb:
	// subscribing gives you a memory bank, not the surfaces you actually want.
	// A knowledge agent declares no ui: block, so this still separates them.
	if len(doc.UI.Surface) > 0 || len(doc.UI.Surfaces) > 0 {
		return true
	}
	return len(doc.Loops) > 0 || len(doc.Tools) > 0
}

// ownerFromIntentPayload extracts the publishing owner from one install
// intent's payload, when that install is the one that produced `app`.
//
// Pure and DB-free on purpose: the owner-resolution BUG was a wrong decision,
// not a wrong query, and a test that needs MySQL is a test that skips in CI —
// which is how the assumption survived a full green suite in the first place.
func ownerFromIntentPayload(payload, app string) (string, bool) {
	var pl map[string]any
	if json.Unmarshal([]byte(payload), &pl) != nil {
		return "", false
	}
	slug, _ := pl["slug"].(string)
	slug = strings.TrimSpace(slug)
	owner, name, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || name == "" {
		return "", false
	}
	// installAppName applies `as` renames and strips -draft, so the local
	// directory name is compared the same way everywhere else compares it.
	if installAppName(pl) != app {
		return "", false
	}
	return owner, true
}

// repoOwnerFor returns the sub that OWNS the published bundle for `app`.
//
// Defaults to the caller (an app they authored themselves), but an install
// records the source slug "<owner>/<name>", so an app installed from the
// marketplace resolves to its actual author. Without this the bundle fetch
// asks for repos/<caller>/<app>, which exists only for the author.
func repoOwnerFor(userSub, app string) string {
	if common.DB == nil {
		return userSub
	}
	var rows []models.MeAppIntent
	if err := common.DB.Where("user_sub = ? AND action = ?", userSub, "install").
		Order("created_at DESC").Limit(50).Find(&rows).Error; err != nil {
		return userSub
	}
	for i := range rows {
		if owner, ok := ownerFromIntentPayload(rows[i].Payload, app); ok {
			return owner
		}
	}
	return userSub
}

// firstPartyOwner — the canonical publisher for shorthand app names. Mirrors
// sdk/ops/apps.py::_FIRST_PARTY_OWNER, including the env override, so the Go
// and Python resolvers cannot drift into disagreeing about what "auto-quant"
// means.
func firstPartyOwner() string {
	if v := os.Getenv("LUMID_FIRST_PARTY_OWNER"); v != "" {
		return v
	}
	return "70f192ce-97f3-5d9e-4324-8a557ea72900"
}

// resolvedOwnerCache memoises bare-name -> owner. The tenant bundle cache in
// front of this already collapses a turn's many tool calls into one miss, so
// this only guards against repeated misses across turns.
var resolvedOwnerCache sync.Map // app -> string

// resolvePublishedOwner finds who publishes `app` when the install recorded no
// owner. Same two rungs, in the same order, as
// sdk/ops/apps.py::_resolve_install_slug:
//
//  1. a direct hit under the first-party owner, then
//  2. a search for a UNIQUE public repo whose name matches exactly.
//
// Ambiguity returns "" rather than a guess. Two owners really do publish an
// app named "mbb-ai", and silently picking one would hand the user someone
// else's bundle — a wrong bundle is worse than the 404 this rescues, because
// it looks like it worked.
func resolvePublishedOwner(userSub, app string) string {
	if app == "" || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		return ""
	}
	if v, ok := resolvedOwnerCache.Load(app); ok {
		return v.(string)
	}
	bearer, err := xpcloudUserJWT(userSub)
	if err != nil {
		return ""
	}
	base := xpcloudBaseURL()

	owner := ""
	// 1. First-party direct hit.
	if code, _, err := xpcloudJSON(http.MethodGet, base+"/api/v1/repos/"+firstPartyOwner()+"/"+app, bearer, nil); err == nil && code == http.StatusOK {
		owner = firstPartyOwner()
	}
	// 2. Unique public exact-name match.
	if owner == "" {
		code, body, err := xpcloudJSON(http.MethodGet, base+"/api/v1/repos?q="+url.QueryEscape(app), bearer, nil)
		if err == nil && code == http.StatusOK {
			repos, _ := body["repos"].([]any)
			owner = uniquePublicOwner(repos, app)
		}
	}
	resolvedOwnerCache.Store(app, owner)
	return owner
}

// uniquePublicOwner returns the owner_sub of the ONE public repo named exactly
// `app`, or "" when there are none or several.
//
// Split out from resolvePublishedOwner so the selection rule is testable
// without a network or a DB: the rule is the whole risk here. A search for
// "mbb-ai" really does return two public repos under different owners, and the
// difference between returning "" and returning either one of them is the
// difference between a visible 404 and silently serving a stranger's bundle.
func uniquePublicOwner(repos []any, app string) string {
	match := ""
	n := 0
	for _, r := range repos {
		rec, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := rec["name"].(string); name != app {
			continue
		}
		if vis, _ := rec["visibility"].(string); vis != "public" {
			continue
		}
		sub, _ := rec["owner_sub"].(string)
		if sub == "" {
			continue
		}
		n++
		match = sub
	}
	if n == 1 {
		return match
	}
	return ""
}

// appListRoots returns every directory a READ-ONLY "walk all of this user's
// apps" scan should consider, in resolveAppDir's precedence: the caller's
// tenant install, the operator-shared bundles, then the materialised cache.
//
// The cache root is the one these scans were missing. resolveAppDir already
// falls back to materialiseTenantApp for a SINGLE named app, so per-app reads
// worked; the list endpoints walked only the first two directories and so
// reported nothing for a cloud tenant whose apps live in the cache. That is why
// the chat's list_apps answered "0 apps" and /me/skills returned an empty
// inventory for an account whose app /me/apps reports ready.
//
// Read-only by construction: the cache is refreshed on a TTL by a RemoveAll +
// directory swap, so nothing may be written here. Writers must keep using
// resolveOwnedAppDir, which deliberately refuses the cache.
//
// Callers MUST dedupe by app name — an app can appear in more than one root,
// and precedence is "first root wins".
func appListRoots(userSub string) []string {
	return []string{
		tenantAppsDir(userSub),
		filepath.Join(operatorHome(), ".xp", "apps"),
		filepath.Join(tenantCacheRoot(), userSub),
	}
}
