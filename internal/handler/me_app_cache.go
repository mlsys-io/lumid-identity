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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
func repoTree(userSub, app, sub string) []string {
	bearer, err := xpcloudUserJWT(userSub)
	if err != nil {
		return nil
	}
	url := xpcloudBaseURL() + "/api/v1/repos/" + userSub + "/" + app + "/tree/main"
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
			out = append(out, repoTree(userSub, app, path)...)
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

	paths := repoTree(userSub, app, "")
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
		body, ok := fetchRepoBlob(userSub, app, p)
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
	if b, err := os.ReadFile(filepath.Join(stage, ".xpcloud.yaml")); err == nil {
		_ = os.WriteFile(filepath.Join(stage, "xpcloud.yaml"), b, 0o644)
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
