package handler

// Public module index (2026-11-28).
//
// A module marked `public: true` in a published app can be called by anyone
// as "<owner>/<app>.<module>" — but until now nothing listed them, and every
// call fetched the owner's spec from xpcloud. This file keeps ONE per-pod
// index of every public module across the published apps, built from the
// same public listing the Marketplace page reads (xpcloud /api/v1/repos,
// anonymous, kind=app), and refreshed on a TTL — never per request:
//
//   - A request that finds the index older than the TTL starts ONE background
//     refresh (single-flight) and is answered from what is there. Only the
//     very first listing on a pod waits for the first build, briefly.
//   - A refresh re-fetches an app's spec only when its head_sha moved, so a
//     quiet marketplace costs one listing call per TTL.
//   - A failed refresh keeps the last good index and says so (`refresh_error`
//     on the listing); it is retried after publicModuleRetry, not on every
//     request. An app whose spec could not be read keeps its previous entry.
//
// The index only ever says YES. resolveModule uses it to answer a public
// module without a fetch; anything the index does not hold as a valid public
// module (unknown owner or app, a module added since the last build, a
// private or refused one) falls through to the live fetch, so every refusal
// is exactly the one it was before. A hit is trusted for publicModuleMaxServe
// at most — if refreshes keep failing, resolve goes back to fetching rather
// than serve a spec of unknown age; the listing keeps showing the last good
// index, marked stale.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	publicModuleTTL       = 10 * time.Minute
	publicModuleRetry     = time.Minute      // after a failed refresh
	publicModuleMaxServe  = 20 * time.Minute // oldest index resolve trusts
	publicModuleFirstWait = 8 * time.Second  // first listing on a pod
	publicModuleNow       = time.Now
)

const (
	publicModuleListLimit   = 200 // xpcloud's /api/v1/repos cap
	publicModuleFetchers    = 6
	publicModuleRefreshTime = 90 * time.Second
)

// publicModule is one callable public module of a published app.
type publicModule struct {
	Name     string // "<owner>/<app>.<id>"
	Owner    string // the publisher's owner_sub
	App      string
	AppTitle string
	Module   appModule
}

// publicApp is what the index remembers of one published app: its head, so
// an unchanged app is not re-fetched, and its public modules.
type publicApp struct {
	head    string
	title   string
	modules []appModule // public and valid only
}

type publicModuleIndex struct {
	mu        sync.Mutex
	apps      map[string]publicApp // "<owner>/<app>"
	byName    map[string]publicModule
	list      []publicModule // sorted by name
	builtAt   time.Time      // last GOOD build
	triedAt   time.Time      // last attempt, good or not
	lastErr   string         // the last attempt's failure, "" when it succeeded
	skipped   []string       // apps whose spec could not be read in the last build
	truncated bool           // the listing hit its cap
	inflight  chan struct{}  // non-nil while a refresh runs
}

var publicModules = &publicModuleIndex{}

// resetPublicModules empties the index (tests).
func resetPublicModules() { publicModules = &publicModuleIndex{} }

// publishedRepo is one row of xpcloud's public listing.
type publishedRepo struct {
	Owner, Name, Title, Head string
}

// listPublishedApps reads the public app listing — the same one the
// Marketplace page browses — anonymously, so only public repos can appear.
func listPublishedApps(ctx context.Context) ([]publishedRepo, bool, error) {
	body, code, err := xpioPublicGet(ctx, fmt.Sprintf(
		"/api/v1/repos?kind=app&limit=%d&include_cycles=false", publicModuleListLimit))
	if err != nil {
		return nil, false, err
	}
	if code != http.StatusOK {
		return nil, false, fmt.Errorf("xp.io listing returned HTTP %d", code)
	}
	var parsed struct {
		Repos []map[string]any `json:"repos"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false, fmt.Errorf("xp.io listing is not JSON: %v", err)
	}
	out := make([]publishedRepo, 0, len(parsed.Repos))
	for _, r := range parsed.Repos {
		if v, _ := r["visibility"].(string); v != "public" {
			continue
		}
		owner, _ := r["owner_sub"].(string)
		name, _ := r["name"].(string)
		if !moduleOwnerRe.MatchString(owner) || !moduleAppRe.MatchString(name) {
			continue // not nameable as <owner>/<app>.<module>
		}
		title, _ := r["display_name"].(string)
		head, _ := r["head_sha"].(string)
		out = append(out, publishedRepo{Owner: owner, Name: name, Title: title, Head: head})
	}
	return out, len(parsed.Repos) >= publicModuleListLimit, nil
}

// fetchPublishedSpec reads a published app's spec anonymously (the dotfile
// first, as the runtime does).
func fetchPublishedSpec(ctx context.Context, owner, app string) ([]byte, error) {
	last := "no .xpcloud.yaml or xpcloud.yaml"
	for _, path := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
		body, code, err := xpioPublicGet(ctx, "/api/v1/repos/"+url.PathEscape(owner)+"/"+
			url.PathEscape(app)+"/blob/main/"+path)
		if err != nil {
			return nil, err
		}
		if code == http.StatusNotFound {
			continue
		}
		if code != http.StatusOK {
			last = fmt.Sprintf("HTTP %d reading %s", code, path)
			continue
		}
		var resp map[string]any
		if json.Unmarshal(body, &resp) != nil {
			last = path + " is not a blob"
			continue
		}
		content, _ := resp["content"].(string)
		if content == "" {
			continue
		}
		// Same reading as fetchRepoBlobAt, so the index and a live resolve
		// see the same spec.
		if dec, derr := base64.StdEncoding.DecodeString(content); derr == nil && len(dec) > 0 {
			return dec, nil
		}
		return []byte(content), nil
	}
	return nil, fmt.Errorf("%s", last)
}

// publicAppModules keeps a spec's public, valid modules. Private ones are not
// callable by anyone else, and a refused one is not callable at all.
func publicAppModules(spec []byte) []appModule {
	mods, _ := specModules(spec)
	var out []appModule
	for _, m := range mods {
		if m.Public {
			out = append(out, m)
		}
	}
	return out
}

// refresh rebuilds the index once. On a listing failure nothing changes but
// the error; an app whose spec cannot be read keeps its previous entry.
func (ix *publicModuleIndex) refresh(ctx context.Context) {
	repos, truncated, err := listPublishedApps(ctx)
	now := publicModuleNow()
	if err != nil {
		ix.mu.Lock()
		ix.triedAt, ix.lastErr = now, err.Error()
		n, built := len(ix.list), ix.builtAt
		ix.mu.Unlock()
		log.Printf("[public-modules] refresh failed: %v (keeping %d modules from %s)", err, n,
			built.UTC().Format(time.RFC3339))
		return
	}
	ix.mu.Lock()
	prev := ix.apps
	ix.mu.Unlock()

	apps := make(map[string]publicApp, len(repos))
	var (
		mu      sync.Mutex
		skipped []string
		wg      sync.WaitGroup
		slots   = make(chan struct{}, publicModuleFetchers)
	)
	for _, r := range repos {
		key := r.Owner + "/" + r.Name
		if old, has := prev[key]; has && r.Head != "" && old.head == r.Head {
			old.title = r.Title
			apps[key] = old
			continue
		}
		wg.Add(1)
		go func(r publishedRepo, key string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			spec, ferr := fetchPublishedSpec(ctx, r.Owner, r.Name)
			mu.Lock()
			defer mu.Unlock()
			if ferr != nil {
				skipped = append(skipped, key+": "+ferr.Error())
				if old, has := prev[key]; has {
					old.title = r.Title
					apps[key] = old // keep the last good read of this app
				}
				return
			}
			apps[key] = publicApp{head: r.Head, title: r.Title, modules: publicAppModules(spec)}
		}(r, key)
	}
	wg.Wait()

	byName := map[string]publicModule{}
	for key, a := range apps {
		owner, app := splitOwnerApp(key)
		for _, m := range a.modules {
			pm := publicModule{Name: key + "." + m.ID, Owner: owner, App: app, AppTitle: a.title, Module: m}
			byName[pm.Name] = pm
		}
	}
	list := make([]publicModule, 0, len(byName))
	for _, pm := range byName {
		list = append(list, pm)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	sort.Strings(skipped)

	ix.mu.Lock()
	ix.apps, ix.byName, ix.list = apps, byName, list
	ix.builtAt, ix.triedAt, ix.lastErr = now, now, ""
	ix.skipped, ix.truncated = skipped, truncated
	ix.mu.Unlock()
	if len(skipped) > 0 || truncated {
		log.Printf("[public-modules] built %d modules from %d apps (%d unreadable, truncated=%v)",
			len(list), len(apps), len(skipped), truncated)
	}
}

func splitOwnerApp(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			return key[:i], key[i+1:]
		}
	}
	return "", key
}

// due: a refresh should start now (called with ix.mu held).
func (ix *publicModuleIndex) due(now time.Time) bool {
	if ix.inflight != nil {
		return false
	}
	if ix.lastErr != "" {
		return now.Sub(ix.triedAt) >= publicModuleRetry
	}
	return ix.builtAt.IsZero() || now.Sub(ix.builtAt) >= publicModuleTTL
}

// kick starts a background refresh when one is due, and returns the channel
// that closes when the running refresh (if any) is done.
func (ix *publicModuleIndex) kick() chan struct{} {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.due(publicModuleNow()) {
		done := make(chan struct{})
		ix.inflight = done
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), publicModuleRefreshTime)
			defer cancel()
			defer func() {
				if r := recover(); r != nil {
					ix.mu.Lock()
					ix.triedAt, ix.lastErr = publicModuleNow(), fmt.Sprint("refresh panicked: ", r)
					ix.mu.Unlock()
				}
				ix.mu.Lock()
				ix.inflight = nil
				ix.mu.Unlock()
				close(done)
			}()
			ix.refresh(ctx)
		}()
	}
	return ix.inflight
}

// snapshot is the index as a listing shows it. Only a pod that has never
// built one waits (up to publicModuleFirstWait) for the first build.
func (ix *publicModuleIndex) snapshot() ([]publicModule, gin.H) {
	done := ix.kick()
	ix.mu.Lock()
	never := ix.builtAt.IsZero() && ix.lastErr == ""
	ix.mu.Unlock()
	if never && done != nil {
		select {
		case <-done:
		case <-time.After(publicModuleFirstWait):
		}
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	now := publicModuleNow()
	status := gin.H{"count": len(ix.list), "ttl_s": int(publicModuleTTL / time.Second)}
	switch {
	case !ix.builtAt.IsZero():
		status["built_at"] = ix.builtAt.UTC().Format(time.RFC3339)
		status["age_s"] = int(now.Sub(ix.builtAt) / time.Second)
	case ix.lastErr == "":
		status["note"] = "the public module index is still being built; ask again in a few seconds"
	}
	if ix.lastErr != "" {
		status["stale"] = true
		status["refresh_error"] = ix.lastErr
		if ix.builtAt.IsZero() {
			status["note"] = "the public module index could not be built (" + ix.lastErr +
				"); no public modules can be listed until xp.io answers — a module you know the name of " +
				"can still be called"
		} else {
			status["note"] = fmt.Sprintf("the public module index could not be refreshed at %s (%s); "+
				"showing the last good one, from %s", ix.triedAt.UTC().Format(time.RFC3339), ix.lastErr,
				ix.builtAt.UTC().Format(time.RFC3339))
		}
	}
	if len(ix.skipped) > 0 {
		status["unreadable_apps"] = len(ix.skipped)
	}
	if ix.truncated {
		status["truncated"] = true
	}
	return append([]publicModule(nil), ix.list...), status
}

// lookup answers a public module from the index, without a fetch. ok=false
// means "ask xpcloud" — never "refused".
func (ix *publicModuleIndex) lookup(owner, app, id string) (appModule, bool) {
	ix.kick()
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.builtAt.IsZero() || publicModuleNow().Sub(ix.builtAt) > publicModuleMaxServe {
		return appModule{}, false
	}
	pm, has := ix.byName[owner+"/"+app+"."+id]
	if !has || !pm.Module.Public {
		return appModule{}, false
	}
	return pm.Module, true
}

// publicModuleListing: the public modules for GET /me/measure/instruments
// ?public=1. The caller's own modules are not repeated, and an app the caller
// has installed shadows a public app of the same name: its bare
// "<app>.<module>" names are the caller's install, and that is what they see.
func publicModuleListing(sub string, shadow map[string]bool) ([]gin.H, gin.H) {
	mods, status := publicModules.snapshot()
	out := []gin.H{}
	shadowed := 0
	for _, pm := range mods {
		if pm.Owner == sub {
			continue // the caller's own app: listed (by its bare name) with ?app=
		}
		if shadow[pm.App] {
			shadowed++
			continue
		}
		item := moduleListItem(pm.Name, pm.Module)
		item["public"], item["owner"], item["app"] = true, pm.Owner, pm.App
		if pm.AppTitle != "" {
			item["app_title"] = pm.AppTitle
		}
		out = append(out, item)
	}
	if shadowed > 0 {
		status["shadowed"] = shadowed
	}
	return out, status
}

// moduleInstalledApps: the apps a caller has installed (a var so tests need
// no intent ledger).
var moduleInstalledApps = installedAppNames
