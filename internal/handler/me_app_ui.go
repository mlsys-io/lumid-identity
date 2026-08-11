package handler

// App-defined UI surfaces for the unified Studio shell.
//
//   GET /me/apps/:app/ui           — serve the app's default UI surface
//   GET /me/apps/:app/ui/:surface  — serve a named surface ("home" == default)
//   PUT /me/apps/:app/ui           — write/create the default surface markdown
//   PUT /me/apps/:app/ui/:surface  — write/create a named surface markdown
//
// An xpio app declares an optional `ui:` block in its xpcloud.yaml:
//
//   ui:
//     sidebar: { show: true, label, icon, section, order, badge_source }
//     surface:  { markdown: "ui/home.md" }   # OR native: "<key>" (default surface)
//     surfaces: { home: "ui/home.md", detail: "ui/detail.md" }  # optional, named
//
// Special markdown path prefixes (fork template sharing):
//
//   "@fork_of"        — inherit the parent app's markdown (fork_of field in xpcloud.yaml)
//   "@shared/<name>"  — read from ~/.xp/apps/.templates/<name>.md (operator-level shared)
//
// `sidebar.show` is the explicit on/off toggle (omit → shown when a sidebar
// block is present; false → keep the config but hide the entry).
//
// Markdown serving reuses the same path-traversal guard as the dataset peek
// surface (resolveAppDir + abs-prefix check + .md-only + size cap), so an
// app author can never read outside their own bundle.
//
// PUT writes are tenant-only (operator-shared dirs are not writable via the
// API — the identity container runs as a different UID). For @fork_of and
// @shared surfaces, PUT writes a per-fork override to ui/home.md and updates
// xpcloud.yaml to point to it (detaches the fork from the template).

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// ---- shared ui types (also consumed by me_apps.go MeAppsList) ----

type appUISidebar struct {
	// Show is the explicit on/off toggle. nil (omitted) = shown when a sidebar
	// block is present (back-compat); false = keep label/icon config but hide.
	Show        *bool  `yaml:"show"         json:"show,omitempty"`
	Label       string `yaml:"label"        json:"label"`
	Icon        string `yaml:"icon"         json:"icon,omitempty"`
	Section     string `yaml:"section"      json:"section,omitempty"`
	Order       int    `yaml:"order"        json:"order,omitempty"`
	BadgeSource string `yaml:"badge_source" json:"badge_source,omitempty"`
}

type appUISurface struct {
	Markdown string `yaml:"markdown" json:"markdown,omitempty"`
	Native   string `yaml:"native"   json:"native,omitempty"`
	// Page is a STRUCTURED page spec (ui/page.yaml) compiled to lumid markdown
	// on serve — the reliable, deterministic surface. When set, it's the
	// source of truth; no separate compiled home.md is kept.
	Page string `yaml:"page" json:"page,omitempty"`
}

// appUINavItem is one entry in an app's surface switcher (ui.nav).
type appUINavItem struct {
	Surface string `yaml:"surface" json:"surface"`
	Label   string `yaml:"label"   json:"label,omitempty"`
}

type appUI struct {
	Sidebar *appUISidebar `yaml:"sidebar" json:"sidebar,omitempty"`
	// Surface is the default ("home") surface — kept for back-compat.
	Surface *appUISurface `yaml:"surface" json:"surface,omitempty"`
	// Surfaces is the optional named-markdown map (name → bundle-relative .md).
	// Each is reachable at /studio/a/<app>/<name>; "home" is the default.
	Surfaces map[string]string `yaml:"surfaces" json:"surfaces,omitempty"`
	// Nav is an optional ORDERED surface switcher. When set, the client renders
	// a tab bar so a multi-surface app's surfaces are pickable from any of them
	// (not just via home-page links). Only list param-free, directly-routable
	// surfaces (each links to /studio/a/<app>/<surface>).
	Nav []appUINavItem `yaml:"nav" json:"nav,omitempty"`
}

// readAppUI parses ONLY the `ui:` subtree from an app's xpcloud.yaml.
// Best-effort: any read/parse error (or no ui block) → nil, never fatal.
func readAppUI(appDir string) *appUI {
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	return parseAppUI(b)
}

// parseAppUI extracts the ui: block from a spec's raw bytes. Lets the
// cross-node fallback (fetchRepoSpecYAML) build a sidebar entry for a tenant
// app whose files identity can't read from disk (svc node ≠ scheduler PVC).
func parseAppUI(b []byte) *appUI {
	var doc struct {
		UI *appUI `yaml:"ui"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil
	}
	return doc.UI
}

// readAppConfig parses the TOP-LEVEL `config:` map from an app's xpcloud.yaml.
// This is the app's user-editable configuration (the Config button edits it) —
// surfaces receive it so widgets like the data-app browser take their defaults
// from config instead of hard-coded directive values. Best-effort → nil.
func readAppConfig(appDir string) map[string]any {
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	return parseAppConfigBytes(b)
}

// parseAppConfigBytes is readAppConfig's body, split out so the cross-node
// fallback can reuse it on a spec fetched over HTTP instead of read from disk.
func parseAppConfigBytes(b []byte) map[string]any {
	var doc struct {
		Config map[string]any `yaml:"config"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil
	}
	return doc.Config
}

// readForkOf returns the fork_of field from an app's xpcloud.yaml, or "".
func readForkOf(appDir string) string {
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return ""
	}
	var doc struct {
		ForkOf string `yaml:"fork_of"`
	}
	_ = yaml.Unmarshal(b, &doc)
	return doc.ForkOf
}

var sharedTemplateNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// resolveSpecialMdPath handles @fork_of and @shared/<name> markdown paths.
// Returns (resolvedMdPath, resolvedAppDir); empty strings signal "not found".
// Never recurses — if the parent also uses @fork_of, returns ("", "").
func resolveSpecialMdPath(special, currentAppDir, userID string) (mdPath, appDir string) {
	switch {
	case special == "@fork_of":
		parent := readForkOf(currentAppDir)
		if parent == "" {
			return "", ""
		}
		// Strip owner prefix (owner/name → name) for resolveAppDir lookup.
		parentName := parent
		if i := strings.LastIndex(parent, "/"); i >= 0 {
			parentName = parent[i+1:]
		}
		parentDir := resolveAppDir(userID, parentName)
		if parentDir == "" {
			return "", ""
		}
		parentUI := readAppUI(parentDir)
		if parentUI == nil {
			return "", ""
		}
		// Read the parent's home surface path. Do NOT recurse if parent also @fork_of.
		var parentMd string
		if p, ok := parentUI.Surfaces["home"]; ok {
			parentMd = p
		} else if parentUI.Surface != nil {
			parentMd = parentUI.Surface.Markdown
		}
		if parentMd == "" || strings.HasPrefix(parentMd, "@") {
			return "", ""
		}
		return parentMd, parentDir

	case strings.HasPrefix(special, "@shared/"):
		name := strings.TrimPrefix(special, "@shared/")
		if !sharedTemplateNameRe.MatchString(name) {
			return "", ""
		}
		templatesDir := filepath.Join(operatorHome(), ".xp", "apps", ".templates")
		mdFile := filepath.Join(templatesDir, name+".md")
		return mdFile, templatesDir
	}
	return "", ""
}

// MeAppUI — GET /me/apps/:app/ui (default surface).
func MeAppUI(c *gin.Context) { serveAppSurface(c, "") }

// MeAppUISurface — GET /me/apps/:app/ui/:surface (named surface).
func MeAppUISurface(c *gin.Context) { serveAppSurface(c, c.Param("surface")) }

// serveAppSurface resolves the app dir, reads the ui.surface declaration,
// and returns the Markdown body (or the native key) for the requested surface.
func serveAppSurface(c *gin.Context, surfaceName string) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	name := surfaceName
	if name == "" {
		name = "home"
	}
	// Cross-node fallback, mirroring MeAppConfig. identity runs on the service
	// tier and does not mount the scheduler's xpio-state PVC, so a CLOUD-installed
	// tenant app has no files here at all. Without this the handler 404s
	// ("app not found") for every such app — including ones that are installed,
	// healthy, and listed by /me/apps — which reads as "the app has no UI" when
	// really it is "identity cannot see the disk". The published bundle carries
	// the same bytes, so serve from there when the local dir is absent.
	appDir := resolveAppDir(userID, app)
	remote := appDir == ""

	var ui *appUI
	var appCfg map[string]any
	if remote {
		spec, ok := fetchRepoSpecYAML(userID, app)
		if !ok {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		ui = parseAppUI(spec)
		appCfg = parseAppConfigBytes(spec)
	} else {
		ui = readAppUI(appDir)
		appCfg = readAppConfig(appDir)
	}
	if ui == nil || (ui.Surface == nil && len(ui.Surfaces) == 0) {
		fail(c, http.StatusNotFound, 1404, "app declares no ui surface")
		return
	}

	// Resolve the requested surface name → (markdown path | native key | page spec).
	var mdPath, native, pagePath string
	if p, ok := ui.Surfaces[name]; ok {
		mdPath = p
	} else if name == "home" && ui.Surface != nil {
		mdPath, native, pagePath = ui.Surface.Markdown, ui.Surface.Native, ui.Surface.Page
	} else {
		fail(c, http.StatusNotFound, 1404, "unknown surface")
		return
	}
	// Named surfaces may ALSO be structured page specs — a `surfaces:` entry
	// pointing at a .yaml compiles through compilePageSpec exactly like the
	// default surface's `page:`. This keeps every tab of a multi-surface app
	// in the configurable spec format (not just home).
	if strings.HasSuffix(strings.ToLower(mdPath), ".yaml") || strings.HasSuffix(strings.ToLower(mdPath), ".yml") {
		pagePath, mdPath = mdPath, ""
	}

	// Structured page spec → compile to markdown on serve (deterministic, no
	// stored home.md). The spec (ui/page.yaml) is the single source of truth.
	if pagePath != "" {
		if strings.ContainsAny(pagePath, "\x00") || strings.Contains(pagePath, "..") || filepath.IsAbs(pagePath) {
			fail(c, http.StatusBadRequest, 1400, "invalid page path")
			return
		}
		var pb []byte
		if remote {
			var ok bool
			if pb, ok = fetchRepoBlob(userID, app, pagePath); !ok {
				fail(c, http.StatusNotFound, 1404, "page spec not found: "+pagePath)
				return
			}
		} else {
			abs := filepath.Clean(filepath.Join(appDir, pagePath))
			if abs != appDir && !strings.HasPrefix(abs, appDir+string(filepath.Separator)) {
				fail(c, http.StatusBadRequest, 1400, "page path escapes app")
				return
			}
			var rerr error
			if pb, rerr = os.ReadFile(abs); rerr != nil {
				fail(c, http.StatusNotFound, 1404, "page spec not found: "+pagePath)
				return
			}
		}
		md, cerr := compilePageSpec(pb)
		if cerr != nil {
			fail(c, http.StatusUnprocessableEntity, 1422, "page spec: "+cerr.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"app": app, "surface": name, "markdown": md, "path": pagePath,
				"nav": ui.Nav, "config": appCfg,
				// The editable source of truth: the editor edits THIS (the
				// markdown above is compiled output). sha backs the PUT's
				// optimistic lock.
				"format": "page",
				"spec":   string(pb),
				"sha":    contentSHA(pb),
			},
		})
		return
	}

	// Native escape-hatch: no markdown body, the client resolves the key
	// against its first-party compiled registry.
	if mdPath == "" {
		if native != "" {
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"app": app, "surface": name, "native": native, "nav": ui.Nav, "config": appCfg},
			})
			return
		}
		fail(c, http.StatusNotFound, 1404, "ui surface has no markdown or native")
		return
	}

	// Special path prefixes: @fork_of inherits from the parent app;
	// @shared/<name> reads from the operator-level shared templates dir.
	// The resolved path is reported back as-is so the client can show
	// "inherits from template" in the editor UI.
	resolvedPath := mdPath
	// Remote (cloud-installed) apps: the .md body comes from the published
	// bundle. The @fork_of / @shared indirections below are filesystem-only
	// (they resolve against a parent app dir / the operator templates dir), so
	// a remote app declaring one is served as "not found" rather than silently
	// falling through to a path guard that would reject it anyway.
	if remote {
		if strings.HasPrefix(mdPath, "@") {
			fail(c, http.StatusNotFound, 1404, "template surfaces need a local install ("+mdPath+")")
			return
		}
		if strings.ToLower(filepath.Ext(mdPath)) != ".md" {
			fail(c, http.StatusBadRequest, 1400, "surface must be a .md file")
			return
		}
		body, ok := fetchRepoBlob(userID, app, mdPath)
		if !ok {
			fail(c, http.StatusNotFound, 1404, "surface file not found")
			return
		}
		const maxRemote = 256 * 1024
		truncated := false
		if len(body) > maxRemote {
			body, truncated = body[:maxRemote], true
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{
				"app": app, "surface": name, "path": mdPath,
				"markdown": string(body), "bytes": len(body), "truncated": truncated,
				"nav": ui.Nav, "config": appCfg, "sha": contentSHA(body),
			},
		})
		return
	}
	if strings.HasPrefix(mdPath, "@") {
		var resolvedDir string
		resolvedPath, resolvedDir = resolveSpecialMdPath(mdPath, appDir, userID)
		if resolvedPath == "" {
			fail(c, http.StatusNotFound, 1404, "template not found ("+mdPath+")")
			return
		}
		// For @shared, resolvedPath is an absolute path; treat it directly.
		// For @fork_of, resolvedPath is relative to resolvedDir.
		if strings.HasPrefix(mdPath, "@shared/") {
			return // handled below — abs path used directly
		}
		appDir = resolvedDir
	}

	// Path-guard: relative, no traversal, must stay under the app dir, .md only.
	var abs string
	if filepath.IsAbs(resolvedPath) {
		// @shared — absolute path already validated by sharedTemplateNameRe.
		abs = resolvedPath
	} else {
		rel := resolvedPath
		if strings.ContainsAny(rel, "\x00") || strings.HasSuffix(rel, "/") {
			fail(c, http.StatusBadRequest, 1400, "invalid surface path")
			return
		}
		target := filepath.Join(appDir, rel)
		var err error
		abs, err = filepath.Abs(target)
		if err != nil || !strings.HasPrefix(abs, appDir+string(os.PathSeparator)) {
			fail(c, http.StatusBadRequest, 1400, "invalid surface path")
			return
		}
	}
	if strings.ToLower(filepath.Ext(abs)) != ".md" {
		fail(c, http.StatusBadRequest, 1400, "surface must be a .md file")
		return
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		fail(c, http.StatusNotFound, 1404, "surface file not found")
		return
	}

	const maxBytes = 256 * 1024
	f, err := os.Open(abs)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot read surface")
		return
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	truncated := st.Size() > int64(n)

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":       app,
			"surface":   name,
			"path":      mdPath, // original declared path (may be "@fork_of" etc.)
			"markdown":  string(buf[:n]),
			"bytes":     st.Size(),
			"truncated": truncated,
			"nav":       ui.Nav,
			"config":    appCfg,
			"sha":       contentSHA(buf[:n]), // optimistic-lock token for PUT
		},
	})
}

// ── Write endpoint ─────────────────────────────────────────────────────────

// MeUpdateAppUI — PUT /me/apps/:app/ui
func MeUpdateAppUI(c *gin.Context) { updateAppSurface(c, "") }

// MeUpdateAppUISurface — PUT /me/apps/:app/ui/:surface
func MeUpdateAppUISurface(c *gin.Context) { updateAppSurface(c, c.Param("surface")) }

type meUpdateAppUIBody struct {
	// Exactly one of Markdown / Spec is the payload: Markdown for .md
	// surfaces, Spec (raw page.yaml text) for structured page surfaces.
	Markdown string `json:"markdown"`
	Spec     string `json:"spec"`
	Surface  string `json:"surface"`
	// BaseSHA is the sha returned by the GET this edit started from —
	// optimistic lock; mismatch → 409 (stale buffer, someone else saved).
	BaseSHA string `json:"base_sha"`
}

// updateAppSurface writes the caller's markdown to the resolved surface file.
// Writes are tenant-only; operator-shared apps are read-only via the API.
// For @fork_of / @shared surfaces, writes a per-fork override ui/home.md and
// patches xpcloud.yaml to point to it (detaches from the shared template).
func updateAppSurface(c *gin.Context, surfaceName string) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}

	var body meUpdateAppUIBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid request body")
		return
	}
	if body.Markdown == "" && body.Spec == "" {
		fail(c, http.StatusBadRequest, 1400, "body needs `markdown` (md surface) or `spec` (page surface)")
		return
	}
	name := surfaceName
	if name == "" {
		if body.Surface != "" {
			name = body.Surface
		} else {
			name = "home"
		}
	}
	const maxBytes = 256 * 1024
	if len(body.Markdown) > maxBytes || len(body.Spec) > maxBytes {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "surface exceeds 256 KB limit")
		return
	}

	// WRITE path: the surface must live in the caller's OWN tenant install.
	// Both dirs are bind-mounted RW into the container, so editing the
	// operator-shared copy would silently change the surface for every other
	// tenant + the scheduler — refuse it (install your own fork first).
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	ui := readAppUI(appDir)
	if ui == nil || (ui.Surface == nil && len(ui.Surfaces) == 0) {
		fail(c, http.StatusNotFound, 1404, "app declares no ui surface")
		return
	}
	// Resolve the surface → declared markdown path (or structured page spec).
	var mdPath, pagePath string
	if p, ok := ui.Surfaces[name]; ok {
		if low := strings.ToLower(p); strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") {
			pagePath = p
		} else {
			mdPath = p
		}
	} else if name == "home" && ui.Surface != nil {
		mdPath, pagePath = ui.Surface.Markdown, ui.Surface.Page
	} else {
		fail(c, http.StatusNotFound, 1404, "unknown surface")
		return
	}

	// Structured page surface — the SPEC is the editable artifact (the served
	// markdown is compiled output). Validate through the compiler so a broken
	// spec can never be saved, honor the optimistic lock, write atomically.
	if pagePath != "" {
		if body.Spec == "" {
			fail(c, http.StatusBadRequest, 1400,
				"this surface is a structured page spec — send `spec` (the raw "+pagePath+" text), not markdown")
			return
		}
		if strings.ContainsAny(pagePath, "\x00") || strings.Contains(pagePath, "..") || filepath.IsAbs(pagePath) {
			fail(c, http.StatusBadRequest, 1400, "invalid page path")
			return
		}
		absSpec := filepath.Clean(filepath.Join(appDir, pagePath))
		if !strings.HasPrefix(absSpec, appDir+string(filepath.Separator)) {
			fail(c, http.StatusBadRequest, 1400, "page path escapes app")
			return
		}
		if _, cerr := compilePageSpec([]byte(body.Spec)); cerr != nil {
			fail(c, http.StatusUnprocessableEntity, 1422, "page spec invalid: "+cerr.Error())
			return
		}
		if body.BaseSHA != "" {
			if cur, rerr := os.ReadFile(absSpec); rerr == nil && contentSHA(cur) != body.BaseSHA {
				fail(c, http.StatusConflict, 1409,
					"this page changed since you loaded it — reload to pick up the other edit, then reapply yours")
				return
			}
		}
		if err := os.MkdirAll(filepath.Dir(absSpec), 0755); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "cannot create surface directory")
			return
		}
		tmp := absSpec + ".tmp"
		if err := os.WriteFile(tmp, []byte(body.Spec), 0644); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "cannot write page spec")
			return
		}
		if err := os.Rename(tmp, absSpec); err != nil {
			_ = os.Remove(tmp)
			fail(c, http.StatusInternalServerError, 1500, "cannot save page spec")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"ok": true, "path": pagePath, "bytes": len(body.Spec),
				"format": "page", "sha": contentSHA([]byte(body.Spec))},
		})
		return
	}

	if body.Markdown == "" {
		fail(c, http.StatusBadRequest, 1400, "this surface is markdown — send `markdown`")
		return
	}
	if mdPath == "" && ui.Surface != nil && ui.Surface.Native != "" {
		fail(c, http.StatusBadRequest, 1400, "native surfaces are not editable via the API")
		return
	}

	// For template-inherited paths, write to a local override and patch xpcloud.yaml.
	// New override files land in the canonical ".ui/" dotfile directory.
	if strings.HasPrefix(mdPath, "@") {
		overridePath := appUIWriteRef("home.md")
		mdPath = overridePath
		if err := patchXpcloudUISurface(appDir, name, overridePath); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "failed to update xpcloud.yaml: "+err.Error())
			return
		}
	}

	if mdPath == "" {
		// No declared path — default to the canonical .ui/home.md and write it.
		mdPath = appUIWriteRef("home.md")
	}

	// Path-guard: same as GET.
	if strings.ContainsAny(mdPath, "\x00") || strings.HasSuffix(mdPath, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid surface path")
		return
	}
	target := filepath.Join(appDir, mdPath)
	abs, err := filepath.Abs(target)
	if err != nil || !strings.HasPrefix(abs, appDir+string(os.PathSeparator)) {
		fail(c, http.StatusBadRequest, 1400, "invalid surface path")
		return
	}
	if strings.ToLower(filepath.Ext(abs)) != ".md" {
		fail(c, http.StatusBadRequest, 1400, "surface must be a .md file")
		return
	}

	// Optimistic lock — refuse a stale-buffer save (see meUpdateAppUIBody).
	if body.BaseSHA != "" {
		if cur, rerr := os.ReadFile(abs); rerr == nil && contentSHA(cur) != body.BaseSHA {
			fail(c, http.StatusConflict, 1409,
				"this page changed since you loaded it — reload to pick up the other edit, then reapply yours")
			return
		}
	}

	// Create parent dirs if writing for the first time.
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot create surface directory")
		return
	}

	// Atomic write: tmp → rename to avoid partial reads.
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, []byte(body.Markdown), 0644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot write surface")
		return
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "cannot save surface")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"ok": true, "path": mdPath, "bytes": len(body.Markdown),
			"sha": contentSHA([]byte(body.Markdown))},
	})
}

// patchXpcloudUISurface rewrites the ui.surface.markdown (or ui.surfaces[name])
// field in xpcloud.yaml to point to a local override path. Used when the user
// edits a @fork_of or @shared surface — their edit becomes a fork-specific file.
// patchXpcloudUISurfacePage sets ui.surface.page (and clears markdown/native)
// so the structured spec becomes the home surface — compiled on serve.
func patchXpcloudUISurfacePage(appDir, pagePath string) error {
	readPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(readPath)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	ui, _ := doc["ui"].(map[string]interface{})
	if ui == nil {
		ui = map[string]interface{}{}
		doc["ui"] = ui
	}
	surface, _ := ui["surface"].(map[string]interface{})
	if surface == nil {
		surface = map[string]interface{}{}
		ui["surface"] = surface
	}
	surface["page"] = pagePath
	delete(surface, "markdown")
	delete(surface, "native")
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	yamlPath := SpecWritePath(appDir)
	tmp := yamlPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, yamlPath); err != nil {
		return err
	}
	// Avoid orphaning a pre-existing legacy spec now that the dotfile is canonical.
	if readPath != yamlPath {
		_ = os.Remove(readPath)
	}
	return nil
}

func patchXpcloudUISurface(appDir, surfaceName, newPath string) error {
	readPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(readPath)
	if err != nil {
		return err
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	ui, _ := doc["ui"].(map[string]interface{})
	if ui == nil {
		ui = map[string]interface{}{}
		doc["ui"] = ui
	}
	if surfaceName == "home" {
		surface, _ := ui["surface"].(map[string]interface{})
		if surface == nil {
			surface = map[string]interface{}{}
			ui["surface"] = surface
		}
		surface["markdown"] = newPath
		delete(surface, "native") // clear native if present
	} else {
		surfaces, _ := ui["surfaces"].(map[string]interface{})
		if surfaces == nil {
			surfaces = map[string]interface{}{}
			ui["surfaces"] = surfaces
		}
		surfaces[surfaceName] = newPath
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	yamlPath := SpecWritePath(appDir)
	tmp := yamlPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, yamlPath); err != nil {
		return err
	}
	// Avoid orphaning a pre-existing legacy spec now that the dotfile is canonical.
	if readPath != yamlPath {
		_ = os.Remove(readPath)
	}
	return nil
}
