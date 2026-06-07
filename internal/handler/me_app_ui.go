package handler

// App-defined UI surfaces for the unified Studio shell.
//
//   GET /me/apps/:app/ui           — serve the app's default UI surface
//   GET /me/apps/:app/ui/:surface  — serve a named surface ("home" == default)
//
// An xpio app declares an optional `ui:` block in its xpcloud.yaml:
//
//   ui:
//     sidebar: { label, icon, section, order, badge_source }
//     surface: { markdown: "ui/home.md" }   # OR native: "<key>"
//
// `surface.markdown` is a bundle-relative path to a Markdown document the
// app builder authors; the Studio shell fetches it here and renders it at
// runtime (react-markdown + Lumid directive widgets). `surface.native` is a
// reserved, bundle-internal key resolved ONLY by the first-party client
// against its compiled registry — the server echoes it but never serves
// arbitrary code. Markdown serving reuses the same path-traversal guard as
// the dataset peek surface (resolveAppDir + abs-prefix check + .md-only +
// size cap), so an app author can never read outside their own bundle.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// ---- shared ui types (also consumed by me_apps.go MeAppsList) ----

type appUISidebar struct {
	Label       string `yaml:"label"        json:"label"`
	Icon        string `yaml:"icon"         json:"icon,omitempty"`
	Section     string `yaml:"section"      json:"section,omitempty"`
	Order       int    `yaml:"order"        json:"order,omitempty"`
	BadgeSource string `yaml:"badge_source" json:"badge_source,omitempty"`
}

type appUISurface struct {
	Markdown string `yaml:"markdown" json:"markdown,omitempty"`
	Native   string `yaml:"native"   json:"native,omitempty"`
}

type appUI struct {
	Sidebar *appUISidebar `yaml:"sidebar" json:"sidebar,omitempty"`
	Surface *appUISurface `yaml:"surface" json:"surface,omitempty"`
}

// readAppUI parses ONLY the `ui:` subtree from an app's xpcloud.yaml.
// Best-effort: any read/parse error (or no ui block) → nil, never fatal.
func readAppUI(appDir string) *appUI {
	b, err := os.ReadFile(filepath.Join(appDir, "xpcloud.yaml"))
	if err != nil {
		return nil
	}
	var doc struct {
		UI *appUI `yaml:"ui"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil
	}
	return doc.UI
}

// MeAppUI — GET /me/apps/:app/ui (default surface).
func MeAppUI(c *gin.Context) { serveAppSurface(c, "") }

// MeAppUISurface — GET /me/apps/:app/ui/:surface (named surface).
func MeAppUISurface(c *gin.Context) { serveAppSurface(c, c.Param("surface")) }

// serveAppSurface resolves the app dir, reads the ui.surface declaration,
// and returns the Markdown body (or the native key) for the requested
// surface. surfaceName "" or "home" maps to the single declared surface;
// other names 404 (named multi-surface support is a future extension).
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
	if surfaceName != "" && surfaceName != "home" {
		fail(c, http.StatusNotFound, 1404, "unknown surface")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	ui := readAppUI(appDir)
	if ui == nil || ui.Surface == nil {
		fail(c, http.StatusNotFound, 1404, "app declares no ui surface")
		return
	}

	// Native escape-hatch: no markdown body, the client resolves the key
	// against its first-party compiled registry.
	if ui.Surface.Markdown == "" {
		if ui.Surface.Native != "" {
			c.JSON(http.StatusOK, gin.H{
				"ret_code": 0, "message": "ok",
				"data": gin.H{"app": app, "surface": "home", "native": ui.Surface.Native},
			})
			return
		}
		fail(c, http.StatusNotFound, 1404, "ui surface has no markdown or native")
		return
	}

	// Path-guard: relative, no traversal, must stay under the app dir, .md only.
	rel := ui.Surface.Markdown
	if strings.ContainsAny(rel, "\x00") || strings.HasSuffix(rel, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid surface path")
		return
	}
	target := filepath.Join(appDir, rel)
	abs, err := filepath.Abs(target)
	if err != nil || !strings.HasPrefix(abs, appDir+string(os.PathSeparator)) {
		fail(c, http.StatusBadRequest, 1400, "invalid surface path")
		return
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
			"surface":   "home",
			"path":      rel,
			"markdown":  string(buf[:n]),
			"bytes":     st.Size(),
			"truncated": truncated,
		},
	})
}
