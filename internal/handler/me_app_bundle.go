package handler

// GET /api/v1/me/apps/:app/bundle?path=<rel> — read one file (or list one
// directory) of an installed app, read-only. The app chat needs it: asked to
// write a Quant Research strategy "like the ofi_momentum_v1 sample", it knew
// the sample sat at sample_data/ofi_momentum_v1.lqts and had no tool that
// could open it, so it declined rather than guess the DSL (2026-11-27). The
// LumidOS MCP tool `app_file` calls this with the user's own token.
//
// What it serves, and from where:
//   - the caller's saved edits first (the same overlay the editors read);
//   - then the caller's own install (tenant dir), or the app's PUBLISHED bundle
//     (materialiseTenantApp) — the same bytes anyone can read on xp.io;
//   - the operator-shared ~/.xp/apps tree only to admins: it holds the
//     operator's runtime state beside the bundle.
//
// Never: dotfiles other than the spec, secret-looking names, anything outside
// the app dir. Files over 200 KB are truncated; non-UTF-8 files are reported,
// not returned.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

const (
	appBundleMaxBytes   = 200 * 1024
	appBundleMaxEntries = 500
)

var appBundleSecretRe = regexp.MustCompile(`(?i)(secret|credential|password|passwd|token|apikey|api_key|private[_-]?key|\.pem$|\.key$|\.p12$|\.pfx$|id_rsa|id_ed25519|\.env$)`)

// appBundlePathOK reports whether rel (already normalised) may be served.
func appBundlePathOK(rel string) bool {
	if rel == "" || rel == "." {
		return true // the app root (a listing)
	}
	if strings.HasPrefix(rel, "/") || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" || seg == ".." {
			return false
		}
		if strings.HasPrefix(seg, ".") && rel != appFileSpecRel {
			return false
		}
		if appBundleSecretRe.MatchString(seg) {
			return false
		}
	}
	return true
}

// appBundleRoot picks the directory a caller may read the app from.
func appBundleRoot(userID, role, app string) string {
	if role == "admin" || role == "super_admin" {
		return resolveAppDir(userID, app)
	}
	if dir := filepath.Join(tenantAppsDir(userID), app); dirExists(dir) {
		return dir
	}
	return materialiseTenantApp(userID, app)
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// MeAppBundleFile — GET /me/apps/:app/bundle?path=<rel>
func MeAppBundleFile(c *gin.Context) {
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
	raw := c.Query("path")
	rel := normAppFileRel(raw)
	if rel == "." {
		rel = ""
	}
	if !appBundlePathOK(rel) {
		fail(c, http.StatusBadRequest, 1400, "path not readable: dotfiles, secrets and paths outside the app are not served")
		return
	}
	// The caller's saved edit wins, exactly as in the editors.
	if rel != "" {
		if ob, deleted, found := appFileOverlay(userID, app, rel); found {
			if deleted {
				fail(c, http.StatusNotFound, 1404, "deleted")
				return
			}
			c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": appBundleFileBody(app, rel, ob, "overlay")})
			return
		}
	}
	root := appBundleRoot(userID, currentUserRole(c), app)
	if root == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	abs := filepath.Clean(filepath.Join(root, filepath.FromSlash(rel)))
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		fail(c, http.StatusBadRequest, 1400, "path escapes the app")
		return
	}
	// A symlink inside the bundle must not lead out of it.
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		if rr, rerr := filepath.EvalSymlinks(root); rerr == nil && real != rr && !strings.HasPrefix(real, rr+string(filepath.Separator)) {
			fail(c, http.StatusBadRequest, 1400, "path escapes the app")
			return
		}
	}
	st, err := os.Stat(abs)
	if err != nil {
		fail(c, http.StatusNotFound, 1404, "no such file")
		return
	}
	if st.IsDir() {
		entries, err := os.ReadDir(abs)
		if err != nil {
			fail(c, http.StatusNotFound, 1404, "no such directory")
			return
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			child := e.Name()
			if rel != "" {
				child = rel + "/" + child
			}
			if !appBundlePathOK(child) {
				continue
			}
			if e.IsDir() {
				names = append(names, e.Name()+"/")
			} else {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		truncated := len(names) > appBundleMaxEntries
		if truncated {
			names = names[:appBundleMaxEntries]
		}
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
			"app": app, "path": rel, "is_dir": true, "entries": names, "truncated": truncated,
		}})
		return
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		fail(c, http.StatusNotFound, 1404, "no such file")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": appBundleFileBody(app, rel, b, "bundle")})
}

func appBundleFileBody(app, rel string, b []byte, source string) gin.H {
	size := len(b)
	truncated := false
	if len(b) > appBundleMaxBytes {
		b = b[:appBundleMaxBytes]
		truncated = true
	}
	out := gin.H{"app": app, "path": rel, "is_dir": false, "size": size, "truncated": truncated, "source": source}
	if truncated {
		// The cut may split a rune: back off to the last whole one.
		for i := 0; i < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1]
		}
	}
	if !utf8.Valid(b) {
		out["binary"] = true
		return out
	}
	out["content"] = string(b)
	return out
}
