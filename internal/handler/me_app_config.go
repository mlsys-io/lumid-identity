package handler

// App configuration editor — read and write an installed app's xpcloud.yaml.
//
//   GET /me/apps/:app/config  — return the raw xpcloud.yaml text
//   PUT /me/apps/:app/config  — validate (YAML parse check) + write atomically
//
// Same security model as the surface editor: resolveAppDir (tenant-first,
// operator-shared fallback), size cap (64 KB), no path traversal.
// The PUT validates that the submitted text is parseable YAML before writing
// so a syntax error never silently breaks the app's runtime manifest.
//
// Concurrency: writes are OPTIMISTICALLY LOCKED. GET returns a `sha` of the
// current bytes; PUT carries it back as `base_sha` and the server 409s when
// the file changed since that read — so a stale editor tab can no longer
// silently clobber edits made elsewhere (the Manage panel, another tab, an
// agent). base_sha is optional for back-compat: CLI/scripted writers that
// don't send it keep last-write-wins semantics.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// fetchRepoSpecYAML reads the app's xpcloud.yaml from the caller's xp.io repo.
// Cross-node fallback: on UKS identity (service tier) can't see the scheduler's
// app PVC (compute tier, RWO), so the local file read 404s. identity CAN reach
// xpcloud, and the published bundle carries the same spec — so the Config/Manage
// surfaces (config_schema, loops, etc.) work without a shared filesystem.
// Best-effort; ("", false) on any miss. Owner is assumed to be the caller (the
// common case: a user manages their own installed app).
// fetchRepoBlob reads ONE file from the caller's xp.io repo. This is the
// cross-node escape hatch: identity runs on the service tier and does not mount
// the scheduler's xpio-state PVC, so a tenant app's files simply are not on its
// filesystem. The published bundle is the same content, reachable over HTTP.
//
// `paths` are tried in order and the first hit wins — the publisher stores the
// spec dot-prefixed (`.xpcloud.yaml`) while the working tree uses the bare name,
// so both spellings have to be probed.
func fetchRepoBlob(userID, app string, paths ...string) ([]byte, bool) {
	// Validate FIRST. The repo API is path-addressed, so a traversal here would
	// read another repo's blob — refuse rather than normalize. Screening before
	// minting the JWT also means a bad path costs no DB lookup and no request.
	safe := paths[:0:0]
	for _, p := range paths {
		if p == "" || strings.Contains(p, "..") || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00") {
			continue
		}
		safe = append(safe, p)
	}
	if len(safe) == 0 {
		return nil, false
	}
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		return nil, false
	}
	// The repo belongs to whoever PUBLISHED the app, which is only the caller
	// when they authored it. Addressing repos/<caller>/<app> made every
	// cloud-installed app 404 for everyone but its author — surfaces blank,
	// spec missing, so no sidebar entry and no nav tabs. repoOwnerFor reads the
	// owner off the install record and falls back to the caller.
	owner := repoOwnerFor(userID, app)
	for _, p := range safe {
		url := xpcloudBaseURL() + "/api/v1/repos/" + owner + "/" + app + "/blob/main/" + p
		code, resp, err := xpcloudJSON(http.MethodGet, url, bearer, nil)
		if err != nil || code >= 300 || resp == nil {
			continue
		}
		content, _ := resp["content"].(string)
		if content == "" {
			continue
		}
		if dec, derr := base64.StdEncoding.DecodeString(content); derr == nil && len(dec) > 0 {
			return dec, true
		}
		return []byte(content), true
	}
	return nil, false
}

func fetchRepoSpecYAML(userID, app string) ([]byte, bool) {
	return fetchRepoBlob(userID, app, ".xpcloud.yaml", "xpcloud.yaml")
}

func contentSHA(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const configMaxBytes = 64 * 1024 // 64 KB — xpcloud.yaml is always small

// MeAppConfig — GET /me/apps/:app/config
func MeAppConfig(c *gin.Context) {
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
	var b []byte
	if appDir := resolveAppDir(userID, app); appDir != "" {
		if yamlPath, _ := ResolveSpecPath(appDir); yamlPath != "" {
			b, _ = os.ReadFile(yamlPath)
		}
	}
	// Cross-node fallback: read the spec from the caller's xp.io repo when the
	// local file isn't visible (identity ≠ scheduler node; see fetchRepoSpecYAML).
	if len(b) == 0 {
		if fetched, ok := fetchRepoSpecYAML(userID, app); ok {
			b = fetched
		}
	}
	if len(b) == 0 {
		fail(c, http.StatusNotFound, 1404, "xpcloud.yaml not found")
		return
	}
	if len(b) > configMaxBytes {
		b = b[:configMaxBytes]
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":   app,
			"yaml":  string(b),
			"bytes": len(b),
			"sha":   contentSHA(b),
		},
	})
}

// MeUpdateAppConfig — PUT /me/apps/:app/config
func MeUpdateAppConfig(c *gin.Context) {
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

	var body struct {
		YAML    string `json:"yaml" binding:"required"`
		BaseSHA string `json:"base_sha"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid request body")
		return
	}
	if len(body.YAML) > configMaxBytes {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "config exceeds 64 KB limit")
		return
	}

	// Validate: must be parseable YAML before we touch the file.
	var check interface{}
	if err := yaml.Unmarshal([]byte(body.YAML), &check); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid YAML: "+err.Error())
		return
	}

	// WRITE path: only the caller's own tenant install may be mutated — never
	// the operator-shared bundle (which the scheduler + every other tenant read).
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	// Read against whichever file currently exists (dotfile or legacy) for
	// the optimistic-lock check; write the canonical dotfile.
	readPath, _ := ResolveSpecPath(appDir)
	yamlPath := SpecWritePath(appDir)

	// Optimistic lock: refuse a write based on a stale read. A 409 means
	// "someone else changed the config since you loaded it" — the client
	// reloads, reapplies, and retries.
	if body.BaseSHA != "" {
		if cur, err := os.ReadFile(readPath); err == nil && contentSHA(cur) != body.BaseSHA {
			fail(c, http.StatusConflict, 1409,
				"config changed since you loaded it — reload to pick up the other edit, then reapply yours")
			return
		}
	}

	// Atomic write.
	tmp := yamlPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(body.YAML), 0644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot write config")
		return
	}
	if err := os.Rename(tmp, yamlPath); err != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "cannot save config")
		return
	}
	// Don't orphan a pre-existing legacy file once the dotfile is the truth.
	if readPath != yamlPath {
		_ = os.Remove(readPath)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		// Echo the new sha so the editor can chain further saves without a reload.
		"data": gin.H{"ok": true, "bytes": len(body.YAML), "sha": contentSHA([]byte(body.YAML))},
	})
}
