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
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// currentConfigSHA computes the sha of the merged spec (base ⊕ override) the
// GET would return for the cross-node config path — the optimistic-lock token.
// Returns ("", false) when the base spec can't be resolved.
func currentConfigSHA(userID, app, overrideJSON string) (string, bool) {
	base, _, ok := specForApp(userID, app)
	if !ok {
		return "", false
	}
	merged, ok := overlayConfigOntoSpec(base, overrideJSON)
	if !ok {
		return "", false
	}
	return contentSHA(merged), true
}

// fetchRepoSpecYAML reads the app's xpcloud.yaml from the caller's xp.io repo.
// Cross-node fallback: on UKS identity (service tier) can't see the scheduler's
// app PVC (compute tier, RWO), so the local file read 404s. identity CAN reach
// xpcloud, and the published bundle carries the same spec — so the Config/Manage
// surfaces (config_schema, loops, etc.) work without a shared filesystem.
// Best-effort; ("", false) on any miss. Owner is assumed to be the caller (the
// common case: a user manages their own installed app).
func fetchRepoSpecYAML(userID, app string) ([]byte, bool) {
	bearer, err := xpcloudUserJWT(userID)
	if err != nil {
		return nil, false
	}
	for _, p := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
		url := xpcloudBaseURL() + "/api/v1/repos/" + userID + "/" + app + "/blob/main/" + p
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
	// Cross-node fallback: read the spec via specForApp (MeAppSpec DB store →
	// published xp.io repo) when the local file isn't visible (identity ≠
	// scheduler node). specForApp covers installed-not-published apps too, which
	// fetchRepoSpecYAML alone missed.
	if len(b) == 0 {
		if fetched, _, ok := specForApp(userID, app); ok {
			b = fetched
		}
	}
	if len(b) == 0 {
		fail(c, http.StatusNotFound, 1404, "xpcloud.yaml not found")
		return
	}
	// Overlay the caller's config override (me_docs app_config_override) onto the
	// base spec's top-level `config:` map, so a cross-node PUT round-trips through
	// GET. The override body is the full config map JSON.
	if raw, has := appConfigOverrideGet(userID, app); has {
		if merged, ok := overlayConfigOntoSpec(b, raw); ok {
			b = merged
		}
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

// overlayConfigOntoSpec replaces the top-level `config:` map in a spec's YAML
// bytes with the override (a JSON object). Returns (mergedYAML, true) on
// success; (nil, false) when either side can't be parsed (caller keeps base).
func overlayConfigOntoSpec(specYAML []byte, overrideJSON string) ([]byte, bool) {
	var doc map[string]any
	if yaml.Unmarshal(specYAML, &doc) != nil {
		return nil, false
	}
	if doc == nil {
		doc = map[string]any{}
	}
	var cfg any
	if json.Unmarshal([]byte(overrideJSON), &cfg) != nil {
		return nil, false
	}
	doc["config"] = cfg
	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
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
	var check map[string]any
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
		// Cross-node: the tenant install lives on the scheduler PVC this pod
		// can't see. Store the edit as a config override in me_docs (ITEM 3)
		// instead of dead-ending on 404 — the scheduler pulls it at cycle start
		// via /internal/app-config-override/fetch. We persist ONLY the top-level
		// `config:` map (the user-editable surface); the rest of xpcloud.yaml is
		// the app author's and stays on the published/DB spec. A bogus app 404s.
		if _, _, okSpec := specForApp(userID, app); !okSpec {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		cfg := check["config"]
		if cfg == nil {
			cfg = map[string]any{}
		}
		cfgJSON, err := json.Marshal(cfg)
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not encode config override")
			return
		}
		// Optimistic lock against the existing override only — a first-time
		// override starts from the published/DB baseline (mirrors the disk path).
		if body.BaseSHA != "" {
			if cur, has := appConfigOverrideGet(userID, app); has {
				if merged, ok := currentConfigSHA(userID, app, cur); ok && merged != body.BaseSHA {
					fail(c, http.StatusConflict, 1409,
						"config changed since you loaded it — reload to pick up the other edit, then reapply yours")
					return
				}
			}
		}
		if err := appConfigOverrideSave(userID, app, string(cfgJSON)); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not save config override")
			return
		}
		// Echo the sha of the merged spec (base ⊕ override) so the editor can
		// chain further saves without a reload — matches the GET's sha source.
		newSHA := ""
		if base, _, ok := specForApp(userID, app); ok {
			if merged, ok := overlayConfigOntoSpec(base, string(cfgJSON)); ok {
				newSHA = contentSHA(merged)
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"ok": true, "bytes": len(body.YAML), "sha": newSHA},
		})
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
