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

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

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
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	yamlPath := filepath.Join(appDir, "xpcloud.yaml")
	b, err := os.ReadFile(yamlPath)
	if err != nil {
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
		YAML string `json:"yaml" binding:"required"`
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

	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	yamlPath := filepath.Join(appDir, "xpcloud.yaml")

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

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"ok": true, "bytes": len(body.YAML)},
	})
}
