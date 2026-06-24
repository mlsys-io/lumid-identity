package handler

// Per-run PROVENANCE — the versioned assets a single run used.
//
//   GET /me/cycles/:app/:loop/:ts/provenance
//
// Authoritative from cycle.json's `assets_used` block (written by the runner)
// when present; otherwise a best-effort DERIVATION so historical runs still
// populate the Studio's Data + Agents panels: dataset version, the metric it's
// scored on, and the agent's knowledge-bank version as-of this run.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// MeCycleProvenance — GET /me/cycles/:app/:loop/:ts/provenance
func MeCycleProvenance(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	ts := c.Param("ts")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop")
		return
	}
	// ts is a cycle dir id (20060102T150405Z) — reject path separators/traversal.
	if ts == "" || strings.ContainsAny(ts, "/\\") || strings.Contains(ts, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid ts")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// 1. Authoritative: the runner's assets_used block.
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	if b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, ts, "cycle.json")); err == nil {
		var cj map[string]any
		if json.Unmarshal(b, &cj) == nil {
			if au, ok := cj["assets_used"].(map[string]any); ok && len(au) > 0 {
				c.JSON(http.StatusOK, gin.H{
					"ret_code": 0, "message": "ok",
					"data": gin.H{"assets_used": au, "derived": false},
				})
				return
			}
		}
	}

	// 2. Derived best-effort (historical runs without a manifest).
	au := gin.H{"app": gin.H{"name": app, "version": readAppVersion(appDir)}}
	if ds := readAppDatasets(appDir); len(ds) > 0 {
		d := ds[0]
		au["dataset"] = gin.H{"id": d.ID, "repo": d.Repo, "version": d.Version}
	}
	if av := agentVersionAt(appAgentMemoryTimes(userID, appDir), ts); av != "" {
		au["agent_version"] = av
	}
	if exps := loopExperiments(appDir, loop); len(exps) > 0 {
		allow := map[string]bool{}
		for _, x := range exps {
			allow[x] = true
		}
		if expID, expDir := pickExperiment(appDir, "", allow, true); expDir != "" {
			metric, higher, _, _ := readExperimentState(expDir)
			if metric != "" {
				au["metric"] = gin.H{"name": metric, "higher_is_better": higher, "experiment": expID}
			}
		}
	}
	if roles := readYamlMemoryAgents(specPathFor(appDir)); len(roles) > 0 {
		au["memory_agents"] = roles
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"assets_used": au, "derived": true},
	})
}

// specPathFor returns the app's spec (xpcloud.yaml) path for memory-agent reads.
func specPathFor(appDir string) string {
	p, _ := ResolveSpecPath(appDir)
	return p
}
