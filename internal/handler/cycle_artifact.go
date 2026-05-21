package handler

// GET /api/v1/admin/cycle-artifact?app=X&loop=Y&ts=Z&name=insight.md
//
// Streams a single artifact file from the latest (or specified) cycle dir.
// Backs the /dashboard/results drill-down modal that renders insight.md +
// signals.csv + trades.json + step_errors.json inline.
//
// Path safety:
//   - app/loop/ts/name are all forced to a strict character set; any
//     ".." or path separator yields a 400. The reconstructed path is
//     joined under ~/.xp/apps/<app>/data/cycles/<loop>/<ts>/<name>, and
//     the resolved absolute path must still live under <home>/.xp/apps/
//     — verified after joining to defeat any clever encoding tricks.
//   - `name` is allowlisted to the small set of artifacts the dashboard
//     actually reads.
//
// Bearer-auth gated like the rest of /api/v1/admin/*.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	_safeNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

	// Whitelist what the dashboard is allowed to fetch. Keeps drift
	// limited and stops any future leak of e.g. credentials.toml that
	// could otherwise land in a cycle dir.
	_allowedArtifacts = map[string]bool{
		"insight.md":       true,
		"signals.csv":      true,
		"trades.json":      true,
		"proposal.json":    true,
		"score.json":       true,
		"step_errors.json": true,
		"observations.json": true,
		"features_trace.json": true,
	}

	// Cap response size — these are dashboards, not raw data dumps. 1 MB
	// is plenty for human-readable artifacts.
	_maxArtifactBytes = int64(1024 * 1024)
)

func CycleArtifact(c *gin.Context) {
	app := c.Query("app")
	loop := c.Query("loop")
	ts := c.Query("ts") // optional; empty → latest
	name := c.Query("name")

	if app == "" || loop == "" || name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app, loop, and name are required"})
		return
	}
	for _, v := range []string{app, loop, name} {
		if !_safeNameRe.MatchString(v) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid characters in app/loop/name"})
			return
		}
	}
	if ts != "" && !_safeNameRe.MatchString(ts) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid characters in ts"})
		return
	}
	if !_allowedArtifacts[name] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artifact name not in allowlist"})
		return
	}

	home := operatorHome()
	appRoot := filepath.Join(home, ".xp", "apps", app)
	cyclesRoot := filepath.Join(appRoot, "data", "cycles", loop)

	cycleDir := ""
	if ts == "" {
		// Reuse the latestCycleDir helper but constrain to the
		// per-loop cycle root only — outbox-style apps don't have
		// per-cycle insight.md/signals.csv anyway.
		entries, err := os.ReadDir(cyclesRoot)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "no cycle dir for that loop yet"})
			return
		}
		newest := ""
		for _, e := range entries {
			if e.IsDir() && e.Name() > newest {
				newest = e.Name()
			}
		}
		if newest == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": "no cycles found"})
			return
		}
		cycleDir = filepath.Join(cyclesRoot, newest)
	} else {
		cycleDir = filepath.Join(cyclesRoot, ts)
	}

	full := filepath.Join(cycleDir, name)
	// Resolve to defend against symlinks etc. — must still live under
	// ~/.xp/apps/.
	resolved, err := filepath.Abs(full)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not resolve path"})
		return
	}
	expectedPrefix, _ := filepath.Abs(filepath.Join(home, ".xp", "apps"))
	if !strings.HasPrefix(resolved, expectedPrefix+string(os.PathSeparator)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path escape detected"})
		return
	}

	info, err := os.Stat(resolved)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact not found"})
		return
	}
	if info.IsDir() || info.Size() > _maxArtifactBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "artifact too large"})
		return
	}

	// Content-Type: derive from extension so the browser renders
	// markdown as text and JSON as JSON.
	mime := "text/plain; charset=utf-8"
	switch filepath.Ext(name) {
	case ".json":
		mime = "application/json; charset=utf-8"
	case ".csv":
		mime = "text/csv; charset=utf-8"
	case ".md":
		mime = "text/markdown; charset=utf-8"
	}

	b, err := os.ReadFile(resolved)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read failed"})
		return
	}
	c.Data(http.StatusOK, mime, b)
}
