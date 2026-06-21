package handler

// Dataset / casebook explorer for the app-overview page.
//
//   GET /me/apps/:app/datasets            — list the data files an app's
//        loops run against (queries.jsonl + schema.sql for auto-sysresearch,
//        Case_*.json for mbb-ai, eval casebooks, etc.). Grouped by folder.
//   GET /me/apps/:app/dataset-file?path=  — read one file's content, capped
//        and path-guarded inside the app dir.
//
// Files are discovered under a fixed set of well-known dataset locations in
// the app bundle (tenant tree first, then operator-shared). This is a
// read-only peek surface — no traversal outside the app dir.

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// resolveAppDir returns the app's bundle dir (tenant tree first, then
// operator-shared), or "" if neither exists.
//
// `app` MUST be a single directory segment. Several callers gate it only with
// slugRe (which permits "/" and ".."), so we reject path separators and
// traversal HERE — the shared sink — rather than trusting each caller. Without
// this, `app = "../<victim_sub>/.xp/apps/<app>"` would filepath.Join out of the
// tenant root into another tenant's (or the operator's) bundle.
func resolveAppDir(userSub, app string) string {
	if app == "" || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		return ""
	}
	for _, base := range []string{tenantAppsDir(userSub), filepath.Join(operatorHome(), ".xp", "apps")} {
		dir := filepath.Join(base, app)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return ""
}

// resolveOwnedAppDir is the WRITE-path resolver: it returns ONLY the caller's
// own tenant install, never the operator-shared copy. `owned` is false (and the
// returned dir is "") when the app exists only as a shared bundle — callers
// must 403 rather than mutate a bundle every other tenant + the scheduler read.
// `shared` distinguishes "shared, not yours" from "not installed at all" for a
// clearer error. Mirrors the guard in me_app_skills.go.
func resolveOwnedAppDir(userSub, app string) (dir string, owned, shared bool) {
	if app == "" || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		return "", false, false
	}
	tenantDir := filepath.Join(tenantAppsDir(userSub), app)
	if st, err := os.Stat(tenantDir); err == nil && st.IsDir() {
		return tenantDir, true, false
	}
	if resolveAppDir(userSub, app) != "" {
		return "", false, true
	}
	return "", false, false
}

// Folders (relative to the app dir) we treat as dataset sources, with a
// human label and the extensions worth surfacing.
var datasetDirs = []struct {
	rel   string
	label string
	exts  []string
}{
	{"system", "Benchmark inputs", []string{".jsonl", ".sql", ".csv", ".md", ".txt", ".yaml"}},
	{"sample_data", "Sample cases", []string{".json", ".jsonl", ".csv"}},
	// Per-case roster folders — MUST stay in sync with me_casebook.go's
	// casebookCaseDirs. The casebook lists these cases; "view data" then loads
	// the matching file via MeAppDatasetFile (resolveCasePath scans this
	// listing), so the same folders must be discoverable here. Omitting
	// data/seed + data/cases is why mbb-ai cases showed in the rail but their
	// raw "case data" resolved to "(no seed file — live-data case)".
	{"data/cases", "Cases", []string{".json", ".jsonl", ".csv", ".md"}},
	{"data/seed", "Seed cases", []string{".json", ".jsonl", ".csv", ".md"}},
	{"data/eval-casebook", "Eval casebook", []string{".json", ".jsonl", ".md", ".csv"}},
	{"data/inbox", "Inbox cases", []string{".json", ".jsonl"}},
	{".lumid/inbox", "Inbox cases", []string{".json", ".jsonl"}},
	{"datasets", "Datasets", []string{".json", ".jsonl", ".csv", ".sql", ".txt"}},
}

func datasetKind(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jsonl":
		return "jsonl"
	case ".json":
		return "json"
	case ".sql":
		return "sql"
	case ".csv":
		return "csv"
	case ".md":
		return "markdown"
	case ".yaml", ".yml":
		return "yaml"
	default:
		return "text"
	}
}

// MeAppDatasets — GET /me/apps/:app/datasets
func MeAppDatasets(c *gin.Context) {
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

	type fileEntry struct {
		Path  string `json:"path"` // relative to app dir
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
		Kind  string `json:"kind"`
	}
	type group struct {
		Group string      `json:"group"`
		Label string      `json:"label"`
		Files []fileEntry `json:"files"`
	}
	groups := make([]group, 0, len(datasetDirs))

	for _, d := range datasetDirs {
		dirAbs := filepath.Join(appDir, d.rel)
		ents, err := os.ReadDir(dirAbs)
		if err != nil {
			continue
		}
		files := make([]fileEntry, 0, len(ents))
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			match := false
			for _, x := range d.exts {
				if ext == x {
					match = true
					break
				}
			}
			if !match {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			files = append(files, fileEntry{
				Path:  filepath.Join(d.rel, e.Name()),
				Name:  e.Name(),
				Bytes: info.Size(),
				Kind:  datasetKind(e.Name()),
			})
		}
		if len(files) == 0 {
			continue
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
		groups = append(groups, group{Group: d.rel, Label: d.label, Files: files})
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "datasets": groups, "count": len(groups)},
	})
}

// MeAppDatasetFile — GET /me/apps/:app/dataset-file?path=<rel>
// Returns the file content capped at 64 KB (with a truncated flag).
func MeAppDatasetFile(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	rel := c.Query("path")
	if !slugRe.MatchString(app) || rel == "" {
		fail(c, http.StatusBadRequest, 1400, "invalid app or path")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	target := filepath.Join(appDir, rel)
	abs, err := filepath.Abs(target)
	if err != nil || !strings.HasPrefix(abs, appDir+string(os.PathSeparator)) {
		fail(c, http.StatusBadRequest, 1400, "invalid path")
		return
	}
	st, err := os.Stat(abs)
	if err != nil || st.IsDir() {
		fail(c, http.StatusNotFound, 1404, "file not found")
		return
	}
	const maxBytes = 64 * 1024
	f, err := os.Open(abs)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot read file")
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
			"path":      rel,
			"name":      filepath.Base(rel),
			"kind":      datasetKind(rel),
			"bytes":     st.Size(),
			"truncated": truncated,
			"content":   string(buf[:n]),
		},
	})
}
