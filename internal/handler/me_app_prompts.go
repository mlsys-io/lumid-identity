package handler

// Prompt editor — read/write the analyst & judge prompts an app's loops run on.
//
//   GET    /me/apps/:app/prompts        — list local + inherited shared prompts
//   GET    /me/apps/:app/prompts/:name  — read one prompt's content + source + sha
//   PUT    /me/apps/:app/prompts/:name  — write a LOCAL override (own app only)
//   DELETE /me/apps/:app/prompts/:name  — remove the local override (revert to shared)
//
// Per-app prompts live as markdown under <appDir>/prompts/*.md (analyst_system.md,
// analyst_skill_*.md, judge_*.md). The lumid-al-core resolver loads them two-tier:
// a LOCAL copy under the app's own prompts/ always overrides the same-named copy
// inherited from an imported skill (skill_imports[] → ~/.xp/skills/<owner>/<repo>/
// prompts/). So a safe per-app override path already exists at runtime — these
// endpoints just give the UI/agent a way to read + write it.
//
// Security mirrors me_app_ui.go / me_app_config.go exactly:
//   - GET uses resolveAppDir (tenant-first, operator-shared fallback) so any
//     installed app's prompts are readable.
//   - PUT/DELETE use ownerWriteTarget — writes land ONLY in the caller's own
//     tenant install; an operator-shared bundle is read-only (403). We never
//     touch the shared skill file (DELETE removes the local override only).
//     When that install is on the scheduler's disk (UKS), the write is queued
//     as an app_file_write intent (202) and reads apply its overlay.
//   - Path-guard via safeAppJoin (no traversal / absolute / NUL), .md-only.
//   - PUT honors an optimistic lock (base_sha) and writes atomically (tmp+rename).

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const promptMaxBytes = 256 * 1024 // prompts are markdown cards — generous cap

// promptDirRel is the bundle-relative directory holding an app's prompt cards.
const promptDirRel = "prompts"

// promptInfo is one row in the prompt list.
type promptInfo struct {
	Name     string `json:"name"`
	Source   string `json:"source"` // "local" | "shared:<owner>/<repo>"
	Editable bool   `json:"editable"`
	SHA      string `json:"sha,omitempty"`
}

// appPromptSkillImports reads skill_imports[].repo from the app's xpcloud.yaml.
// Best-effort: any read/parse error → nil. Mirrors resolveAppSkills' shape.
func appPromptSkillImports(appDir string) []string {
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	var doc struct {
		SkillImports []struct {
			Repo string `yaml:"repo"`
		} `yaml:"skill_imports"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, si := range doc.SkillImports {
		repo := strings.TrimSpace(si.Repo)
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		out = append(out, repo)
	}
	return out
}

// skillPromptsDir returns the prompts/ dir for an imported skill repo
// ("owner/name"), checking the caller's tenant skills tree first, then the
// operator-shared one — the same precedence as the runtime resolver. Returns ""
// when the repo has no prompts dir in either root.
func skillPromptsDir(userSub, repo string) string {
	for _, root := range []string{
		filepath.Join(tenantRoot(userSub), ".xp", "skills"),
		filepath.Join(operatorHome(), ".xp", "skills"),
	} {
		dir := filepath.Join(root, filepath.FromSlash(repo), promptDirRel)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir
		}
	}
	return ""
}

// localPromptsDir is the app's own prompts/ dir (may not exist yet).
func localPromptsDir(appDir string) string {
	return filepath.Join(appDir, promptDirRel)
}

// readMdNames returns the *.md filenames in dir (no path), or nil.
func readMdNames(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range ents {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if strings.ToLower(filepath.Ext(e.Name())) == ".md" {
			out = append(out, e.Name())
		}
	}
	return out
}

// validPromptName gates the :name path segment: a plain .md filename, no
// traversal / separators (it flows into safeAppJoin under prompts/).
func validPromptName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\\x00") || strings.Contains(name, "..") {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	return strings.ToLower(filepath.Ext(name)) == ".md"
}

// MeAppPrompts — GET /me/apps/:app/prompts
func MeAppPrompts(c *gin.Context) {
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
	// Writable when the caller has their own install — on a disk identity can
	// see (direct) or one only the scheduler can (queued). A shared app's
	// prompts are read-only here (the user forks/installs first to edit).
	prompts := listAppPrompts(userID, app, appDir, ownerCanEdit(userID, app))
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "prompts": prompts},
	})
}

// listAppPrompts builds the prompt list for an app: inherited shared-skill
// prompts, shadowed by the app's own prompts/, shadowed by any applied
// app_file_write overlay (see me_app_file_intent.go). The overlay is what makes
// an edit — or a newly CREATED prompt — visible when the app's files are only
// on the scheduler's disk and this pod reads the published bundle.
func listAppPrompts(userID, app, appDir string, editable bool) []promptInfo {
	shared := map[string]promptInfo{}
	for _, repo := range appPromptSkillImports(appDir) {
		sdir := skillPromptsDir(userID, repo)
		if sdir == "" {
			continue
		}
		for _, name := range readMdNames(sdir) {
			if _, has := shared[name]; has {
				continue // first import wins, as in resolvePromptRead
			}
			// A shared prompt is editable iff the caller owns the app (editing
			// creates a LOCAL override; the shared file is never mutated).
			p := promptInfo{Name: name, Source: "shared:" + repo, Editable: editable}
			if b, err := os.ReadFile(filepath.Join(sdir, name)); err == nil {
				p.SHA = contentSHA(b)
			}
			shared[name] = p
		}
	}
	// Local prompts override shared (same name → source flips to "local").
	local := map[string]promptInfo{}
	for _, name := range readMdNames(localPromptsDir(appDir)) {
		p := promptInfo{Name: name, Source: "local", Editable: editable}
		if b, err := os.ReadFile(filepath.Join(localPromptsDir(appDir), name)); err == nil {
			p.SHA = contentSHA(b)
		}
		local[name] = p
	}
	// Applied-but-unpublished writes win over the bundle; a delete removes the
	// local override, so the name falls back to its shared copy (or vanishes).
	for name, ov := range appFileOverlayNames(userID, app, promptDirRel) {
		if !validPromptName(name) {
			continue
		}
		if ov.Deleted {
			delete(local, name)
			continue
		}
		local[name] = promptInfo{Name: name, Source: "local", Editable: editable, SHA: contentSHA(ov.Content)}
	}
	for name, p := range local {
		shared[name] = p
	}
	names := make([]string, 0, len(shared))
	for name := range shared {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]promptInfo, 0, len(names))
	for _, name := range names {
		out = append(out, shared[name])
	}
	return out
}

// readAppPrompt returns a prompt's bytes + source, honouring the app_file_write
// overlay first (an applied edit wins; an applied delete skips the local copy
// and falls back to the shared one). found=false → no such prompt.
func readAppPrompt(userID, app, appDir, name string) (b []byte, source string, found bool, err error) {
	content, deleted, has := appFileOverlay(userID, app, promptDirRel+"/"+name)
	if has && !deleted {
		return content, "local", true, nil
	}
	var p string
	if has && deleted {
		p, source = resolveSharedPromptRead(userID, appDir, name)
	} else {
		p, source = resolvePromptRead(userID, appDir, name)
	}
	if p == "" {
		return nil, "", false, nil
	}
	b, err = os.ReadFile(p)
	return b, source, true, err
}

// resolvePromptRead returns the on-disk path + source for a prompt, preferring a
// local override over the inherited shared copy. ("" path, "" source) → missing.
func resolvePromptRead(userSub, appDir, name string) (path, source string) {
	local := filepath.Join(localPromptsDir(appDir), name)
	if st, err := os.Stat(local); err == nil && !st.IsDir() {
		return local, "local"
	}
	return resolveSharedPromptRead(userSub, appDir, name)
}

// resolveSharedPromptRead is resolvePromptRead without the local override.
func resolveSharedPromptRead(userSub, appDir, name string) (path, source string) {
	for _, repo := range appPromptSkillImports(appDir) {
		sdir := skillPromptsDir(userSub, repo)
		if sdir == "" {
			continue
		}
		p := filepath.Join(sdir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, "shared:" + repo
		}
	}
	return "", ""
}

// MeAppPrompt — GET /me/apps/:app/prompts/:name
func MeAppPrompt(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	name := c.Param("name")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if !validPromptName(name) {
		fail(c, http.StatusBadRequest, 1400, "invalid prompt name (.md only)")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	b, source, found, err := readAppPrompt(userID, app, appDir, name)
	if !found {
		fail(c, http.StatusNotFound, 1404, "prompt not found: "+name)
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot read prompt")
		return
	}
	if len(b) > promptMaxBytes {
		b = b[:promptMaxBytes]
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":      app,
			"name":     name,
			"content":  string(b),
			"source":   source,
			"sha":      contentSHA(b),
			"editable": ownerCanEdit(userID, app),
			// The bundle-relative path the override is/would be written to.
			"path": filepath.Join(promptDirRel, name),
		},
	})
}

// MeUpdateAppPrompt — PUT /me/apps/:app/prompts/:name
func MeUpdateAppPrompt(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	name := c.Param("name")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if !validPromptName(name) {
		fail(c, http.StatusBadRequest, 1400, "invalid prompt name (.md only)")
		return
	}
	var body struct {
		Content string `json:"content" binding:"required"`
		BaseSHA string `json:"base_sha"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid request body")
		return
	}
	if len(body.Content) > promptMaxBytes {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "prompt exceeds 256 KB limit")
		return
	}

	// WRITE path: the caller's OWN tenant install only — never the operator-
	// shared bundle (read by the scheduler + every other tenant). On UKS that
	// install is on the scheduler's disk, not ours, so the write is queued as an
	// app_file_write for the process that can see it (me_app_file_intent.go).
	appDir, direct, viaIntent, shared := ownerWriteTarget(userID, app)
	if viaIntent {
		enqueueAppFileWrite(c, userID, app, promptDirRel+"/"+name, "write", body.Content, body.BaseSHA)
		return
	}
	if !direct {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// Path-guard: stays under <appDir>/prompts, .md only.
	abs, err := safeAppJoin(appDir, filepath.Join(promptDirRel, name))
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid prompt path")
		return
	}
	if strings.ToLower(filepath.Ext(abs)) != ".md" {
		fail(c, http.StatusBadRequest, 1400, "prompt must be a .md file")
		return
	}

	// Optimistic lock: base_sha is checked against the LOCAL override only — a
	// first-time override (no local file yet) starts from the shared baseline, so
	// we only enforce when a local file already exists.
	if body.BaseSHA != "" {
		if cur, rerr := os.ReadFile(abs); rerr == nil && contentSHA(cur) != body.BaseSHA {
			fail(c, http.StatusConflict, 1409,
				"this prompt changed since you loaded it — reload to pick up the other edit, then reapply yours")
			return
		}
	}

	if err := writeFileAtomic(abs, []byte(body.Content)); err != nil {
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"saved": true, "sha": contentSHA([]byte(body.Content))},
	})
}

// MeDeleteAppPrompt — DELETE /me/apps/:app/prompts/:name
// Removes the LOCAL override only (reverting to the inherited shared prompt);
// the shared skill file is never touched.
func MeDeleteAppPrompt(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	name := c.Param("name")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if !validPromptName(name) {
		fail(c, http.StatusBadRequest, 1400, "invalid prompt name (.md only)")
		return
	}
	// Same routing as the PUT: the scheduler removes the override when the
	// install is on its disk (op "delete" on a missing file is a no-op there).
	appDir, direct, viaIntent, shared := ownerWriteTarget(userID, app)
	if viaIntent {
		enqueueAppFileWrite(c, userID, app, promptDirRel+"/"+name, "delete", "", "")
		return
	}
	if !direct {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	abs, err := safeAppJoin(appDir, filepath.Join(promptDirRel, name))
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid prompt path")
		return
	}
	// Only ever remove a LOCAL override. If none exists, that's a no-op success
	// (the prompt already resolves to the shared copy).
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		fail(c, http.StatusInternalServerError, 1500, "cannot remove prompt override")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"reverted": true},
	})
}
