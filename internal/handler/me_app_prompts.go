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
//   - PUT/DELETE use resolveOwnedAppDir — writes land ONLY in the caller's own
//     tenant install; an operator-shared bundle is read-only (403). We never
//     touch the shared skill file (DELETE removes the local override only).
//   - Path-guard via safeAppJoin (no traversal / absolute / NUL), .md-only.
//   - PUT honors an optimistic lock (base_sha) and writes atomically (tmp+rename).

import (
	"encoding/json"
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

// ── cross-node prompt overrides (DB) ─────────────────────────────────────────
//
// On UKS the tenant install lives on the SCHEDULER pod's PVC, which identity
// can't mount (RWO, different node) — so the on-disk local-override write path
// is unreachable and PUT used to dead-end. When the bundle isn't on this pod's
// disk, overrides land in me_docs instead (the same replica-safe store that
// fixed chats/personas), keyed deterministically per (app, prompt). Reads on
// the cross-node path prefer the DB override over the published-repo blob, so
// GET-after-PUT round-trips. NOTE: like the casebook/trajectory fallbacks this
// is a Studio-surface fix — the scheduler's runtime prompt resolver still reads
// the PVC files, so a DB override doesn't reach cycle execution yet (the
// remaining half of the cross-node tenant-app-files gap).

// meDocKindPrompt — MeDoc kind for cross-node prompt overrides.
const meDocKindPrompt = "app_prompt"

// promptOverrideDoc is the me_docs payload for one override.
type promptOverrideDoc struct {
	App     string `json:"app"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// promptOverrideID — deterministic doc_id for (app, name). sha256 hex is
// exactly 64 chars (the me_docs key width); app+name raw can exceed it.
func promptOverrideID(app, name string) string {
	return contentSHA([]byte(app + "/" + name))
}

// promptOverrideGet returns the override content for (app, name), if any.
func promptOverrideGet(userSub, app, name string) (string, bool) {
	doc, found, err := meDocGet(userSub, meDocKindPrompt, promptOverrideID(app, name))
	if err != nil || !found {
		return "", false
	}
	var d promptOverrideDoc
	if json.Unmarshal([]byte(doc), &d) != nil {
		return "", false
	}
	return d.Content, true
}

// promptOverridesForApp returns name → content for all of the caller's
// overrides on one app.
func promptOverridesForApp(userSub, app string) map[string]string {
	rows, err := meDocList(userSub, meDocKindPrompt)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, r := range rows {
		var d promptOverrideDoc
		if json.Unmarshal([]byte(r.Doc), &d) == nil && d.App == app && validPromptName(d.Name) {
			out[d.Name] = d.Content
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
// publishedPromptNames lists *.md under the app's published repo prompts/ dir
// (authenticated, so private repos resolve). Cross-node read-only fallback.
func publishedPromptNames(userID, app string) []string {
	out := []string{}
	for _, name := range publishedTreeBlobs(userID, app, promptDirRel) {
		if strings.HasSuffix(name, ".md") {
			out = append(out, name)
		}
	}
	return out
}

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
		// Cross-node: identity can't read the tenant PVC. List the app's prompts
		// from the caller's PUBLISHED xp.io repo, shadowed by any DB overrides
		// (a same-named override flips source to "local", like the disk path).
		// Editable is true — PUT works cross-node via the me_docs override store.
		names := publishedPromptNames(userID, app)
		ovr := promptOverridesForApp(userID, app)
		seen := map[string]bool{}
		prompts := make([]promptInfo, 0, len(names)+len(ovr))
		for _, n := range names {
			seen[n] = true
			pi := promptInfo{Name: n, Source: "published", Editable: true}
			if content, has := ovr[n]; has {
				pi.Source = "local"
				pi.SHA = contentSHA([]byte(content))
			}
			prompts = append(prompts, pi)
		}
		extras := []string{}
		for n := range ovr {
			if !seen[n] {
				extras = append(extras, n)
			}
		}
		sort.Strings(extras)
		for _, n := range extras {
			prompts = append(prompts, promptInfo{
				Name: n, Source: "local", Editable: true, SHA: contentSHA([]byte(ovr[n]))})
		}
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
			"data": gin.H{"app": app, "prompts": prompts}})
		return
	}
	// Writable only when the caller owns the app (tenant install). A shared app's
	// prompts are read-only here (the user forks/installs first to edit).
	_, owned, _ := resolveOwnedAppDir(userID, app)

	type acc struct {
		info promptInfo
	}
	byName := map[string]*acc{}
	order := []string{}
	upsert := func(name string) *acc {
		if a, has := byName[name]; has {
			return a
		}
		a := &acc{info: promptInfo{Name: name}}
		byName[name] = a
		order = append(order, name)
		return a
	}

	// Inherited shared-skill prompts first (so a later local entry shadows them).
	for _, repo := range appPromptSkillImports(appDir) {
		sdir := skillPromptsDir(userID, repo)
		if sdir == "" {
			continue
		}
		for _, name := range readMdNames(sdir) {
			a := upsert(name)
			a.info.Source = "shared:" + repo
			// A shared prompt is editable iff the caller owns the app (editing
			// creates a LOCAL override; the shared file is never mutated).
			a.info.Editable = owned
			if b, err := os.ReadFile(filepath.Join(sdir, name)); err == nil {
				a.info.SHA = contentSHA(b)
			}
		}
	}

	// Local prompts override shared (same name → source flips to "local").
	for _, name := range readMdNames(localPromptsDir(appDir)) {
		a := upsert(name)
		a.info.Source = "local"
		a.info.Editable = owned
		if b, err := os.ReadFile(filepath.Join(localPromptsDir(appDir), name)); err == nil {
			a.info.SHA = contentSHA(b)
		}
	}

	sort.Strings(order)
	prompts := make([]promptInfo, 0, len(order))
	for _, name := range order {
		prompts = append(prompts, byName[name].info)
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "prompts": prompts},
	})
}

// resolvePromptRead returns the on-disk path + source for a prompt, preferring a
// local override over the inherited shared copy. ("" path, "" source) → missing.
func resolvePromptRead(userSub, appDir, name string) (path, source string) {
	local := filepath.Join(localPromptsDir(appDir), name)
	if st, err := os.Stat(local); err == nil && !st.IsDir() {
		return local, "local"
	}
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
// publishedPromptBlob reads one prompt's bytes from the app's published repo
// (authenticated). Cross-node read-only fallback for MeAppPrompt.
func publishedPromptBlob(userID, app, name string) []byte {
	return publishedRepoBlob(userID, app, promptDirRel+"/"+name)
}

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
		// Cross-node: a DB override (written by the cross-node PUT) wins over
		// the published-repo blob — same local-shadows-shared precedence as disk.
		if content, has := promptOverrideGet(userID, app, name); has {
			b := []byte(content)
			if len(b) > promptMaxBytes {
				b = b[:promptMaxBytes]
			}
			c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
				"data": gin.H{"app": app, "name": name, "content": string(b),
					"source": "local", "sha": contentSHA(b), "editable": true,
					"path": filepath.Join(promptDirRel, name)}})
			return
		}
		if body := publishedPromptBlob(userID, app, name); body != nil {
			if len(body) > promptMaxBytes {
				body = body[:promptMaxBytes]
			}
			c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
				"data": gin.H{"app": app, "name": name, "content": string(body),
					"source": "published", "sha": contentSHA(body), "editable": true,
					"path": filepath.Join(promptDirRel, name)}})
			return
		}
		fail(c, http.StatusNotFound, 1404, "prompt not found: "+name)
		return
	}
	path, source := resolvePromptRead(userID, appDir, name)
	if path == "" {
		fail(c, http.StatusNotFound, 1404, "prompt not found: "+name)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot read prompt")
		return
	}
	if len(b) > promptMaxBytes {
		b = b[:promptMaxBytes]
	}
	_, owned, _ := resolveOwnedAppDir(userID, app)
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":      app,
			"name":     name,
			"content":  string(b),
			"source":   source,
			"sha":      contentSHA(b),
			"editable": owned,
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
	// shared bundle (read by the scheduler + every other tenant).
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		// Cross-node: the tenant install lives on the scheduler PVC this pod
		// can't see. Accept the override into the DB store when the app resolves
		// as the caller's own published repo (the ownership proxy fetchRepoSpecYAML
		// already uses for config reads); a bogus app name still 404s.
		if _, okSpec := fetchRepoSpecYAML(userID, app); !okSpec {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		// Optimistic lock against the existing DB override only — a first-time
		// override starts from the published baseline (mirrors the disk path,
		// which only enforces when a local file already exists).
		if body.BaseSHA != "" {
			if cur, has := promptOverrideGet(userID, app, name); has && contentSHA([]byte(cur)) != body.BaseSHA {
				fail(c, http.StatusConflict, 1409,
					"this prompt changed since you loaded it — reload to pick up the other edit, then reapply yours")
				return
			}
		}
		doc, err := json.Marshal(promptOverrideDoc{App: app, Name: name, Content: body.Content})
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not encode prompt override")
			return
		}
		if err := meDocSave(userID, meDocKindPrompt, promptOverrideID(app, name), string(doc)); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "could not save prompt override")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"saved": true, "sha": contentSHA([]byte(body.Content))},
		})
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
	appDir, owned, shared := resolveOwnedAppDir(userID, app)
	if !owned {
		if shared {
			fail(c, http.StatusForbidden, 1403, "this app is operator-shared (read-only) — install your own copy first")
			return
		}
		// Cross-node: remove the DB override (no-op success when none exists,
		// matching the disk path's semantics).
		if _, okSpec := fetchRepoSpecYAML(userID, app); !okSpec {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		if _, err := meDocDelete(userID, meDocKindPrompt, promptOverrideID(app, name)); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "cannot remove prompt override")
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"reverted": true},
		})
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
