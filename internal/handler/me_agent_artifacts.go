package handler

// me_agent tool: save_artifact + the read endpoints that back the
// Studio artifact panel.
//
// Artifacts are first-class "output objects" the agent produces —
// long-form text the user wants to keep, code listings, JSON blobs.
// They live under the user's tenant so they outlive the chat
// session without leaving the operator's box:
//
//   ~/.tenants/<userID>/.artifacts/<id>.json
//
// Each file is a self-describing envelope ({id, kind, title, content,
// language?, created_at}) so the panel can render the right viewer
// without a separate index file. Listing is just `os.ReadDir`.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Artifact lives at ~/.tenants/<userID>/.artifacts/<id>.json
type artifact struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`               // markdown | code | json | text
	Title     string `json:"title"`              // human-readable label
	Language  string `json:"language,omitempty"` // for kind=code: "python", "go", …
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	// SourceTool — which agent tool produced this. Lets the panel show
	// "from deep_research" or "from code_run" badges.
	SourceTool string `json:"source_tool,omitempty"`
}

const (
	artifactMaxContent = 256 * 1024 // 256 KB ceiling per artifact
	artifactsKeep      = 200        // soft cap on per-user count; oldest pruned on overflow
)

var artifactIDRe = regexp.MustCompile(`^art-[a-f0-9]{16}$`)

func artifactsDir(userID string) string {
	return filepath.Join(tenantRoot(userID), ".artifacts")
}

func artifactPath(userID, id string) string {
	return filepath.Join(artifactsDir(userID), id+".json")
}

func newArtifactID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("art-%016x", time.Now().UnixNano())
	}
	return "art-" + hex.EncodeToString(b)
}

// toolSaveArtifact — agent tool. Writes one artifact under the
// caller's tenant and returns enough metadata for the UI to pivot to
// the panel without re-fetching.
func toolSaveArtifact(userID string, args map[string]any) (map[string]any, bool) {
	if userID == "" {
		return map[string]any{"error": "no user"}, false
	}
	title, _ := args["title"].(string)
	content, _ := args["content"].(string)
	kind, _ := args["kind"].(string)
	language, _ := args["language"].(string)
	srcTool, _ := args["source_tool"].(string)

	title = strings.TrimSpace(title)
	content = strings.TrimSpace(content)
	if title == "" {
		return map[string]any{"error": "title required"}, false
	}
	if content == "" {
		return map[string]any{"error": "content required"}, false
	}
	if len(content) > artifactMaxContent {
		return map[string]any{"error": fmt.Sprintf("content too long (max %d bytes)", artifactMaxContent)}, false
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "":
		kind = "markdown"
	case "markdown", "code", "json", "text":
		// ok
	default:
		return map[string]any{"error": "kind must be one of markdown|code|json|text"}, false
	}

	if err := os.MkdirAll(artifactsDir(userID), 0o755); err != nil {
		return map[string]any{"error": "mkdir: " + err.Error()}, false
	}

	a := artifact{
		ID:         newArtifactID(),
		Kind:       kind,
		Title:      truncStr(title, 200),
		Language:   strings.ToLower(language),
		Content:    content,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		SourceTool: srcTool,
	}
	buf, err := json.Marshal(a)
	if err != nil {
		return map[string]any{"error": "marshal: " + err.Error()}, false
	}
	tmp := artifactPath(userID, a.ID) + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return map[string]any{"error": "write: " + err.Error()}, false
	}
	if err := os.Rename(tmp, artifactPath(userID, a.ID)); err != nil {
		_ = os.Remove(tmp)
		return map[string]any{"error": "rename: " + err.Error()}, false
	}

	// Best-effort soft cap — prune oldest beyond artifactsKeep.
	go pruneArtifacts(userID, artifactsKeep)

	return map[string]any{
		"id":         a.ID,
		"kind":       a.Kind,
		"title":      a.Title,
		"language":   a.Language,
		"created_at": a.CreatedAt,
		"url":        "/api/v1/me/artifacts/" + a.ID,
		"bytes":      len(content),
	}, true
}

// pruneArtifacts deletes the oldest files when the user has more than
// `keep`. Best-effort — errors swallowed; called in a goroutine after
// each save so the foreground request stays fast.
func pruneArtifacts(userID string, keep int) {
	entries, err := os.ReadDir(artifactsDir(userID))
	if err != nil {
		return
	}
	type item struct {
		name string
		mod  time.Time
	}
	rows := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rows = append(rows, item{e.Name(), info.ModTime()})
	}
	if len(rows) <= keep {
		return
	}
	// Oldest first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].mod.Before(rows[j].mod) })
	for _, r := range rows[:len(rows)-keep] {
		_ = os.Remove(filepath.Join(artifactsDir(userID), r.name))
	}
}

// MeArtifactsList — GET /api/v1/me/artifacts
// Returns metadata only; clients hit /:id for the content.
func MeArtifactsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	dir := artifactsDir(userID)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"artifacts": []any{}}})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "readdir: "+err.Error())
		return
	}
	type listRow struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		Title      string `json:"title"`
		Language   string `json:"language,omitempty"`
		CreatedAt  string `json:"created_at"`
		SourceTool string `json:"source_tool,omitempty"`
		Bytes      int    `json:"bytes"`
	}
	rows := make([]listRow, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var a artifact
		if err := json.Unmarshal(b, &a); err != nil {
			continue
		}
		rows = append(rows, listRow{
			ID:         a.ID,
			Kind:       a.Kind,
			Title:      a.Title,
			Language:   a.Language,
			CreatedAt:  a.CreatedAt,
			SourceTool: a.SourceTool,
			Bytes:      len(a.Content),
		})
	}
	// Newest first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].CreatedAt > rows[j].CreatedAt })
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"artifacts": rows}})
}

// MeArtifactGet — GET /api/v1/me/artifacts/:id
// Returns the full envelope incl. content.
func MeArtifactGet(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !artifactIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid artifact id")
		return
	}
	path := artifactPath(userID, id)
	// Path safety — guarantee we stay inside the tenant dir.
	abs, _ := filepath.Abs(path)
	if !strings.HasPrefix(abs, artifactsDir(userID)+string(os.PathSeparator)) {
		fail(c, http.StatusBadRequest, 1400, "invalid path")
		return
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read: "+err.Error())
		return
	}
	var a artifact
	if err := json.Unmarshal(b, &a); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "parse: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": a})
}

// MeArtifactDelete — DELETE /api/v1/me/artifacts/:id
func MeArtifactDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !artifactIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid artifact id")
		return
	}
	err := os.Remove(artifactPath(userID, id))
	if errors.Is(err, os.ErrNotExist) {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "remove: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"id": id}})
}
