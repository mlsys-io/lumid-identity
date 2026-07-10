package handler

// me_agent tool: save_artifact + the read endpoints that back the
// Studio artifact panel.
//
// Artifacts are first-class "output objects" the agent produces —
// long-form text the user wants to keep, code listings, JSON blobs.
// Each is one me_docs row (kind="artifact", doc_id=<id>) so it
// outlives the chat session; formerly a file at
// ~/.tenants/<userID>/.artifacts/<id>.json (see models/me_doc.go for
// why the pod-local files had to go).
//
// Each doc is a self-describing envelope ({id, kind, title, content,
// language?, created_at}) so the panel can render the right viewer
// without a separate index.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// artifact — the envelope serialized into the doc.
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
	if err := meDocSave(userID, meDocKindArtifact, a.ID, string(buf)); err != nil {
		return map[string]any{"error": "write: " + err.Error()}, false
	}

	// Best-effort soft cap — prune oldest beyond artifactsKeep.
	go meDocPrune(userID, meDocKindArtifact, artifactsKeep)

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

// MeArtifactsList — GET /api/v1/me/artifacts
// Returns metadata only; clients hit /:id for the content.
func MeArtifactsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	docs, err := meDocList(userID, meDocKindArtifact)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list: "+err.Error())
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
	rows := make([]listRow, 0, len(docs))
	for _, d := range docs {
		var a artifact
		if err := json.Unmarshal([]byte(d.Doc), &a); err != nil {
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
	doc, found, err := meDocGet(userID, meDocKindArtifact, id)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read: "+err.Error())
		return
	}
	if !found {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	var a artifact
	if err := json.Unmarshal([]byte(doc), &a); err != nil {
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
	found, err := meDocDelete(userID, meDocKindArtifact, id)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "remove: "+err.Error())
		return
	}
	if !found {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"id": id}})
}
