package handler

// me_agent tool: save_artifact + the read endpoints that back the
// Studio artifact panel.
//
// Artifacts are first-class "output objects" the agent produces —
// long-form text, code listings, JSON blobs, and (via generate_image /
// text_to_speech) images + audio. They are stored in the auth DB
// (models.MeArtifact) so BOTH identity replicas see them — the old
// pod-local file store (~/.tenants/<userID>/.artifacts/<id>.json) flapped
// 200/404 across the 2-replica deploy. Each row is a self-describing
// envelope ({id, kind, title, content, language?, created_at, source_tool})
// so the panel renders the right viewer without a separate index.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// artifact is the JSON envelope returned to the Studio panel.
type artifact struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`               // markdown | code | json | text | image | audio
	Title     string `json:"title"`              // human-readable label
	Language  string `json:"language,omitempty"` // for kind=code: "python", "go", …
	Content   string `json:"content"`
	CreatedAt string `json:"created_at"`
	// SourceTool — which agent tool produced this. Lets the panel show
	// "from deep_research" or "from generate_image" badges.
	SourceTool string `json:"source_tool,omitempty"`
}

const (
	artifactMaxContent = 256 * 1024 // 256 KB ceiling for the text kinds
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

// persistArtifact writes one artifact row for the caller and returns the small
// metadata map the UI/model use to pivot to the panel. Shared by the text
// (save_artifact) and media (generate_image / text_to_speech) tools; maxBytes
// lets media carry a larger ceiling than the text kinds.
func persistArtifact(userID string, a artifact, maxBytes int) (map[string]any, bool) {
	if userID == "" {
		return map[string]any{"error": "no user"}, false
	}
	if a.Content == "" {
		return map[string]any{"error": "content required"}, false
	}
	if len(a.Content) > maxBytes {
		return map[string]any{"error": fmt.Sprintf("content too long (max %d bytes)", maxBytes)}, false
	}
	if a.ID == "" {
		a.ID = newArtifactID()
	}
	row := models.MeArtifact{
		ID:         a.ID,
		UserSub:    userID,
		Kind:       a.Kind,
		Title:      truncStr(a.Title, 200),
		Language:   strings.ToLower(a.Language),
		Content:    a.Content,
		SourceTool: a.SourceTool,
	}
	if err := common.DB.Create(&row).Error; err != nil {
		return map[string]any{"error": "save: " + err.Error()}, false
	}
	go pruneArtifacts(userID, artifactsKeep)
	return map[string]any{
		"id":         row.ID,
		"kind":       row.Kind,
		"title":      row.Title,
		"language":   row.Language,
		"created_at": row.CreatedAt.UTC().Format(time.RFC3339),
		"url":        "/api/v1/me/artifacts/" + row.ID,
		"bytes":      len(row.Content),
	}, true
}

// toolSaveArtifact — agent tool. Writes one text-kind artifact for the caller.
func toolSaveArtifact(userID string, args map[string]any) (map[string]any, bool) {
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
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "":
		kind = "markdown"
	case "markdown", "code", "json", "text":
		// ok
	default:
		return map[string]any{"error": "kind must be one of markdown|code|json|text"}, false
	}
	return persistArtifact(userID, artifact{
		Kind: kind, Title: title, Language: language, Content: content, SourceTool: srcTool,
	}, artifactMaxContent)
}

// pruneArtifacts deletes the oldest rows when the user has more than `keep`.
// Best-effort — called in a goroutine after each save.
func pruneArtifacts(userID string, keep int) {
	var ids []string
	if err := common.DB.Model(&models.MeArtifact{}).
		Where("user_sub = ?", userID).
		Order("created_at DESC").
		Offset(keep).
		Pluck("id", &ids).Error; err != nil || len(ids) == 0 {
		return
	}
	_ = common.DB.Where("user_sub = ? AND id IN ?", userID, ids).
		Delete(&models.MeArtifact{}).Error
}

// MeArtifactsList — GET /api/v1/me/artifacts. Metadata only (no content).
func MeArtifactsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
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
	var rows []models.MeArtifact
	if err := common.DB.Where("user_sub = ?", userID).
		Order("created_at DESC").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query: "+err.Error())
		return
	}
	out := make([]listRow, 0, len(rows))
	for _, a := range rows {
		out = append(out, listRow{
			ID:         a.ID,
			Kind:       a.Kind,
			Title:      a.Title,
			Language:   a.Language,
			CreatedAt:  a.CreatedAt.UTC().Format(time.RFC3339),
			SourceTool: a.SourceTool,
			Bytes:      len(a.Content),
		})
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"artifacts": out}})
}

// MeArtifactGet — GET /api/v1/me/artifacts/:id. Full envelope incl. content.
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
	var row models.MeArtifact
	err := common.DB.Where("id = ? AND user_sub = ?", id, userID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "query: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": artifact{
		ID:         row.ID,
		Kind:       row.Kind,
		Title:      row.Title,
		Language:   row.Language,
		Content:    row.Content,
		CreatedAt:  row.CreatedAt.UTC().Format(time.RFC3339),
		SourceTool: row.SourceTool,
	}})
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
	res := common.DB.Where("id = ? AND user_sub = ?", id, userID).Delete(&models.MeArtifact{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "remove: "+res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"id": id}})
}
