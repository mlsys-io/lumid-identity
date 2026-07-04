package handler

// Persistent chat history — every conversation is one file under
//   ~/.tenants/<userID>/.chats/<id>.json
//
// The frontend POSTs the full transcript at the end of each turn,
// so the file is always up-to-date with the in-memory session. List
// + get + delete are read paths for the sidebar.
//
// Title is inferred from the first user message (first 60 chars,
// single line). created_at and updated_at are managed server-side
// on write.

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

const (
	chatsKeep       = 200       // soft cap; oldest pruned in background after save
	chatMaxBytes    = 2_000_000 // 2 MB per chat file (cap on transcript size)
	chatTitleMaxLen = 60
)

var chatIDRe = regexp.MustCompile(`^chat-[a-f0-9]{16}$`)

// chatRecord — what we serialize on disk. Messages are intentionally
// JSON-as-is (whatever the frontend sends) so we don't have to keep
// the wire format in lockstep with the message type as it evolves.
type chatRecord struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// Messages is a free-form array of objects matching the frontend
	// Message type — {role, content, tools?, thinking?, ...}.
	Messages []map[string]any `json:"messages"`
	// Model + mode last used — surfaces in the sidebar as small chips
	// so the user knows what backed the thread.
	Model string `json:"model,omitempty"`
	Mode  string `json:"mode,omitempty"`
	// Claude CLI session backing this thread (claude-code providers).
	// Restored on thread load so --resume continuity survives reloads.
	ClaudeSessionID string `json:"claude_session_id,omitempty"`
	// App this conversation is grounded on (Studio workspace app slug), so the
	// session picker can group/switch by app and re-open the right workspace.
	// Empty = a general (non-app) chat from the home.
	App string `json:"app,omitempty"`
}

func chatsDir(userID string) string {
	return filepath.Join(tenantRoot(userID), ".chats")
}

func chatPath(userID, id string) string {
	return filepath.Join(chatsDir(userID), id+".json")
}

func newChatID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("chat-%016x", time.Now().UnixNano())
	}
	return "chat-" + hex.EncodeToString(b)
}

func inferTitle(msgs []map[string]any) string {
	for _, m := range msgs {
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		content, _ := m["content"].(string)
		// Strip the buildSelectionPreamble prefix if present —
		// "On page X — selection: Y\n\n<actual question>"
		if idx := strings.Index(content, "\n\n"); idx >= 0 && idx < 200 {
			content = content[idx+2:]
		}
		// Single-line, capped.
		content = strings.TrimSpace(strings.ReplaceAll(content, "\n", " "))
		if content == "" {
			continue
		}
		if len([]rune(content)) > chatTitleMaxLen {
			content = string([]rune(content)[:chatTitleMaxLen]) + "…"
		}
		return content
	}
	return "Untitled chat"
}

// MeChatsList — GET /api/v1/me/chats — sidebar source.
// Returns id, title, model, mode, message count, created/updated.
// Content + tool calls are NOT included to keep the response small.
func MeChatsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	dir := chatsDir(userID)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"chats": []any{}}})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "readdir: "+err.Error())
		return
	}
	type listRow struct {
		ID        string `json:"id"`
		Title     string `json:"title"`
		Model     string `json:"model,omitempty"`
		Mode      string `json:"mode,omitempty"`
		App       string `json:"app,omitempty"`
		MsgCount  int    `json:"msg_count"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
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
		var r chatRecord
		if err := json.Unmarshal(b, &r); err != nil {
			continue
		}
		rows = append(rows, listRow{
			ID:        r.ID,
			Title:     r.Title,
			Model:     r.Model,
			Mode:      r.Mode,
			App:       r.App,
			MsgCount:  len(r.Messages),
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		})
	}
	// Newest-updated first.
	sort.Slice(rows, func(i, j int) bool { return rows[i].UpdatedAt > rows[j].UpdatedAt })
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"chats": rows}})
}

// MeChatGet — GET /api/v1/me/chats/:id — full transcript.
func MeChatGet(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !chatIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid chat id")
		return
	}
	path := chatPath(userID, id)
	abs, _ := filepath.Abs(path)
	if !strings.HasPrefix(abs, chatsDir(userID)+string(os.PathSeparator)) {
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
	var r chatRecord
	if err := json.Unmarshal(b, &r); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "parse: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": r})
}

// MeChatSave — POST /api/v1/me/chats — upsert.
// Body: {id?, messages: [...], model?, mode?}
// If id is empty or missing → server mints a new one.
// If id is provided but file doesn't exist → 404. (Keeps the
// frontend honest: never POST a stale localStorage id.)
func MeChatSave(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		ID              string           `json:"id"`
		Messages        []map[string]any `json:"messages"`
		Model           string           `json:"model"`
		Mode            string           `json:"mode"`
		ClaudeSessionID string           `json:"claude_session_id"`
		App             string           `json:"app"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if len(body.Messages) == 0 {
		fail(c, http.StatusBadRequest, 1400, "messages required")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var rec chatRecord
	isNew := false
	if body.ID == "" {
		isNew = true
		rec = chatRecord{
			ID:        newChatID(),
			CreatedAt: now,
		}
	} else {
		if !chatIDRe.MatchString(body.ID) {
			fail(c, http.StatusBadRequest, 1400, "invalid chat id")
			return
		}
		// Load existing to preserve CreatedAt.
		path := chatPath(userID, body.ID)
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			fail(c, http.StatusNotFound, 1404, "chat not found — omit id to create a new one")
			return
		}
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "read: "+err.Error())
			return
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			rec = chatRecord{ID: body.ID, CreatedAt: now}
		}
	}

	rec.Messages = body.Messages
	rec.Model = body.Model
	rec.Mode = body.Mode
	if body.ClaudeSessionID != "" {
		rec.ClaudeSessionID = body.ClaudeSessionID
	}
	// App grounding — set on create; on update keep the existing value unless a
	// non-empty app is sent (a thread shouldn't silently lose its app binding).
	if body.App != "" {
		rec.App = body.App
	}
	rec.Title = inferTitle(body.Messages)
	rec.UpdatedAt = now

	if err := os.MkdirAll(chatsDir(userID), 0o755); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mkdir: "+err.Error())
		return
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "marshal: "+err.Error())
		return
	}
	if len(buf) > chatMaxBytes {
		fail(c, http.StatusRequestEntityTooLarge, 1413, fmt.Sprintf("chat exceeds %d bytes — split into a new thread", chatMaxBytes))
		return
	}
	tmp := chatPath(userID, rec.ID) + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write: "+err.Error())
		return
	}
	if err := os.Rename(tmp, chatPath(userID, rec.ID)); err != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "rename: "+err.Error())
		return
	}

	if isNew {
		go pruneChats(userID, chatsKeep)
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0,
		"message":  "ok",
		"data": gin.H{
			"id":         rec.ID,
			"title":      rec.Title,
			"created_at": rec.CreatedAt,
			"updated_at": rec.UpdatedAt,
		},
	})
}

// MeChatDelete — DELETE /api/v1/me/chats/:id
func MeChatDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !chatIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid chat id")
		return
	}
	err := os.Remove(chatPath(userID, id))
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

// pruneChats deletes the oldest files when the user has more than
// `keep`. Best-effort. Mirrors the artifact-pruning pattern.
func pruneChats(userID string, keep int) {
	entries, err := os.ReadDir(chatsDir(userID))
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
	sort.Slice(rows, func(i, j int) bool { return rows[i].mod.Before(rows[j].mod) })
	for _, r := range rows[:len(rows)-keep] {
		_ = os.Remove(filepath.Join(chatsDir(userID), r.name))
	}
}
