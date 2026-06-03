package handler

// User-defined personas for the Studio chat. Each persona is a
// custom system prompt + optional tool whitelist + display label.
// Lives at ~/.tenants/<userID>/.personas/<id>.json. Endpoints
// follow the same shape as artifacts + chats (list/get/upsert/delete).
//
// When the chat body sets `persona_id`, buildSystemPrompt swaps the
// LumidOS assistant base + agent-bank block entirely for the
// persona's system prompt. Tools filter via allowed_tools[] when
// set; empty = full catalog.
//
// Personas are independent of `agent_id` — you can't combine them
// in the same turn (mutually exclusive; persona_id wins if both set
// since it's a stronger override).

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
	personasKeep       = 50          // soft cap per user
	personaMaxPrompt   = 16 * 1024   // 16 KB system prompt cap
)

var personaIDRe = regexp.MustCompile(`^per-[a-f0-9]{16}$`)

type persona struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`             // human label, e.g. "Code Reviewer"
	Icon          string   `json:"icon,omitempty"`   // optional emoji
	SystemPrompt  string   `json:"system_prompt"`
	AllowedTools  []string `json:"allowed_tools,omitempty"` // empty = full catalog
	PreferredModel string  `json:"preferred_model,omitempty"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func personasDir(userID string) string {
	return filepath.Join(tenantRoot(userID), ".personas")
}

func personaPath(userID, id string) string {
	return filepath.Join(personasDir(userID), id+".json")
}

func newPersonaID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("per-%016x", time.Now().UnixNano())
	}
	return "per-" + hex.EncodeToString(b)
}

// loadPersona reads one persona from disk. Returns nil + nil error
// when the id doesn't exist (caller decides whether that's fatal).
func loadPersona(userID, id string) (*persona, error) {
	if !personaIDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid persona id")
	}
	b, err := os.ReadFile(personaPath(userID, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p persona
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// buildPersonaSystemPrompt — replaces buildSystemPrompt entirely
// when persona_id is set. The persona's prompt becomes the base;
// we still append modeSystemSuffix at the call site for citations.
func buildPersonaSystemPrompt(p *persona) string {
	if p == nil {
		return ""
	}
	return p.SystemPrompt
}

// MePersonasList — GET /api/v1/me/personas
func MePersonasList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	dir := personasDir(userID)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"personas": []any{}}})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "readdir: "+err.Error())
		return
	}
	type row struct {
		ID            string   `json:"id"`
		Name          string   `json:"name"`
		Icon          string   `json:"icon,omitempty"`
		AllowedTools  []string `json:"allowed_tools,omitempty"`
		PreferredModel string  `json:"preferred_model,omitempty"`
		PromptLen     int      `json:"prompt_len"`
		UpdatedAt     string   `json:"updated_at"`
	}
	rows := []row{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var p persona
		if err := json.Unmarshal(b, &p); err != nil {
			continue
		}
		rows = append(rows, row{
			ID:            p.ID,
			Name:          p.Name,
			Icon:          p.Icon,
			AllowedTools:  p.AllowedTools,
			PreferredModel: p.PreferredModel,
			PromptLen:     len(p.SystemPrompt),
			UpdatedAt:     p.UpdatedAt,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].UpdatedAt > rows[j].UpdatedAt })
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"personas": rows}})
}

// MePersonaGet — GET /api/v1/me/personas/:id
func MePersonaGet(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	p, err := loadPersona(userID, id)
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	if p == nil {
		fail(c, http.StatusNotFound, 1404, "not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": p})
}

// MePersonaSave — POST /api/v1/me/personas (upsert)
// Body: {id?, name, icon?, system_prompt, allowed_tools?[], preferred_model?}
func MePersonaSave(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		ID            string   `json:"id"`
		Name          string   `json:"name"`
		Icon          string   `json:"icon"`
		SystemPrompt  string   `json:"system_prompt"`
		AllowedTools  []string `json:"allowed_tools"`
		PreferredModel string  `json:"preferred_model"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.SystemPrompt = strings.TrimSpace(body.SystemPrompt)
	if body.Name == "" {
		fail(c, http.StatusBadRequest, 1400, "name required")
		return
	}
	if body.SystemPrompt == "" {
		fail(c, http.StatusBadRequest, 1400, "system_prompt required")
		return
	}
	if len(body.SystemPrompt) > personaMaxPrompt {
		fail(c, http.StatusRequestEntityTooLarge, 1413,
			fmt.Sprintf("system_prompt > %d bytes", personaMaxPrompt))
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	var rec persona
	isNew := false
	if body.ID == "" {
		isNew = true
		rec = persona{ID: newPersonaID(), CreatedAt: now}
	} else {
		if !personaIDRe.MatchString(body.ID) {
			fail(c, http.StatusBadRequest, 1400, "invalid persona id")
			return
		}
		existing, err := loadPersona(userID, body.ID)
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, err.Error())
			return
		}
		if existing == nil {
			fail(c, http.StatusNotFound, 1404, "persona not found — omit id to create")
			return
		}
		rec = *existing
	}
	rec.Name = body.Name
	rec.Icon = body.Icon
	rec.SystemPrompt = body.SystemPrompt
	rec.AllowedTools = body.AllowedTools
	rec.PreferredModel = body.PreferredModel
	rec.UpdatedAt = now

	if err := os.MkdirAll(personasDir(userID), 0o755); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "mkdir: "+err.Error())
		return
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "marshal: "+err.Error())
		return
	}
	tmp := personaPath(userID, rec.ID) + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write: "+err.Error())
		return
	}
	if err := os.Rename(tmp, personaPath(userID, rec.ID)); err != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "rename: "+err.Error())
		return
	}

	if isNew {
		go prunePersonas(userID, personasKeep)
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"id": rec.ID, "name": rec.Name, "updated_at": rec.UpdatedAt},
	})
}

// MePersonaDelete — DELETE /api/v1/me/personas/:id
func MePersonaDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !personaIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid persona id")
		return
	}
	err := os.Remove(personaPath(userID, id))
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

// prunePersonas keeps only the `keep` newest files. Mirrors the
// artifact/chat pruning pattern.
func prunePersonas(userID string, keep int) {
	entries, err := os.ReadDir(personasDir(userID))
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
		_ = os.Remove(filepath.Join(personasDir(userID), r.name))
	}
}
