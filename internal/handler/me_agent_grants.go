package handler

// Persistent per-user state for the chat agent, stored as small JSON
// files in the caller's tenant dir (same pattern as .chats/):
//
//   .tool-grants.json     — "always allow" grants for destructive tools.
//                           tool name → RFC3339 grant time. Checked by
//                           the stream handler before raising an
//                           approval gate; written by MeAgentToolApprove
//                           (always=true); managed via
//                           GET/DELETE /api/v1/me/agent/tool-grants.
//
//   .claude-sessions.json — claude CLI session ids previously issued to
//                           this user by the claude-code provider.
//                           Authorizes --resume: a session id from the
//                           client is honored only if it appears here,
//                           so users can only resume their own sessions.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var grantsMu sync.Mutex // serializes read-modify-write on both files

const claudeSessionsKeep = 100 // oldest pruned beyond this

func toolGrantsPath(userID string) string {
	return filepath.Join(tenantRoot(userID), ".tool-grants.json")
}

func claudeSessionsPath(userID string) string {
	return filepath.Join(tenantRoot(userID), ".claude-sessions.json")
}

// loadJSONMap reads a string→string JSON object, returning an empty map
// on any error (missing file, parse failure) so callers fail open to
// "no grants / no sessions".
func loadJSONMap(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

func saveJSONMap(path string, m map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ── Tool grants ──────────────────────────────────────────────────────────────

// hasToolGrant reports whether the user has a persistent "always allow"
// grant for the named tool.
func hasToolGrant(userID, tool string) bool {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	_, ok := loadJSONMap(toolGrantsPath(userID))[tool]
	return ok
}

// grantTool records a persistent allow for the named tool.
func grantTool(userID, tool string) error {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	m := loadJSONMap(toolGrantsPath(userID))
	m[tool] = time.Now().UTC().Format(time.RFC3339)
	return saveJSONMap(toolGrantsPath(userID), m)
}

// MeAgentToolGrants — GET /api/v1/me/agent/tool-grants
func MeAgentToolGrants(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	grantsMu.Lock()
	m := loadJSONMap(toolGrantsPath(userID))
	grantsMu.Unlock()
	type row struct {
		Tool      string `json:"tool"`
		GrantedAt string `json:"granted_at"`
	}
	rows := make([]row, 0, len(m))
	for k, v := range m {
		rows = append(rows, row{Tool: k, GrantedAt: v})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Tool < rows[j].Tool })
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"grants": rows}})
}

// MeAgentToolGrantRevoke — DELETE /api/v1/me/agent/tool-grants/:name
func MeAgentToolGrantRevoke(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	name := c.Param("name")
	grantsMu.Lock()
	defer grantsMu.Unlock()
	m := loadJSONMap(toolGrantsPath(userID))
	if _, ok := m[name]; !ok {
		fail(c, http.StatusNotFound, 1404, "no grant for "+name)
		return
	}
	delete(m, name)
	if err := saveJSONMap(toolGrantsPath(userID), m); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"tool": name}})
}

// ── Claude session registry ──────────────────────────────────────────────────

// recordClaudeSession remembers that this claude CLI session id was
// issued to this user, authorizing later --resume with it.
func recordClaudeSession(userID, sessionID string) {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	path := claudeSessionsPath(userID)
	m := loadJSONMap(path)
	m[sessionID] = time.Now().UTC().Format(time.RFC3339)
	// Prune oldest beyond the cap so the file can't grow unbounded.
	if len(m) > claudeSessionsKeep {
		type kv struct{ k, v string }
		rows := make([]kv, 0, len(m))
		for k, v := range m {
			rows = append(rows, kv{k, v})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].v < rows[j].v })
		for _, r := range rows[:len(m)-claudeSessionsKeep] {
			delete(m, r.k)
		}
	}
	_ = saveJSONMap(path, m)
}

// userOwnsClaudeSession reports whether sessionID was previously issued
// to this user.
func userOwnsClaudeSession(userID, sessionID string) bool {
	grantsMu.Lock()
	defer grantsMu.Unlock()
	_, ok := loadJSONMap(claudeSessionsPath(userID))[sessionID]
	return ok
}
