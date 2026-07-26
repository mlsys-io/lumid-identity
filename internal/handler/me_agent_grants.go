package handler

// Persistent per-user state for the chat agent, stored in Redis so
// BOTH identity replicas agree (the old per-pod JSON files flapped by
// replica and were wiped on every image roll). Legacy files are still
// read as a fallback for the transition window and for Redis-less dev:
//
//   claude:tool-grants:<uid>  — hash of "always allow" grants for
//                               destructive tools. field = tool name,
//                               value = RFC3339 grant time. Checked by
//                               the stream handler before raising an
//                               approval gate; written by MeAgentToolApprove
//                               (always=true); managed via
//                               GET/DELETE /api/v1/me/agent/tool-grants.
//                               (legacy file: .tool-grants.json)
//
//   claude:sessions:<uid>     — claude CLI session ids previously issued
//                               to this user by the claude-code provider.
//                               Authorizes --resume: a session id from the
//                               client is honored only if it appears here,
//                               so users can only resume their own sessions.
//                               (legacy file: .claude-sessions.json)

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"lumid_identity/internal/common"
)

var grantsMu sync.Mutex // serializes read-modify-write on the legacy fallback files

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
//
// Redis-backed (hash claude:tool-grants:<uid>, field = tool, value =
// RFC3339 grant time, no TTL) so grants are consistent across BOTH
// identity replicas and survive pod restarts — the old per-pod
// .tool-grants.json flapped by replica, so an "always allow" recorded
// on one pod silently re-prompted on the other. The legacy file is
// still read as a fallback (grants recorded before this migration, and
// Redis-less dev runs, which also keep writing it).

func toolGrantsKey(userID string) string { return "claude:tool-grants:" + userID }

// hasToolGrant reports whether the user has a persistent "always allow"
// grant for the named tool.
func hasToolGrant(userID, tool string) bool {
	if common.Redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if ok, err := common.Redis.HExists(ctx, toolGrantsKey(userID), tool).Result(); err == nil && ok {
			return true
		}
		// Miss (or Redis error) → fall through to the legacy file so
		// pre-migration grants still hold.
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	_, ok := loadJSONMap(toolGrantsPath(userID))[tool]
	return ok
}

// grantTool records a persistent allow for the named tool.
func grantTool(userID, tool string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if common.Redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		return common.Redis.HSet(ctx, toolGrantsKey(userID), tool, now).Err()
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	m := loadJSONMap(toolGrantsPath(userID))
	m[tool] = now
	return saveJSONMap(toolGrantsPath(userID), m)
}

// MeAgentToolGrants — GET /api/v1/me/agent/tool-grants
func MeAgentToolGrants(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	// Merge the legacy file with Redis for the transition window;
	// Redis wins on conflicting tools.
	grantsMu.Lock()
	m := loadJSONMap(toolGrantsPath(userID))
	grantsMu.Unlock()
	if common.Redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if h, err := common.Redis.HGetAll(ctx, toolGrantsKey(userID)).Result(); err == nil {
			for k, v := range h {
				m[k] = v
			}
		}
	}
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
	removed := false
	if common.Redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if n, err := common.Redis.HDel(ctx, toolGrantsKey(userID), name).Result(); err == nil && n > 0 {
			removed = true
		}
	}
	// Also drop any legacy-file copy so a revoked grant can't resurface
	// via the transition-window merge.
	grantsMu.Lock()
	defer grantsMu.Unlock()
	m := loadJSONMap(toolGrantsPath(userID))
	if _, ok := m[name]; ok {
		delete(m, name)
		if err := saveJSONMap(toolGrantsPath(userID), m); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
			return
		}
		removed = true
	}
	if !removed {
		fail(c, http.StatusNotFound, 1404, "no grant for "+name)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"tool": name}})
}

// ── Claude session registry ──────────────────────────────────────────────────
//
// Redis-backed (sorted set claude:sessions:<uid>, score = issue time) so
// the registry is consistent across BOTH identity replicas and survives
// pod restarts — the old per-pod .claude-sessions.json flapped by replica
// and silently broke --resume authorization. File fallback kept for
// Redis-less dev runs and for sessions recorded before this migration.

func claudeSessionsKey(userID string) string { return "claude:sessions:" + userID }

// recordClaudeSession remembers that this claude CLI session id was
// issued to this user, authorizing later --resume with it.
func recordClaudeSession(userID, sessionID string) {
	if common.Redis != nil {
		ctx := context.Background()
		key := claudeSessionsKey(userID)
		_ = common.Redis.ZAdd(ctx, key, &redis.Z{
			Score:  float64(time.Now().Unix()),
			Member: sessionID,
		}).Err()
		// Prune oldest beyond the cap so the set can't grow unbounded.
		_ = common.Redis.ZRemRangeByRank(ctx, key, 0, int64(-(claudeSessionsKeep + 1))).Err()
		return
	}
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
	if common.Redis != nil {
		err := common.Redis.ZScore(context.Background(), claudeSessionsKey(userID), sessionID).Err()
		if err == nil {
			return true
		}
		// redis.Nil (not a member) → fall through to the legacy file so
		// pre-migration sessions still resume; other errors → deny.
		if err != redis.Nil {
			return false
		}
	}
	grantsMu.Lock()
	defer grantsMu.Unlock()
	_, ok := loadJSONMap(claudeSessionsPath(userID))[sessionID]
	return ok
}
