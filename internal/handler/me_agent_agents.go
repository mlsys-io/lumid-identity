package handler

// GET /api/v1/me/agents — list of installed xpio agents the user can
// chat with. Walks the user's tenant kg dir + the operator-shared
// kg dir, returns per-agent metadata (bank size, last memory ts).
//
// When the chat body carries `agent_id`, buildSystemPrompt swaps the
// me-prefs context for that agent's most-recent bank entries — the
// chat acts as the agent's spokesperson, grounded in the agent's
// accumulated knowledge rather than the user's global prefs.

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// agentRole — the bits of an xpcloud.yaml roles[] entry we use when
// building the persona prompt. Memory_agent maps to the bank id.
type agentRole struct {
	AppName      string
	RoleName     string
	Description  string
	DefaultModel string
}

// findAgentRole walks ~/.xp/apps/*/xpcloud.yaml looking for the role
// whose memory_agent matches the given agent id. Returns nil when
// no app declares this agent (operator may have a bank without a
// hosting app — bare me-prefs is the canonical example).
func findAgentRole(agentID string) *agentRole {
	appsRoot := filepath.Join(operatorHome(), ".xp", "apps")
	apps, err := os.ReadDir(appsRoot)
	if err != nil {
		return nil
	}
	for _, e := range apps {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		manifestPath, _ := ResolveSpecPath(filepath.Join(appsRoot, e.Name()))
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}
		var doc struct {
			Roles []struct {
				Name         string `yaml:"name"`
				MemoryAgent  string `yaml:"memory_agent"`
				Description  string `yaml:"description"`
				DefaultModel string `yaml:"default_model"`
			} `yaml:"roles"`
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			continue
		}
		for _, r := range doc.Roles {
			if r.MemoryAgent == agentID {
				return &agentRole{
					AppName:      e.Name(),
					RoleName:     r.Name,
					Description:  strings.TrimSpace(r.Description),
					DefaultModel: r.DefaultModel,
				}
			}
		}
	}
	return nil
}

// parseRFC3339Unix — tiny helper so me_agent_agents.go can share
// the timestamp logic with the bank scanner. Returns unix seconds.
func parseRFC3339Unix(s string) (float64, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return float64(t.Unix()), nil
}

// agentInfo — per-agent metadata for the picker.
type agentInfo struct {
	ID           string  `json:"id"`
	Scope        string  `json:"scope"` // "tenant" | "shared"
	RowCount     int     `json:"row_count"`
	LastMemoryTs float64 `json:"last_memory_ts"` // unix seconds; 0 if empty/unknown
	// Role metadata — populated when the agent is declared in some
	// installed xpio app's xpcloud.yaml::roles[]. Empty otherwise.
	App          string `json:"app,omitempty"`
	Role         string `json:"role,omitempty"`
	Description  string `json:"description,omitempty"`
	DefaultModel string `json:"default_model,omitempty"`
}

// agentBankPaths returns (path, scope) candidates for the given
// agent id, tenant-first. Both may exist (we return only the
// tenant one in that case — tenant privacy wins).
func agentBankPaths(userID, agentID string) []struct{ path, scope string } {
	return []struct{ path, scope string }{
		{filepath.Join(tenantRoot(userID), ".xp", "kg", "agents", agentID, "bank.jsonl"), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "kg", "agents", agentID, "bank.jsonl"), "shared"},
	}
}

// MeAgentsList — GET /api/v1/me/agents.
// Returns the union of tenant-private + operator-shared agents,
// tenant entries shadow shared ones with the same id.
func MeAgentsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	seen := map[string]bool{}
	rows := []agentInfo{}

	roots := []struct {
		base, scope string
	}{
		{filepath.Join(tenantRoot(userID), ".xp", "kg", "agents"), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "kg", "agents"), "shared"},
	}
	for _, r := range roots {
		entries, err := os.ReadDir(r.base)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			id := e.Name()
			if seen[id] {
				continue
			}
			seen[id] = true
			bank := filepath.Join(r.base, id, "bank.jsonl")
			info, err := os.Stat(bank)
			if err != nil {
				continue
			}
			role := findAgentRole(id)
			ai := agentInfo{ID: id, Scope: r.scope}
			if role != nil {
				ai.App = role.AppName
				ai.Role = role.RoleName
				ai.Description = role.Description
				ai.DefaultModel = role.DefaultModel
			}
			if info.Size() == 0 {
				rows = append(rows, ai)
				continue
			}
			count, lastTs := scanBankMeta(bank)
			ai.RowCount = count
			ai.LastMemoryTs = lastTs
			rows = append(rows, ai)
		}
	}

	// Newest-memory-first, then alphabetical for empty banks.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastMemoryTs != rows[j].LastMemoryTs {
			return rows[i].LastMemoryTs > rows[j].LastMemoryTs
		}
		return rows[i].ID < rows[j].ID
	})

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"agents": rows},
	})
}

// scanBankMeta counts rows + reads the newest created_at without
// parsing every row's content. Handles both timestamp shapes:
// unix-float (xpio runtime) and RFC3339 string (me-prefs).
func scanBankMeta(path string) (count int, lastTs float64) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		count++
		var row map[string]any
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			continue
		}
		ts := parseRowTs(row)
		if ts > lastTs {
			lastTs = ts
		}
	}
	return
}

// parseRowTs handles both unix-float and RFC3339 created_at fields.
// Returns unix seconds; 0 when neither shape parses.
func parseRowTs(row map[string]any) float64 {
	if v, ok := row["created_at"]; ok {
		switch t := v.(type) {
		case float64:
			return t
		case string:
			// RFC3339 → unix
			if ts, err := parseRFC3339Unix(t); err == nil {
				return ts
			}
		}
	}
	return 0
}

// loadAgentBankMemories returns up to `limit` most-recent memory
// rows from an agent's bank. Used by buildSystemPrompt when the
// chat body sets agent_id. Returns nil when the bank is empty/
// missing (caller falls through to the me-prefs path).
func loadAgentBankMemories(userID, agentID string, limit int) []map[string]any {
	if limit <= 0 || limit > 50 {
		limit = 12
	}
	for _, p := range agentBankPaths(userID, agentID) {
		f, err := os.Open(p.path)
		if err != nil {
			continue
		}
		defer f.Close()
		rows := []map[string]any{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var row map[string]any
			if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
				continue
			}
			rows = append(rows, row)
		}
		if len(rows) == 0 {
			return nil
		}
		// Newest first.
		sort.Slice(rows, func(i, j int) bool {
			return parseRowTs(rows[i]) > parseRowTs(rows[j])
		})
		if len(rows) > limit {
			rows = rows[:limit]
		}
		return rows
	}
	return nil
}

// renderAgentBankBlock builds the system-prompt section that
// replaces renderPrefsBlock when agent_id is set. When the agent is
// declared as a role in an installed xpio app's xpcloud.yaml, we
// also inject the role's `name` + `description` so the LLM speaks
// in the agent's specific voice rather than a generic "speaking
// for X" framing. Falls back to bank-only context when no role
// definition exists (e.g. me-prefs, default).
func renderAgentBankBlock(userID, agentID string) string {
	rows := loadAgentBankMemories(userID, agentID, 12)
	role := findAgentRole(agentID)

	var sb strings.Builder
	if role != nil && role.Description != "" {
		// Rich persona — voice + scope from the role declaration.
		sb.WriteString("\n\n## You are the `" + role.RoleName + "` agent (from xpio app `" + role.AppName + "`)\n")
		sb.WriteString(role.Description + "\n\n")
		sb.WriteString("You are answering AS this agent. Three rules:\n")
		sb.WriteString("1. Speak in the agent's voice — first person, focused on its domain, terse and decisive within its expertise.\n")
		sb.WriteString("2. Refuse tool calls outside the agent's scope. The user can still call any tool in their main chat — but when they're talking TO this agent, the agent shouldn't be sending emails, creating calendar events, or installing apps unless that's clearly part of its declared description. Reply something like: \"That's outside what I do as the " + role.RoleName + " — your default assistant can handle it; clear the agent picker and ask again.\"\n")
		sb.WriteString("3. If the user's question is outside the agent's described domain entirely (not just a tool action), say so plainly and suggest clearing the agent picker.\n\n")
	} else {
		// Generic framing for agents without a role declaration —
		// e.g. me-prefs or banks the user created manually.
		sb.WriteString("\n\n## You are speaking for `" + agentID + "`\n")
		sb.WriteString("The user is asking about (or addressing) the `" + agentID + "` xpio agent. Ground your reply in this agent's accumulated knowledge below — speak from its perspective, cite its memories, and don't invent things it doesn't appear to know. If the question is outside this agent's domain, say so plainly.\n\n")
	}

	if len(rows) == 0 {
		sb.WriteString("(this agent's bank is empty — it hasn't recorded any memories yet. Answer from your role description above; be honest that you have no accumulated knowledge to draw on)\n")
		return sb.String()
	}
	sb.WriteString("Recent memories from this agent's bank (newest first):\n")
	for _, r := range rows {
		content, _ := r["content"].(string)
		if content == "" {
			continue
		}
		title, _ := r["title"].(string)
		var line string
		if title != "" {
			line = title + ": " + content
		} else {
			line = content
		}
		if len([]rune(line)) > 280 {
			line = string([]rune(line)[:280]) + "…"
		}
		sb.WriteString("- " + line + "\n")
	}
	return sb.String()
}
