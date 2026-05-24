package handler

// Phase S3-D — per-tenant knowledge browser.
//
// /me/knowledge/agents — list the caller's knowledge agents
// /me/knowledge/agents/:id/memories?kind=&limit= — paginated bank
//
// Reads the tenant's xpio agentic KG at
//   ~/.tenants/<sub>/.xp/kg/agents/<agent>/bank.jsonl
// One line per memory; each is a small JSON dict the schema docs at
// LumidOS/xpio/schema.py describe. We surface the most useful fields
// without forcing the UI to know the full schema.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type knowledgeAgent struct {
	ID            string `json:"id"`
	MemoryCount   int    `json:"memory_count"`
	LastMemoryTs  string `json:"last_memory_ts,omitempty"`
	BankPath      string `json:"bank_path"` // server-relative; UI debugging
	AutoPublish   bool   `json:"auto_publish_published_today,omitempty"`
}

// MeKnowledgeAgents serves GET /api/v1/me/knowledge/agents
func MeKnowledgeAgents(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	kgRoot := filepath.Join(operatorHome(), ".tenants", userID, ".xp", "kg", "agents")
	agents := []knowledgeAgent{}
	dirs, err := os.ReadDir(kgRoot)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"agents": agents, "count": 0},
		})
		return
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		bank := filepath.Join(kgRoot, d.Name(), "bank.jsonl")
		st, err := os.Stat(bank)
		if err != nil {
			continue
		}
		agent := knowledgeAgent{ID: d.Name(), BankPath: bank}
		// Cheap line count + last-ts via tail. For dogfood bank sizes
		// (low MB) full read is fine; pagination kicks in for large banks.
		f, err := os.Open(bank)
		if err == nil {
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
			lastTs := ""
			n := 0
			for scanner.Scan() {
				n++
				line := scanner.Bytes()
				// Extract ts cheaply; full parse only when we know we want this line.
				if i := strings.Index(string(line), `"created_at":"`); i >= 0 {
					rest := string(line)[i+len(`"created_at":"`):]
					if j := strings.Index(rest, `"`); j > 0 {
						lastTs = rest[:j]
					}
				}
			}
			f.Close()
			agent.MemoryCount = n
			agent.LastMemoryTs = lastTs
		}
		_ = st // future: mtime
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].ID < agents[j].ID })
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"agents": agents, "count": len(agents)},
	})
}

type memoryRow struct {
	ID         string  `json:"id,omitempty"`
	Kind       string  `json:"kind,omitempty"`
	Source     string  `json:"source,omitempty"`
	Content    string  `json:"content,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	CreatedAt  string  `json:"created_at,omitempty"`
	Recurrence int     `json:"recurrence,omitempty"`
}

// MeKnowledgeMemories serves GET /api/v1/me/knowledge/agents/:id/memories?kind=&limit=&offset=
func MeKnowledgeMemories(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	agent := c.Param("id")
	// Agent ids are user-prefixed UUIDs + suffix; allow the same charset slugRe permits.
	if !slugRe.MatchString(agent) {
		fail(c, http.StatusBadRequest, 1400, "invalid agent id")
		return
	}
	bankPath := filepath.Join(operatorHome(), ".tenants", userID, ".xp", "kg", "agents", agent, "bank.jsonl")
	abs, _ := filepath.Abs(bankPath)
	if !strings.HasPrefix(abs, filepath.Join(operatorHome(), ".tenants", userID)+string(os.PathSeparator)) {
		fail(c, http.StatusBadRequest, 1400, "invalid path")
		return
	}
	f, err := os.Open(bankPath)
	if err != nil {
		fail(c, http.StatusNotFound, 1404, "bank not found")
		return
	}
	defer f.Close()

	kindFilter := c.Query("kind")
	limit := 50
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	offset := 0
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	all := []memoryRow{}
	for scanner.Scan() {
		var raw map[string]any
		if json.Unmarshal(scanner.Bytes(), &raw) != nil {
			continue
		}
		row := memoryRow{}
		if v, ok := raw["id"].(string); ok {
			row.ID = v
		}
		if v, ok := raw["kind"].(string); ok {
			row.Kind = v
		}
		if v, ok := raw["source"].(string); ok {
			row.Source = v
		}
		if v, ok := raw["content"].(string); ok {
			row.Content = v
		}
		if v, ok := raw["confidence"].(float64); ok {
			row.Confidence = v
		}
		if v, ok := raw["created_at"].(string); ok {
			row.CreatedAt = v
		}
		if v, ok := raw["recurrence"].(float64); ok {
			row.Recurrence = int(v)
		}
		if kindFilter != "" && row.Kind != kindFilter {
			continue
		}
		all = append(all, row)
	}
	// Reverse so newest first
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt > all[j].CreatedAt
	})
	total := len(all)
	end := offset + limit
	if end > total {
		end = total
	}
	if offset > total {
		offset = total
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"agent":   agent,
			"total":   total,
			"offset":  offset,
			"limit":   limit,
			"memories": all[offset:end],
			"as_of":   time.Now().UTC().Format(time.RFC3339),
		},
	})
}
