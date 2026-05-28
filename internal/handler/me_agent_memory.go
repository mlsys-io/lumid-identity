package handler

// me_agent tool: remember_about_me — long-term memory writes.
// Appends a row to ~/.tenants/<userID>/.xp/kg/agents/me-prefs/bank.jsonl,
// the dedicated "what the agent has learned about the user" bank.
//
// Reads use the existing query_my_knowledge tool (which scans the
// same path). Recent entries are also injected into buildSystemPrompt
// so the agent always has the user's preferences in context without
// needing an explicit recall step.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// prefsBankAgent — the dedicated agent name used by the personal
// memory layer. Kept as a constant so the inject + write paths agree.
const prefsBankAgent = "me-prefs"

// toolRememberAboutMe appends one memory row to the user's me-prefs
// bank. Note is required; tags is an optional comma-or-array hint that
// helps future retrieval (e.g. "preference,style" or "fact,context").
func toolRememberAboutMe(userID, note string, tags any) (map[string]any, bool) {
	note = strings.TrimSpace(note)
	if note == "" {
		return map[string]any{"error": "note required"}, false
	}
	if userID == "" {
		return map[string]any{"error": "no user"}, false
	}

	tagStr := normalizeTags(tags)
	bankPath := prefsBankPath(userID)
	if err := os.MkdirAll(filepath.Dir(bankPath), 0o755); err != nil {
		return map[string]any{"error": "mkdir: " + err.Error()}, false
	}

	row := map[string]any{
		"id":         newMemoryID(),
		"kind":       "preference",
		"source":     "chat",
		"content":    note,
		"confidence": 1.0,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"recurrence": 1,
	}
	if tagStr != "" {
		row["tags"] = tagStr
	}

	if err := appendBankRow(bankPath, row); err != nil {
		return map[string]any{"error": "append: " + err.Error()}, false
	}

	return map[string]any{
		"ok":         true,
		"agent":      prefsBankAgent,
		"id":         row["id"],
		"created_at": row["created_at"],
		"note":       truncStr(note, 120),
	}, true
}

// prefsBankPath returns the absolute path to the user's me-prefs
// bank.jsonl. The directory is created lazily by callers.
func prefsBankPath(userID string) string {
	return filepath.Join(tenantRoot(userID), ".xp", "kg", "agents", prefsBankAgent, "bank.jsonl")
}

// appendBankRow appends one row as a newline-terminated JSON object.
// O_APPEND on POSIX guarantees the write is atomic up to PIPE_BUF size
// (typically 4096 bytes), which is more than enough for a memory row.
func appendBankRow(path string, row map[string]any) error {
	b, err := json.Marshal(row)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

// newMemoryID generates a short opaque memory id. Not security-sensitive.
func newMemoryID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("mem-%d", time.Now().UnixNano())
	}
	return "mem-" + hex.EncodeToString(b)
}

// normalizeTags accepts either a comma-separated string or a JSON
// array of strings (Anthropic tool args can be either) and emits the
// canonical comma-separated form for storage.
func normalizeTags(raw any) string {
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		parts := []string{}
		for _, e := range v {
			if s, ok := e.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					parts = append(parts, s)
				}
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

// loadRecentPrefs returns up to `limit` most-recent preference rows
// from the user's me-prefs bank, newest first. Empty list when the
// bank doesn't exist yet. Used by buildSystemPrompt so the agent
// always has the user's known preferences in context.
func loadRecentPrefs(userID string, limit int) []map[string]any {
	if limit <= 0 || limit > 50 {
		limit = 12
	}
	path := prefsBankPath(userID)
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	rows := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		rows = append(rows, row)
	}
	// Newest first by created_at (RFC3339 strings sort lexicographically).
	sort.Slice(rows, func(i, j int) bool {
		a, _ := rows[i]["created_at"].(string)
		b, _ := rows[j]["created_at"].(string)
		return a > b
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// renderPrefsBlock formats the recent prefs as a system-prompt
// section. Empty string when no prefs exist, so the prompt stays
// clean for new users.
func renderPrefsBlock(userID string) string {
	prefs := loadRecentPrefs(userID, 12)
	if len(prefs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n\n## What you know about this user (long-term memory)\n")
	sb.WriteString("These are notes the user has explicitly asked you to remember (via the `remember_about_me` tool). Apply them to your replies; cite them when relevant; update or correct them with new `remember_about_me` calls when the user signals a change.\n\n")
	for _, p := range prefs {
		content, _ := p["content"].(string)
		if content == "" {
			continue
		}
		ts, _ := p["created_at"].(string)
		date := ts
		if len(date) >= 10 {
			date = date[:10]
		}
		sb.WriteString(fmt.Sprintf("- (%s) %s\n", date, truncStr(content, 240)))
	}
	return sb.String()
}
