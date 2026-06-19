package handler

// Helpers for the conversational shell's tool dispatcher. Pull the
// "side-effect" parts of the HTTP handlers into plain Go funcs so the
// agent can call them without going through HTTP.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// toolListApps returns the same shape as MeAppsList — caller's tenant
// plus operator-shared, each with a tenant flag.
func toolListApps(userID string) map[string]any {
	type appCard struct {
		Name     string `json:"name"`
		Tenant   bool   `json:"tenant"`
		HasMfst  bool   `json:"has_manifest"`
	}
	out := []appCard{}
	walk := func(root string, isTenant bool) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			_, mfstOk := ResolveManifestPath(filepath.Join(root, e.Name()))
			out = append(out, appCard{
				Name:    e.Name(),
				Tenant:  isTenant,
				HasMfst: mfstOk,
			})
		}
	}
	walk(tenantAppsDir(userID), true)
	walk(filepath.Join(operatorHome(), ".xp", "apps"), false)
	return map[string]any{"apps": out, "count": len(out)}
}

// writeIntentDirect is writeIntent without the *gin.Context — for the
// agent path that doesn't need to set HTTP response on failure.
// Returns the intent UUID or "" on error.
func writeIntentDirect(userSub, action string, payload map[string]any) string {
	dir := intentDir()
	// World-writable so the scheduler can write results regardless of its uid
	// (see writeIntent for the full rationale — uid mismatch broke 0o775).
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return ""
	}
	_ = os.Chmod(dir, 0o777)

	id := uuid.New().String()
	envelope := map[string]any{
		"intent_id":  id,
		"action":     action,
		"user_sub":   userSub,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"payload":    payload,
	}
	body, _ := json.MarshalIndent(envelope, "", "  ")
	tmp := filepath.Join(dir, id+".json.tmp")
	final := filepath.Join(dir, id+".json")
	if err := os.WriteFile(tmp, body, 0o666); err != nil {
		return ""
	}
	if err := os.Rename(tmp, final); err != nil {
		return ""
	}
	_ = os.Chmod(final, 0o666)
	return id
}

// agentEnqueueOneshot appends a one-shot job to ~/.lumilake/jobs.jsonl.
// Same schema MeLoopRunNow writes.
func agentEnqueueOneshot(userID, app, loop string) (string, error) {
	jobID := fmt.Sprintf("oneshot-%d", time.Now().UnixNano())
	row := map[string]any{
		"job_id":         jobID,
		"source":         "loop_cycle",
		"submitter_app":  app,
		"submitter_loop": loop,
		"state":          "queued",
		"submitted_at":   time.Now().UTC().Format(time.RFC3339),
		"submitted_by":   userID,
		"payload": map[string]any{
			"oneshot": true, "via": "agent",
		},
	}
	if err := appendJobRow(row); err != nil {
		return "", err
	}
	return jobID, nil
}

// agentLatestCycleTs returns the most recent cycle ts dir name for
// (app, loop) — caller's tenant first, then operator-shared.
func agentLatestCycleTs(userID, app, loop string) (string, error) {
	for _, base := range []string{tenantAppsDir(userID), filepath.Join(operatorHome(), ".xp", "apps")} {
		// Prefer the canonical .lumid/cycles tree, fall back to legacy data/cycles.
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(base, app), "data/cycles")
		dir := filepath.Join(cyclesRoot, loop)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		names := []string{}
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		return names[len(names)-1], nil
	}
	return "", fmt.Errorf("no cycles found")
}

// agentWriteFeedback writes a feedback entry to the cycle dir +
// app journal. Same logic as MeCycleFeedback minus the HTTP response.
func agentWriteFeedback(userID, app, loop, ts string, rating int, note string) error {
	cycleDir, source := resolveCycleDir(userID, app, loop, ts)
	if cycleDir == "" {
		return fmt.Errorf("cycle not found: %s/%s/%s", app, loop, ts)
	}
	entry := map[string]any{
		"type":       "feedback",
		"app":        app,
		"loop":       loop,
		"ts":         ts,
		"rating":     rating,
		"note":       note,
		"by":         userID,
		"at":         time.Now().UTC().Format(time.RFC3339),
		"cycle_root": source,
		"via":        "agent",
	}
	if err := appendJSONL(filepath.Join(cycleDir, "feedback.jsonl"), entry); err != nil {
		return err
	}
	// Best-effort journal append; primary record is feedback.jsonl.
	// cycleDir is <appDir>/{.lumid|data}/cycles/<loop>/<ts>; strip ts, loop,
	// then either the canonical or legacy "<root>/cycles/" suffix to recover appDir.
	appDir := strings.TrimSuffix(strings.TrimSuffix(cycleDir, ts), "/")
	appDir = strings.TrimSuffix(appDir, loop)
	appDir = strings.TrimSuffix(appDir, "/")
	appDir = strings.TrimSuffix(appDir, "/"+filepath.Join(RuntimeStateDir, "cycles"))
	appDir = strings.TrimSuffix(appDir, "/data/cycles")
	// Journal is a runtime artifact: write to the canonical .lumid/journal.jsonl.
	journalPath, err := ResolveRuntimeWritePath(appDir, "data/journal.jsonl")
	if err != nil {
		journalPath = filepath.Join(appDir, "data", "journal.jsonl")
	}
	_ = appendJSONL(journalPath, entry)
	return nil
}

// agentListCycles returns the N most-recent cycle ts dirs for a loop.
func agentListCycles(userID, app, loop string, limit int) []map[string]any {
	out := []map[string]any{}
	for _, src := range []struct {
		base   string
		source string
	}{
		{tenantAppsDir(userID), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "apps"), "shared"},
	} {
		// Prefer the canonical .lumid/cycles tree, fall back to legacy data/cycles.
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(src.base, app), "data/cycles")
		dir := filepath.Join(cyclesRoot, loop)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		names := []string{}
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, n := range names {
			if len(out) >= limit {
				break
			}
			out = append(out, map[string]any{
				"ts":     n,
				"source": src.source,
				"path":   filepath.Join(dir, n),
			})
		}
		if len(out) >= limit {
			break
		}
	}
	return out
}

// agentListMarketplace queries xp.io for available apps. The xpcloud
// repos endpoint returns {"repos":[...]} with public visibility.
func agentListMarketplace(q string, limit int) []map[string]any {
	url := fmt.Sprintf("https://xp.io/api/v1/repos/search?kind=app&q=%s&limit=%d", q, limit)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}
	repos, _ := parsed["repos"].([]any)
	out := []map[string]any{}
	for _, r := range repos {
		row, _ := r.(map[string]any)
		if row == nil {
			continue
		}
		slug := fmt.Sprintf("%s/%s", row["owner_sub"], row["name"])
		out = append(out, map[string]any{
			"slug":    slug,
			"name":    row["name"],
			"summary": row["summary"],
			"version": row["version"],
			"kind":    row["kind"],
		})
	}
	return out
}

// agentQueryKnowledge greps the user's local KG banks for memories.
// Matching is token-wise OR (any whitespace-separated term in the
// query needs to appear in the line, case-insensitive). Rows are
// then scored by how many distinct query tokens hit + length-
// boosted for shorter, denser hits, and returned best-first.
//
// Keyword-only — cheap, no embeddings infra. Walks BOTH tenant
// agents (~/.tenants/<sub>/.xp/kg/agents/*/) and operator-shared
// agents (~/.xp/kg/agents/*/) so the user sees both their own
// memories and the operator's accumulated knowledge.
//
// Returns up to `limit` hits, each {agent, id, title, content_snippet, source, score}.
func agentQueryKnowledge(userID, query, agentFilter string, limit int) []map[string]any {
	// Tokenize the query — lowercase, split on whitespace + punctuation.
	tokens := []string{}
	{
		clean := strings.Map(func(r rune) rune {
			switch r {
			case ',', '.', ';', ':', '!', '?', '"', '\'', '(', ')', '[', ']', '{', '}', '/', '\\':
				return ' '
			}
			return r
		}, strings.ToLower(query))
		for _, t := range strings.Fields(clean) {
			if len(t) >= 2 { // skip 1-char tokens; mostly noise
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) == 0 {
		return nil
	}

	type scoredHit struct {
		score float64
		row   map[string]any
	}
	hits := []scoredHit{}

	roots := []struct {
		base   string
		source string
	}{
		{filepath.Join(tenantRoot(userID), ".xp", "kg", "agents"), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "kg", "agents"), "shared"},
	}
	const maxRowsScanned = 5000 // safety bound on huge banks
	scanned := 0

	for _, r := range roots {
		entries, err := os.ReadDir(r.base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if agentFilter != "" && e.Name() != agentFilter {
				continue
			}
			bankPath := filepath.Join(r.base, e.Name(), "bank.jsonl")
			f, err := os.Open(bankPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
			for scanner.Scan() {
				if scanned++; scanned > maxRowsScanned {
					_ = f.Close()
					goto done
				}
				line := strings.ToLower(scanner.Text())
				matched := 0
				for _, tok := range tokens {
					if strings.Contains(line, tok) {
						matched++
					}
				}
				if matched == 0 {
					continue
				}
				var row map[string]any
				if err := json.Unmarshal([]byte(scanner.Text()), &row); err != nil {
					continue
				}
				content, _ := row["content"].(string)
				snippet := content
				if len(snippet) > 280 {
					snippet = snippet[:280] + "…"
				}
				// Score: term coverage dominates; tiebreak with inverse
				// content length (denser = better).
				score := float64(matched)
				if len(content) > 0 {
					score += 1.0 / float64(len(content))
				}
				hits = append(hits, scoredHit{
					score: score,
					row: map[string]any{
						"agent":           e.Name(),
						"id":              row["id"],
						"type":            row["type"],
						"title":           row["title"],
						"content_snippet": snippet,
						"source":          r.source,
						"score":           score,
						"matched_terms":   matched,
					},
				})
			}
			_ = f.Close()
		}
	}
done:
	sort.Slice(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	if len(hits) > limit {
		hits = hits[:limit]
	}
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.row)
	}
	return out
}

// _silence_unused_compile_errors — keeps go vet quiet about bytes/buffer
// helpers used elsewhere in this file under different code paths.
var _ = bytes.NewReader