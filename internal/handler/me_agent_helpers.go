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
)

// toolListApps returns the same shape as MeAppsList — caller's tenant
// plus operator-shared, each with a tenant flag.
func toolListApps(userID string) map[string]any {
	type appCard struct {
		Name    string `json:"name"`
		Tenant  bool   `json:"tenant"`
		HasMfst bool   `json:"has_manifest"`
	}
	out := []appCard{}
	seen := map[string]bool{}
	walk := func(root string, isTenant bool) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || seen[e.Name()] {
				continue
			}
			seen[e.Name()] = true
			_, mfstOk := ResolveManifestPath(filepath.Join(root, e.Name()))
			out = append(out, appCard{
				Name:    e.Name(),
				Tenant:  isTenant,
				HasMfst: mfstOk,
			})
		}
	}
	// Walk every root, cache included — this reported "0 apps" to the chat for a
	// cloud tenant whose apps live in the materialised cache rather than on a
	// disk identity mounts. The agent then told the user, in its own words, that
	// they had no apps installed while /me/apps said ready.
	//
	// Dedupe by name: appListRoots can surface the same app from more than one
	// root and the first root wins, matching resolveAppDir.
	for i, root := range appListRoots(userID) {
		walk(root, i != 1) // index 1 is the operator-shared root
	}
	return map[string]any{"apps": out, "count": len(out)}
}

// writeIntentDirect is writeIntent without the *gin.Context — for the agent
// path that doesn't need to set an HTTP response on failure. Enqueues into the
// DB-backed queue (see me_intents_db.go). Returns the intent id or "" on error.
func writeIntentDirect(userSub, action string, payload map[string]any) string {
	id, err := insertIntent(action, userSub, payload)
	if err != nil {
		return ""
	}
	return id
}

// agentEnqueueOneshot appends a one-shot job to ~/.lumilake/jobs.jsonl.
// Same schema MeLoopRunNow writes. Optional `args` (e.g. {"cases":"Case_019"})
// scopes the run — the loop's {{ args.* }} template expands them; nil = full.
func agentEnqueueOneshot(userID, app, loop string, args map[string]any) (string, error) {
	jobID := fmt.Sprintf("oneshot-%d", time.Now().UnixNano())
	payload := map[string]any{"oneshot": true, "via": "agent"}
	if len(args) > 0 {
		payload["args"] = args
	}
	row := map[string]any{
		"job_id":         jobID,
		"source":         "loop_cycle",
		"submitter_app":  app,
		"submitter_loop": loop,
		"state":          "queued",
		"submitted_at":   time.Now().UTC().Format(time.RFC3339),
		"submitted_by":   userID,
		"payload":        payload,
	}
	if err := appendJobRow(row); err != nil {
		return "", err
	}
	return jobID, nil
}

// agentStopLoop — chat twin of REST MeLoopStop. Writes the per-loop cooperative
// stop signal the runner checks before each LLM call (→ cycle aborts) + a
// "stopped by user" journal event. Returns the in-flight cycle ts it observed
// (best-effort, may be ""). Safe + reversible (just re-run to restart).
func agentStopLoop(userID, app, loop string) (string, error) {
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return "", fmt.Errorf("app not found: %s", app)
	}
	controlDir := filepath.Join(appDir, "data", "control")
	if err := os.MkdirAll(controlDir, 0o755); err != nil {
		return "", err
	}
	sig := map[string]any{"loop": loop, "by": userID, "at": time.Now().UTC().Format(time.RFC3339)}
	if b, err := json.Marshal(sig); err == nil {
		if err := os.WriteFile(filepath.Join(controlDir, "stop."+loop+".signal"), b, 0o644); err != nil {
			return "", err
		}
	}
	jrow := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "loop": loop,
		"event": "control", "stage": "stopped", "status": "stopped",
		"ok": false, "outcome": "interrupted", "note": "stopped by user (chat)",
	}
	if b, err := json.Marshal(jrow); err == nil {
		if f, e := os.OpenFile(filepath.Join(appDir, "data", "journal.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); e == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}
	stopped := ""
	cyclesDir := filepath.Join(appDir, "data", "cycles", loop)
	if entries, err := os.ReadDir(cyclesDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() > stopped {
				if _, err := os.Stat(filepath.Join(cyclesDir, e.Name(), "cycle.json")); err != nil {
					stopped = e.Name()
				}
			}
		}
	}
	return stopped, nil
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
