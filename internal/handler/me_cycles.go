package handler

// /api/v1/me/cycles/* — per-cycle write surface.
//
// POST /me/cycles/feedback — keystone of Hook 2 ("adapt to me"). Each
// feedback entry is the user telling the loop what worked or what to
// change. Stored two places:
//   1. <cycle_dir>/feedback.jsonl — co-located with the artifact so
//      future cycles' prior_knowledge step picks it up via the same
//      bank-read code path that reads memories.
//   2. <app>/data/journal.jsonl — appended as a {type:"feedback", …}
//      row so /admin/loops + /me/loops/health can surface the feedback
//      count per loop.
//
// Cycle addressing matches /admin/cycle-artifact:
//   ~/.xp/apps/<app>/data/cycles/<loop>/<ts>/
// Tenant-aware: caller's tenant root takes precedence, operator-shared
// is the fallback (so a tenant who's running the operator's auto-quant
// loop can still leave feedback even though the cycle dir is shared).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Cycle timestamp dirs are <YYYYMMDD>T<HHMMSS>Z. Some loops add a
// suffix (e.g. _retry) so we allow alphanumerics, hyphens, and
// underscores after the canonical prefix.
var cycleTsRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z[A-Za-z0-9_-]{0,32}$`)

type meCycleFeedbackBody struct {
	App    string `json:"app"    binding:"required"`
	Loop   string `json:"loop"   binding:"required"`
	Ts     string `json:"ts"     binding:"required"`
	Rating int    `json:"rating"` // -1 (bad), 0 (neutral), +1 (good)
	Note   string `json:"note"`   // free-text — the natural-language signal
}

// POST /api/v1/me/cycles/feedback
//
// Body: {"app":"personal-agent","loop":"morning_brief",
//
//	"ts":"20260522T150000Z","rating":1,"note":"perfect — keep this format"}
//
// The agent's give_feedback tool (P4) calls this with the same shape,
// so the natural-language path and a future UI button share one
// backend.
func MeCycleFeedback(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body meCycleFeedbackBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) || !slugRe.MatchString(body.Loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop name")
		return
	}
	if !cycleTsRe.MatchString(body.Ts) {
		fail(c, http.StatusBadRequest, 1400, "invalid ts — expected YYYYMMDDTHHMMSSZ")
		return
	}
	if body.Rating < -1 || body.Rating > 1 {
		fail(c, http.StatusBadRequest, 1400, "rating must be -1, 0, or +1")
		return
	}
	if len(body.Note) > 4000 {
		fail(c, http.StatusBadRequest, 1400, "note must be ≤4000 chars")
		return
	}

	cycleDir, source := resolveCycleDir(userID, body.App, body.Loop, body.Ts)
	if cycleDir == "" {
		fail(c, http.StatusNotFound, 1404,
			fmt.Sprintf("cycle not found in tenant or shared at %s/%s/%s", body.App, body.Loop, body.Ts))
		return
	}

	entry := map[string]any{
		"type":       "feedback",
		"app":        body.App,
		"loop":       body.Loop,
		"ts":         body.Ts,
		"rating":     body.Rating,
		"note":       body.Note,
		"by":         userID,
		"at":         time.Now().UTC().Format(time.RFC3339),
		"cycle_root": source, // "tenant" | "shared" — useful for downstream filtering
	}

	// 1. Co-located feedback.jsonl in the cycle dir.
	if err := appendJSONL(filepath.Join(cycleDir, "feedback.jsonl"), entry); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write feedback.jsonl: "+err.Error())
		return
	}

	// 2. Per-app journal so loops dashboards surface the count.
	// cycleDir is <appDir>/<cycles-root>/<loop>/<ts> where <cycles-root> is
	// either ".lumid/cycles" (canonical) or "data/cycles" (legacy); peel off
	// ts/loop/cycles/<state-dir> to recover the bundle root.
	appDir := strings.TrimSuffix(strings.TrimSuffix(cycleDir, body.Ts), "/")
	appDir = strings.TrimSuffix(strings.TrimSuffix(appDir, body.Loop), "/")
	appDir = strings.TrimSuffix(appDir, "/.lumid/cycles")
	appDir = strings.TrimSuffix(appDir, "/data/cycles")
	// 2b. Mirror into the improvement ledger so the Intent detail
	//     page can render this as an axis="examples" event without
	//     scanning every cycle dir. Non-fatal; the canonical record
	//     lives in feedback.jsonl above.
	{
		var verb string
		switch {
		case body.Rating > 0:
			verb = "good"
		case body.Rating < 0:
			verb = "wrong"
		default:
			verb = "edit"
		}
		label := body.Note
		if label == "" {
			label = fmt.Sprintf("user %s on %s/%s @ %s", verb, body.App, body.Loop, body.Ts)
		}
		_ = appendImprovement(userID, &improvementEvent{
			App:       body.App,
			Loop:      body.Loop,
			CycleTs:   body.Ts,
			Axis:      "examples",
			Verb:      verb,
			Label:     label,
			Rationale: body.Note,
			Source:    "user",
		})
	}

	journalPath, jerr := ResolveRuntimeWritePath(appDir, "data/journal.jsonl")
	if jerr != nil {
		// Non-fatal — the primary record is in feedback.jsonl.
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "feedback saved (journal path resolve failed: " + jerr.Error() + ")",
			"data": gin.H{
				"cycle_dir": cycleDir,
				"source":    source,
			},
		})
		return
	}
	if err := appendJSONL(journalPath, entry); err != nil {
		// Non-fatal — the primary record is in feedback.jsonl.
		// We still log via the response.
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "feedback saved (journal append failed: " + err.Error() + ")",
			"data": gin.H{
				"cycle_dir": cycleDir,
				"source":    source,
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "feedback saved",
		"data": gin.H{
			"cycle_dir": cycleDir,
			"source":    source, // "tenant" | "shared"
			"saved_at":  entry["at"],
		},
	})
}

// resolveCycleDir locates the cycle dir for (app, loop, ts) preferring
// the caller's tenant root, falling back to operator-shared. Returns
// the absolute path + a label ("tenant" or "shared"), or "" if neither
// exists.
func resolveCycleDir(userSub, app, loop, ts string) (string, string) {
	candidates := []struct {
		base   string
		source string
	}{
		{tenantAppsDir(userSub), "tenant"},
		{filepath.Join(operatorHome(), ".xp", "apps"), "shared"},
	}
	for _, cand := range candidates {
		// Prefer the canonical .lumid/cycles tree, fall back to legacy data/cycles.
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(cand.base, app), "data/cycles")
		dir := filepath.Join(cyclesRoot, loop, ts)
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			return dir, cand.source
		}
	}
	return "", ""
}

// nearestCycleDir resolves the cycle dir CLOSEST in time to `wantTs` for an
// app/loop, across tenant + operator trees. Drilling into a run must not
// dead-end just because the caller's ts is approximate — list_runs derives a
// ts from the journal clock, which for Pattern-B loops (two dirs per fire: a
// `…Z` wrapper + a `…Z` work dir seconds later) won't byte-match the dir. We
// pick the dir with the smallest absolute time difference (ties → latest).
// Returns (absPath, actualTs); "" if the loop has no cycles at all.
func nearestCycleDir(userSub, app, loop, wantTs string) (string, string) {
	const layout = "20060102T150405Z"
	want, werr := time.Parse(layout, wantTs)
	var bestDir, bestTs string
	var bestDiff time.Duration = 1<<62 - 1
	for _, base := range []string{tenantAppsDir(userSub), filepath.Join(operatorHome(), ".xp", "apps")} {
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(base, app), "data/cycles")
		root := filepath.Join(cyclesRoot, loop)
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			dir := filepath.Join(root, name)
			// No parseable want-ts → just take the latest dir overall.
			if werr != nil {
				if name > bestTs {
					bestTs, bestDir = name, dir
				}
				continue
			}
			got, perr := time.Parse(layout, name)
			if perr != nil {
				continue
			}
			diff := got.Sub(want)
			if diff < 0 {
				diff = -diff
			}
			if diff < bestDiff || (diff == bestDiff && name > bestTs) {
				bestDiff, bestDir, bestTs = diff, dir, name
			}
		}
	}
	return bestDir, bestTs
}

// nearestSummaryDir finds the cycle dir closest in time to `ts` (excluding ts
// itself) that actually has a cycle.json. Pattern-B loops write a wrapper dir
// (has cycle.json) + a work dir seconds later (observations/proposal only) — a
// drill into the WORK dir has no summary, so we pull it from the nearest
// wrapper. Returns "" if none found.
func nearestSummaryDir(userSub, app, loop, ts string) string {
	const layout = "20060102T150405Z"
	want, werr := time.Parse(layout, ts)
	best, bestDiff := "", time.Duration(1<<62-1)
	for _, base := range []string{tenantAppsDir(userSub), filepath.Join(operatorHome(), ".xp", "apps")} {
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(base, app), "data/cycles")
		root := filepath.Join(cyclesRoot, loop)
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || e.Name() == ts {
				continue
			}
			dir := filepath.Join(root, e.Name())
			if _, err := os.Stat(filepath.Join(dir, "cycle.json")); err != nil {
				continue // only dirs that carry a summary
			}
			if werr != nil {
				if best == "" {
					best = dir
				}
				continue
			}
			got, perr := time.Parse(layout, e.Name())
			if perr != nil {
				continue
			}
			diff := got.Sub(want)
			if diff < 0 {
				diff = -diff
			}
			if diff < bestDiff {
				bestDiff, best = diff, dir
			}
		}
	}
	return best
}

// memoriesLearnedInCycle returns the KG memories a cycle's learn stage wrote,
// correlated by TIME WINDOW: a memory belongs to cycle <ts> if its created_at
// falls in [ts, next_cycle_ts) for one of the app's memory_agents. This needs
// no producer-side changes and works for BOTH Pattern A (app_runner learn) and
// Pattern B (a verb's own bank writes) — and retroactively for existing banks.
// It's what turns "what it learned" from empty into the actual synthesized
// insight (e.g. "avoid with_sample_values (-15pp)"), since learning lands in
// the agent banks, not the cycle dir.
func memoriesLearnedInCycle(userSub, app, loop, ts string) []map[string]any {
	const layout = "20060102T150405Z"
	start, err := time.Parse(layout, ts)
	if err != nil {
		return nil
	}
	// Window end = the next cycle dir after ts (across both trees); else +24h.
	end := start.Add(24 * time.Hour)
	nextTs := ""
	for _, base := range []string{tenantAppsDir(userSub), filepath.Join(operatorHome(), ".xp", "apps")} {
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(base, app), "data/cycles")
		entries, derr := os.ReadDir(filepath.Join(cyclesRoot, loop))
		if derr != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() && n > ts && (nextTs == "" || n < nextTs) {
				nextTs = n
			}
		}
	}
	if nextTs != "" {
		if nt, e := time.Parse(layout, nextTs); e == nil {
			end = nt
		}
	}
	startU, endU := float64(start.Unix()), float64(end.Unix())

	// Memory agents from xpcloud.yaml (tenant copy first, then operator-shared).
	var agents []string
	for _, base := range []string{tenantAppsDir(userSub), filepath.Join(operatorHome(), ".xp", "apps")} {
		specPath, _ := ResolveSpecPath(filepath.Join(base, app))
		if a := readYamlMemoryAgents(specPath); len(a) > 0 {
			agents = a
			break
		}
	}

	out := []map[string]any{}
	seen := map[string]bool{}
	kgRoots := []string{
		filepath.Join(tenantRoot(userSub), ".xp", "kg", "agents"),
		filepath.Join(operatorHome(), ".xp", "kg", "agents"),
	}
	for _, ag := range agents {
		for _, kg := range kgRoots {
			b, rerr := os.ReadFile(filepath.Join(kg, ag, "bank.jsonl"))
			if rerr != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var m map[string]any
				if json.Unmarshal([]byte(line), &m) != nil {
					continue
				}
				ca, _ := m["created_at"].(float64)
				if ca < startU || ca >= endU {
					continue
				}
				id, _ := m["id"].(string)
				if seen[id] {
					continue
				}
				seen[id] = true
				content, _ := m["content"].(string)
				if len(content) > 240 {
					content = content[:240] + "…"
				}
				out = append(out, map[string]any{
					"agent": ag, "id": id, "title": m["title"],
					"content": content, "created_at": ca,
				})
			}
		}
	}
	return out
}

// appendJSONL appends one JSON-encoded entry as a line. Creates parent
// dirs as needed. Uses O_APPEND so concurrent writers don't tear.
func appendJSONL(path string, row map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(row)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
