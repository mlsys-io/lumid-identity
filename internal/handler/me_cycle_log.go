// me_cycle_log.go — GET /api/v1/me/apps/:app/cycle-log?loop=&after=<n>
//
// Live execution feed for a running (or recent) cycle. The runner + command
// engines append per-stage events to <appDir>/data/journal.jsonl AS THE CYCLE
// RUNS (hypothesize start, variant proposed, act, errors, …), so tailing it
// gives real-time progress. We poll-tail rather than SSE: SSE through the
// nginx/FRP chain is flaky (it's what broke the chat stop button), a cursor
// poll is robust.
//
// `after` is a line cursor (0-based index into journal.jsonl). Returns rows
// with index > after, filtered to the loop, plus `total` (current line count)
// so the caller advances its cursor. Read-only, best-effort.
package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// readStreamPartial reads the in-flight LLM call's partial sidecar (written by
// claude_code_caller as a turn streams) and returns it as a conversation row,
// or nil if absent/empty. Tagged partial:true so the UI can show a live cursor.
func readStreamPartial(cdir string) map[string]any {
	b, err := os.ReadFile(filepath.Join(cdir, ".llm_stream.json"))
	if err != nil {
		return nil
	}
	var row map[string]any
	if json.Unmarshal(b, &row) != nil {
		return nil
	}
	if row["event"] == nil {
		row["event"] = "llm"
	}
	row["partial"] = true
	return row
}

const cycleLogTailCap = 300

func MeCycleLog(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Query("loop")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	after := -1
	if a := c.Query("after"); a != "" {
		if n, err := strconv.Atoi(a); err == nil {
			after = n
		}
	}
	ts := c.Query("ts")
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// ts=latest → resolve to the newest cycle dir (the running/just-finished
	// one), so a "view the running session" affordance needn't know the ts.
	if ts == "latest" && loop != "" {
		loopCyclesDir, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "cycles", loop))
		if entries, err := os.ReadDir(loopCyclesDir); err == nil {
			newest := ""
			for _, e := range entries {
				if e.IsDir() && e.Name() > newest {
					newest = e.Name()
				}
			}
			ts = newest
		}
		// No cycle dirs on this pod (the caller's install is on the
		// scheduler's volume): the newest run in the store names it.
		if ts == "latest" || ts == "" {
			if id, err := resolveLatestCycleTs(userID, app, loop); err == nil {
				ts = id
			}
		}
	}
	// Conversation mode: a specific cycle's session — its LLM turns (the AI
	// generation) merged with its journal stage/tool events, newest-relevant
	// last. Returns the full (capped) timeline each poll; the UI replaces.
	if ts != "" && loop != "" && slugRe.MatchString(ts) {
		conv := cycleConversation(appDir, loop, ts)
		running := false
		cdir, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "cycles", loop, ts))
		if _, err := os.Stat(filepath.Join(cdir, "cycle.json")); err != nil {
			if st, e2 := os.Stat(cdir); e2 == nil {
				running = true // dir exists, no cycle.json yet → in flight
				_ = st
			}
		}
		// While the cycle runs, surface the IN-FLIGHT LLM call's partial text
		// (the .llm_stream.json sidecar the caller tees) as the live last turn,
		// so the session reveals output progressively instead of one finished
		// block at a time. Skip it once the full turn is in the conv log.
		if running {
			if pr := readStreamPartial(cdir); pr != nil {
				prResp, _ := pr["response"].(string)
				dup := false
				for _, r := range conv {
					if r["event"] == "llm" {
						if rs, _ := r["response"].(string); prResp != "" && strings.HasPrefix(rs, prResp) {
							dup = true // the final turn already supersedes this partial
						}
					}
				}
				if !dup && prResp != "" {
					conv = append(conv, pr)
				}
			}
		}
		resp := gin.H{"app": app, "loop": loop, "ts": ts, "rows": conv,
			"running": running, "conversation": true}
		if len(conv) == 0 {
			// Empty because the transcript is unreachable, or empty because
			// nothing was said? They mean opposite things and read identically.
			if why := unavailableReason(appDir, "this cycle's LLM transcript"); why != "" {
				// The caller's own install: the scheduler reads the cycle's
				// LLM turns for us. Journal stage events are not included —
				// the journal is app-wide and large; the turns are the session.
				if rows, running, err, tried := cycleTranscriptViaScheduler(ginReqCtx(c), userID, app, loop, ts); tried {
					switch {
					case err == nil:
						resp["rows"], resp["running"], resp["source"] = rows, running, "scheduler"
						why = ""
					case errors.Is(err, errCycleNotOnScheduler):
						why = ""
					default:
						why = "this cycle's LLM transcript could not be read from the scheduler: " + err.Error()
					}
				}
				if why != "" {
					resp["unavailable"] = why
				}
			}
		}
		ok(c, "ok", resp)
		return
	}

	path, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "journal.jsonl"))
	rows := []map[string]any{}
	total := 0
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		idx := -1
		for sc.Scan() {
			idx++
			total = idx + 1
			if idx <= after {
				continue
			}
			line := sc.Text()
			if line == "" {
				continue
			}
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			// Filter to this loop (rows without a loop field pass — some
			// engine-level events omit it). Carry the line index so the UI
			// can dedupe / advance precisely.
			if loop != "" {
				if lp, ok := row["loop"].(string); ok && lp != "" && lp != loop {
					continue
				}
			}
			row["_i"] = idx
			rows = append(rows, row)
		}
		f.Close()
	}
	// Cap to the most recent tail so a cold first poll (after=-1) doesn't ship
	// the entire history; live polls (after=total) return only the few new rows.
	if len(rows) > cycleLogTailCap {
		rows = rows[len(rows)-cycleLogTailCap:]
	}
	resp := gin.H{"app": app, "loop": loop, "rows": rows, "total": total}
	if total == 0 {
		if why := unavailableReason(appDir, "this app's cycle log"); why != "" {
			resp["unavailable"] = why
		}
	}
	ok(c, "ok", resp)
}

// cycleConversation builds one cycle's session timeline: its LLM turns
// (prompt+response, from the per-cycle .llm_conversation.jsonl claude_code_caller
// wrote) merged with the loop journal's stage/tool events in this cycle's time
// window (ts >= the cycle's start), sorted chronologically. This is what the UI
// renders as the running session's subagent/tool-style conversation.
func cycleConversation(appDir, loop, ts string) []map[string]any {
	out := []map[string]any{}
	readJSONL := func(p string, fn func(map[string]any)) {
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				continue
			}
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) == nil {
				fn(row)
			}
		}
	}
	// 1. LLM turns for this cycle (definitively this run's AI generation).
	convPath, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "cycles", loop, ts, ".llm_conversation.jsonl"))
	readJSONL(convPath, func(r map[string]any) {
		out = append(out, r)
	})
	// 2. Journal stage/tool events from this cycle's start onward (loop-scoped).
	start := digitsOnlyTs(ts)
	journalPath, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "journal.jsonl"))
	readJSONL(journalPath, func(r map[string]any) {
		if lp, ok := r["loop"].(string); ok && lp != "" && lp != loop {
			return
		}
		rts, _ := r["ts"].(string)
		if digitsOnlyTs(rts) < start {
			return
		}
		if _, has := r["event"]; !has {
			r["event"] = "stage"
		}
		out = append(out, r)
	})
	// Chronological by ts.
	sort.SliceStable(out, func(i, j int) bool {
		ti, _ := out[i]["ts"].(string)
		tj, _ := out[j]["ts"].(string)
		return ti < tj
	})
	if len(out) > cycleLogTailCap {
		out = out[len(out)-cycleLogTailCap:]
	}
	return out
}

// digitsOnlyTs strips non-digits so a cycle dir id ("20260616T211953Z") and an
// ISO journal ts ("2026-06-16T21:19:53Z") become comparable ("20260616211953").
func digitsOnlyTs(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b = append(b, s[i])
		}
	}
	return string(b)
}

// cycleTranscriptViaScheduler reads one cycle's LLM turns
// (.llm_conversation.jsonl) from the caller's own install on the scheduler.
// tried=false when the app is not the caller's scheduler-side install, so the
// caller keeps its own "not available" answer.
func cycleTranscriptViaScheduler(ctx context.Context, userID, app, loop, ts string) (rows []map[string]any, running bool, err error, tried bool) {
	if _, direct, viaIntent, _ := ownerWriteTarget(userID, app); direct || !viaIntent || !safeSeg(loop) || !safeSeg(ts) {
		return nil, false, nil, false
	}
	res, err := cycleFilesViaScheduler(ctx, userID, app, loop, ts, true)
	if err != nil {
		return nil, false, err, true
	}
	rows = []map[string]any{}
	sc := bufio.NewScanner(bytes.NewReader(res.files[".llm_conversation.jsonl"]))
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var row map[string]any
		if json.Unmarshal(sc.Bytes(), &row) == nil {
			rows = append(rows, row)
		}
	}
	if len(rows) > cycleLogTailCap {
		rows = rows[len(rows)-cycleLogTailCap:]
	}
	return rows, res.running, nil, true
}
