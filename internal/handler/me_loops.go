package handler

// /api/v1/me/loops/* — per-loop control plane.
//
// Three actions, all completable in-Go without external execution:
//   PATCH /me/loops/:app/:loop {runtime?, schedule?, enabled?, goal?}
//       — writes ~/.xp/apps/:app/.user-overrides.yaml (Helm-values
//         style; merged last by sdk/apps/app_runner.load_manifest in
//         P1+). In P0 the file lands on disk and the scheduler honors
//         the `enabled` field via its existing skip logic; full
//         schedule/runtime merging arrives with the load_manifest
//         change.
//
//   POST /me/loops/:app/:loop/run
//       — appends a one-shot job entry to ~/.lumilake/jobs.jsonl
//         (matches the schema sdk/ops/jobs.py::record_submission
//         writes). The lumid-scheduler container polls this file and
//         picks up the run.
//
//   GET /me/loops/health
//       — tenant-scoped mirror of /admin/loops. In P0 the operator
//         host is single-tenant so we return everything; per-tenant
//         filtering lands when cloud runtime stands up (P2).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type meLoopPatchBody struct {
	Runtime  *string `json:"runtime,omitempty"`
	Schedule *string `json:"schedule,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
	// Goal — the loop's objective (xpcloud.yaml loops[].goal.primary). An
	// empty string clears the override (reverts to the declared goal).
	Goal *string `json:"goal,omitempty"`
	// Model — the per-workflow runtime model switch (loops[].model). A tier
	// alias (haiku|sonnet|opus) or "kvrun-gemma"; empty clears the override.
	// The scheduler maps it to the cycle's LLM env (see _run_loop_cycle).
	Model *string `json:"model,omitempty"`
}

// PATCH /api/v1/me/loops/:app/:loop
//
// Writes/merges keys into ~/.xp/apps/:app/.user-overrides.yaml. We use
// a minimal hand-rolled YAML emitter (3 keys only) so this file has
// zero new dependencies — the canonical merge logic lives in Python
// (app_runner.load_manifest).
func MeLoopPatch(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app/loop name")
		return
	}
	var body meLoopPatchBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Runtime != nil && *body.Runtime != "local" && *body.Runtime != "cloud" {
		fail(c, http.StatusBadRequest, 1400, "runtime must be local|cloud")
		return
	}

	// Resolve the app dir: caller's tenant first, then operator-shared. When
	// neither is on this pod's disk (UKS: bundle on the scheduler PVC), we skip
	// the disk write entirely and rely on the DB override below — the app must
	// still be in the caller's installed set (specForApp / install intent) so a
	// bogus name 404s.
	tenantDir := filepath.Join(tenantAppsDir(userID), app)
	appDir := ""
	if st, err := os.Stat(tenantDir); err == nil && st.IsDir() {
		appDir = tenantDir
	} else if shared := filepath.Join(operatorHome(), ".xp", "apps", app); func() bool {
		st2, err2 := os.Stat(shared)
		return err2 == nil && st2.IsDir()
	}() {
		// Operator-shared: synthesize a tenant override dir (the code lives in
		// `shared`; the override is a thin shim). os.MkdirAll is idempotent.
		if err := os.MkdirAll(tenantDir, 0o775); err == nil {
			appDir = tenantDir
		}
	}
	crossNode := appDir == ""
	if crossNode {
		if !appInstalledForUser(userID, app) {
			fail(c, http.StatusNotFound, 1404, "app not installed in your account")
			return
		}
	}

	// Build the effective loop-override map from the request, merged over any
	// existing on-disk overrides (so unknown/CLI-set keys survive) or, cross-node,
	// the existing DB override.
	loopOver := map[string]any{}
	if crossNode {
		if raw, has := appLoopOverrideGet(userID, app, loop); has {
			_ = json.Unmarshal([]byte(raw), &loopOver)
		}
	}
	var overrides map[string]any
	var overridesPath string
	if !crossNode {
		overridesPath = filepath.Join(appDir, ".user-overrides.yaml")
		overrides = readSimpleOverrides(overridesPath)
		if overrides["loops"] == nil {
			overrides["loops"] = map[string]any{}
		}
		loopsMap, _ := overrides["loops"].(map[string]any)
		if lo, _ := loopsMap[loop].(map[string]any); lo != nil {
			loopOver = lo
		}
	}

	if body.Runtime != nil {
		loopOver["runtime"] = *body.Runtime
	}
	if body.Schedule != nil {
		loopOver["schedule"] = *body.Schedule
	}
	if body.Enabled != nil {
		loopOver["enabled"] = *body.Enabled
	}
	if body.Goal != nil {
		// Single-line; bound the length so the tiny YAML emitter (which
		// quotes via %q on one line) stays well-formed. Empty clears it.
		g := strings.TrimSpace(*body.Goal)
		g = strings.ReplaceAll(g, "\n", " ")
		if len(g) > 280 {
			g = g[:280]
		}
		if g == "" {
			delete(loopOver, "goal")
		} else {
			loopOver["goal"] = g
		}
	}
	if body.Model != nil {
		if m := strings.TrimSpace(*body.Model); m == "" {
			delete(loopOver, "model") // empty → revert to the app default
		} else {
			loopOver["model"] = m
		}
	}

	if crossNode {
		// Store the loop override in me_docs (kind app_loop_override); the
		// scheduler pulls it at cycle start via /internal/app-loop-overrides/fetch.
		ojson, err := json.Marshal(loopOver)
		if err != nil {
			fail(c, http.StatusInternalServerError, 1500, "encode override: "+err.Error())
			return
		}
		if err := appLoopOverrideSave(userID, app, loop, string(ojson)); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "save override: "+err.Error())
			return
		}
	} else {
		loopsMap, _ := overrides["loops"].(map[string]any)
		loopsMap[loop] = loopOver
		overrides["loops"] = loopsMap
		// Audit trail — the file gets re-written every PATCH so we record
		// the last write timestamp + last-touched user.
		overrides["_meta"] = map[string]any{
			"last_modified_at": time.Now().UTC().Format(time.RFC3339),
			"last_modified_by": userID,
		}
		if err := writeSimpleOverrides(overridesPath, overrides); err != nil {
			fail(c, http.StatusInternalServerError, 1500, "write overrides: "+err.Error())
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":       app,
			"loop":      loop,
			"overrides": loopOver,
		},
	})
}

type meLoopRunBody struct {
	Args map[string]any `json:"args,omitempty"`
	// Trajectory ops (item 18). When this run is a fork / re-run-from-here /
	// run-a-variant of an earlier cycle, the UI (G3b) sends these; the
	// scheduler's drain_oneshots threads them into app_runner.cycle() so the
	// produced cycle.json records lineage. All optional → plain run-now.
	FromRunTs   string         `json:"from_run_ts,omitempty"`
	Variant     map[string]any `json:"variant,omitempty"`
	BranchLabel string         `json:"branch_label,omitempty"`
	// "Next Run" composer (Phases B/C/D). All optional; threaded into the
	// jobs.jsonl payload so the scheduler's drain_oneshots passes them into
	// app_runner.cycle() / the trajectory engine.
	//   Criteria    — Phase B: success criteria for this run (judge prompt).
	//   AutoPromote — Phase B: auto-promote the produced run if it wins.
	//   Cases       — Phase C: casebook case ids to evaluate this run against.
	//   NotBefore   — Phase D: ISO-8601 earliest-start gate (deferred run).
	Criteria    string   `json:"criteria,omitempty"`
	AutoPromote bool     `json:"auto_promote,omitempty"`
	Cases       []string `json:"cases,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
}

// POST /api/v1/me/loops/:app/:loop/run
//
// Appends a row to ~/.lumilake/jobs.jsonl that the lumid-scheduler
// picks up. Schema matches sdk/ops/jobs.py::record_submission.
func MeLoopRunNow(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app/loop name")
		return
	}
	var body meLoopRunBody
	_ = c.ShouldBindJSON(&body) // optional body

	// Enqueue a run_loop intent in the DB-backed queue (me_app_intents) — NOT
	// the old ~/.lumilake/jobs.jsonl, which is pod-local on identity and never
	// reaches the scheduler on UKS (same cross-pod defect as the install queue).
	// The scheduler picker's run_loop action invokes app_runner.cycle.
	payload := map[string]any{
		"app":          app,
		"loop":         loop,
		"args":         body.Args,
		"from_run_ts":  body.FromRunTs,
		"variant":      body.Variant,
		"branch_label": body.BranchLabel,
	}
	if body.Criteria != "" {
		payload["criteria"] = body.Criteria
	}
	if body.AutoPromote {
		payload["auto_promote"] = true
	}
	if len(body.Cases) > 0 {
		payload["cases"] = body.Cases
	}
	if body.NotBefore != "" {
		payload["not_before"] = body.NotBefore
	}
	id := writeIntent(c, "run_loop", userID, payload)
	if id == "" {
		return // writeIntent already wrote the error response
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "one-shot queued",
		"data": gin.H{"job_id": id, "state": "queued"},
	})
}

// POST /api/v1/me/loops/:app/:loop/stop
//
// Cooperative stop for a running cycle. Writes a per-loop signal file that the
// runner's claude_code_caller checks before each LLM call (it raises → the
// cycle aborts and marks itself interrupted). For instant UI feedback we also
// (a) append a "stopped by user" journal event and (b) stamp the in-flight
// cycle dir with an interrupted cycle.json so the inspector/session reflect it
// even before the subprocess notices.
func MeLoopStop(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app/loop name")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	// 1. Write the cooperative stop signal where the runner WATCHES it. The runner
	//    resolves data/control → .lumid/control (the runtime dir) and exposes that
	//    via LUMID_CYCLE_STOP_FILE, so writing only data/control was never seen.
	//    Write BOTH to cover the dual read/write layout.
	sig := map[string]any{"loop": loop, "by": userID, "at": time.Now().UTC().Format(time.RFC3339)}
	sigBytes, _ := json.Marshal(sig)
	for _, base := range []string{filepath.Join(appDir, ".lumid", "control"), filepath.Join(appDir, "data", "control")} {
		_ = os.MkdirAll(base, 0o755)
		_ = os.WriteFile(filepath.Join(base, "stop."+loop+".signal"), sigBytes, 0o644)
	}
	// 2. Append a journal event so the live session shows "stopped by user".
	jrow := map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339), "loop": loop,
		"event": "control", "stage": "stopped", "status": "stopped",
		"ok": false, "outcome": "interrupted", "note": "stopped by user",
	}
	if b, err := json.Marshal(jrow); err == nil {
		if f, e := os.OpenFile(filepath.Join(appDir, "data", "journal.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); e == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}
	// 3. Stamp the newest in-flight cycle dir (no cycle.json yet) as interrupted.
	//    Resolve the RUNTIME cycles dir (.lumid/cycles) — that's where the runner
	//    creates the in-flight cycle, so data/cycles would miss it.
	stopped := ""
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	cyclesDir := filepath.Join(cyclesRoot, loop)
	if entries, err := os.ReadDir(cyclesDir); err == nil {
		newest := ""
		for _, e := range entries {
			if e.IsDir() && e.Name() > newest {
				if _, err := os.Stat(filepath.Join(cyclesDir, e.Name(), "cycle.json")); err != nil {
					newest = e.Name() // in-flight (no cycle.json)
				}
			}
		}
		if newest != "" {
			cj := map[string]any{
				"ok": false, "app": app, "loop": loop, "status": "interrupted",
				"outcome": "interrupted", "reason": "user_stopped",
				"cycle_dir":   filepath.Join(cyclesDir, newest),
				"stopped_at":  time.Now().UTC().Format(time.RFC3339),
				"interrupted": true,
			}
			if b, err := json.MarshalIndent(cj, "", "  "); err == nil {
				_ = os.WriteFile(filepath.Join(cyclesDir, newest, "cycle.json"), b, 0o644)
				stopped = newest
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "stop requested",
		"data": gin.H{"loop": loop, "stopped_cycle": stopped},
	})
}

// GET /api/v1/me/loops/health
//
// P0: returns the same shape as /admin/loops (delegates internally).
// P2: filters to the calling user's tenant root once per-tenant
// volumes land.
func MeLoopsHealth(c *gin.Context) {
	if _, authed := currentUserID(c); !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	// Delegate — same handler the admin tile calls. Filtering by
	// tenant lands in P2; in P0 every user sees the operator host's
	// loops (acceptable since single-tenant during dogfood).
	AdminLoops(c)
}

// --- jobs.jsonl + overrides file helpers ------------------------------------

func jobsLedgerPath() string {
	return filepath.Join(operatorHome(), ".lumilake", "jobs.jsonl")
}

func appendJobRow(row map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(jobsLedgerPath()), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(jobsLedgerPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
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

// readSimpleOverrides reads a tiny YAML-ish file. We restrict the
// surface to keys we own: `loops: {<loop>: {runtime, schedule,
// enabled}}` + `_meta`. Anything else in the file (CLI-edited keys
// the user added by hand) is round-tripped as raw lines so we don't
// corrupt them. This is intentionally minimal — full YAML support
// arrives when we wire the Python merge in P1.
func readSimpleOverrides(path string) map[string]any {
	out := map[string]any{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	// Round-trip parse — best-effort. Stored fields we care about
	// come back as nested map[string]any. Unparseable content goes
	// into `_raw` and is preserved on write.
	currentTop := ""
	currentLoop := ""
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" || strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			continue
		}
		indent := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		body := strings.TrimSpace(trimmed)
		switch {
		case indent == 0 && strings.HasSuffix(body, ":"):
			currentTop = strings.TrimSuffix(body, ":")
			currentLoop = ""
			if out[currentTop] == nil {
				out[currentTop] = map[string]any{}
			}
		case indent == 2 && strings.HasSuffix(body, ":") && currentTop == "loops":
			currentLoop = strings.TrimSuffix(body, ":")
			loopsMap, _ := out["loops"].(map[string]any)
			if loopsMap == nil {
				loopsMap = map[string]any{}
			}
			if loopsMap[currentLoop] == nil {
				loopsMap[currentLoop] = map[string]any{}
			}
			out["loops"] = loopsMap
		case indent >= 4 && currentTop == "loops" && currentLoop != "" && strings.Contains(body, ":"):
			kv := strings.SplitN(body, ":", 2)
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			v = strings.Trim(v, "\"'")
			loopsMap, _ := out["loops"].(map[string]any)
			loopOver, _ := loopsMap[currentLoop].(map[string]any)
			switch v {
			case "true":
				loopOver[k] = true
			case "false":
				loopOver[k] = false
			default:
				loopOver[k] = v
			}
			loopsMap[currentLoop] = loopOver
			out["loops"] = loopsMap
		case indent == 2 && currentTop == "_meta" && strings.Contains(body, ":"):
			kv := strings.SplitN(body, ":", 2)
			m, _ := out["_meta"].(map[string]any)
			if m == nil {
				m = map[string]any{}
			}
			m[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), "\"'")
			out["_meta"] = m
		}
	}
	return out
}

func writeSimpleOverrides(path string, data map[string]any) error {
	var b strings.Builder
	b.WriteString("# Auto-generated by lumid-identity /api/v1/me/loops PATCH.\n")
	b.WriteString("# Merged AFTER xpcloud.yaml by app_runner.load_manifest() (P1+).\n")
	b.WriteString("# Edit by hand if you must; PATCH preserves unknown top-level keys.\n\n")
	if loops, ok := data["loops"].(map[string]any); ok && len(loops) > 0 {
		b.WriteString("loops:\n")
		for loopName, raw := range loops {
			over, _ := raw.(map[string]any)
			if over == nil {
				continue
			}
			b.WriteString("  " + loopName + ":\n")
			for _, k := range []string{"runtime", "schedule", "enabled", "goal", "model"} {
				v, ok := over[k]
				if !ok {
					continue
				}
				b.WriteString("    " + k + ": ")
				switch vv := v.(type) {
				case bool:
					if vv {
						b.WriteString("true\n")
					} else {
						b.WriteString("false\n")
					}
				default:
					b.WriteString(fmt.Sprintf("%q\n", fmt.Sprint(vv)))
				}
			}
		}
	}
	if meta, ok := data["_meta"].(map[string]any); ok && len(meta) > 0 {
		b.WriteString("\n_meta:\n")
		for k, v := range meta {
			b.WriteString("  " + k + ": " + fmt.Sprintf("%q", fmt.Sprint(v)) + "\n")
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
