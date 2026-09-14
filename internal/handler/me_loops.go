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
	"net/http"
	"os"
	"strings"

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

	// ── This goes through an INTENT, not the disk ──
	//
	// It used to stat <tenant>/.xp/apps/<app>, then the operator-shared path,
	// and 404 when neither existed. Identity mounts exactly one volume — the
	// signing keys — so NEITHER EVER EXISTED, and every PATCH here 404'd for
	// every user: pause, resume, schedule and the workflow panel's goal save,
	// all of them, with a red toast naming a path nobody could create. The
	// materialised bundle cache would not have rescued it either; it lives
	// under a different root and holds the PUBLISHED tree, not the tenant's
	// writable one.
	//
	// The scheduler is the process that can see that disk, so the write belongs
	// there — the same route install and patch_experiment already take. The
	// hand-rolled YAML emitter moved with it (_write_user_overrides in
	// me_intent_picker.py), which also ends the two-writers-one-format problem.
	payload := map[string]any{"app": app, "loop": loop}
	requested := gin.H{}
	if body.Runtime != nil {
		payload["runtime"] = *body.Runtime
		requested["runtime"] = *body.Runtime
	}
	if body.Schedule != nil {
		payload["schedule"] = *body.Schedule
		requested["schedule"] = *body.Schedule
	}
	if body.Enabled != nil {
		payload["enabled"] = *body.Enabled
		requested["enabled"] = *body.Enabled
	}
	if body.Goal != nil {
		// Single-line and bounded, as the emitter on the far side expects.
		// Empty clears the override (reverts to the declared goal).
		g := strings.TrimSpace(strings.ReplaceAll(*body.Goal, "\n", " "))
		if len(g) > 280 {
			g = g[:280]
		}
		payload["goal"] = g
		requested["goal"] = g
	}
	if body.Model != nil {
		m := strings.TrimSpace(*body.Model)
		payload["model"] = m
		requested["model"] = m
	}
	if len(requested) == 0 {
		fail(c, http.StatusBadRequest, 1400, "nothing to change")
		return
	}

	id := writeIntent(c, "patch_loop", userID, payload)
	if id == "" {
		return // writeIntent already wrote the error response
	}
	// 202 and no claim that it landed — identity queues, the scheduler applies,
	// exactly as for install. `overrides` echoes what was REQUESTED so a client
	// can still render optimistically; poll the intent for the result.
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "queued",
		"data": gin.H{
			"app":       app,
			"loop":      loop,
			"intent_id": id,
			"status":    "pending",
			"overrides": requested,
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
	//   (NotBefore was removed 2026-09-04: it was accepted here and forwarded
	//   into the intent payload, but me_intent_picker never read it — only the
	//   legacy drain_oneshots path did — so a "defer until" run started
	//   immediately. No UI ever set it. Reinstate it WITH a picker-side gate,
	//   not before.)
	Criteria    string   `json:"criteria,omitempty"`
	AutoPromote bool     `json:"auto_promote,omitempty"`
	Cases       []string `json:"cases,omitempty"`
}

// POST /api/v1/me/loops/:app/:loop/run
//
// Queues a `run_loop` intent in me_app_intents, which the scheduler's picker
// drains. (This comment described the old ~/.lumilake/jobs.jsonl ledger, which
// the body stopped using long ago and which was deleted 2026-09-04 — it was
// pod-local on identity and nothing ever read it.)
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
	// A slug that resolves NOWHERE is rejected here, cheaply, without writing a
	// queue row: resolveAppDir returns "" only when the name is not a tenant
	// app, not operator-shared, and not published (so its materialise fallback
	// fails too). A typo is a real signal, and it is the ONLY signal this check
	// carries.
	//
	// It used to carry more weight than that, wrongly. Because resolveAppDir
	// MATERIALISES the published bundle onto identity's own pod when it finds
	// nothing local (me_datasets.go), it returns a directory for any published
	// app — so the check passed for everyone, including the 28 tenants whose
	// scheduler-side install was still under the pre-rename slug. Every one of
	// them got "one-shot queued" for a cycle that died a second later with
	// `app 'quant-research' not installed for this user`. A check that cannot
	// fail is not a check.
	//
	// So: this means "the slug exists somewhere", nothing more. Whether the
	// cycle can actually RUN is answered by the settle-wait below, which asks
	// the one process that knows.
	if resolveAppDir(userID, app) == "" {
		fail(c, http.StatusNotFound, 1404, "app not found: "+app)
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
	id := writeIntent(c, "run_loop", userID, payload)
	if id == "" {
		return // writeIntent already wrote the error response
	}

	// Whether it can actually RUN is answered by POLLING `job_id`, not by
	// blocking here.
	//
	// Identity cannot decide that on its own: it mounts no tenant volume (only
	// signing-keys), so the tree it would stat is not the one the cycle Job
	// reads — that lives on the scheduler's `xpio-state` PVC in another
	// cluster. The scheduler knows, and reports back to
	// /internal/me-intents/:id/result, into this same table. That is what
	// makes `job_id` the useful half of this response: GET /me/intents/:id
	// carries the real outcome and the scheduler's own error text.
	//
	// v0.5.273 tried to wait here for an early failure. MEASURED on the live
	// queue that does not work: a FAILED dispatch reports at ~6-7s and a
	// SUCCESSFUL one at ~8s, so no bound separates them. A 6s wait caught most
	// failures and turned every healthy call from 0.4s into 6.2s — a 15x
	// regression on every click, to make a subset of failures louder. Removed.
	// The reporting belongs in the client, which can poll `job_id` without
	// holding a request open.
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
	// ── An INTENT, for the same reason the patch is ──
	//
	// This handler resolved its app dir through resolveAppDir, which on a pod
	// returns the MATERIALISED BUNDLE CACHE — a copy of the published tree. So
	// it never 404'd, and all three of its effects (the stop signal, the journal
	// line, the interrupted cycle.json) were written into a pod-local directory
	// the runner never reads, and it returned 200 "stop requested". A control
	// that reports success without acting is worse than one that errors.
	//
	// The scheduler owns the volume the runner watches, so the stop goes there.
	// It costs one drain tick of latency; a late stop beats one that never
	// arrives.
	id := writeIntent(c, "stop_loop", userID, map[string]any{"app": app, "loop": loop})
	if id == "" {
		return // writeIntent already wrote the error response
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "stop queued",
		"data": gin.H{"app": app, "loop": loop, "intent_id": id, "status": "pending"},
	})
}

// GET /api/v1/me/loops/health
//
// P0: returns the same shape as /admin/loops (delegates internally).
// P2: filters to the calling user's tenant root once per-tenant
// volumes land.
func MeLoopsHealth(c *gin.Context) {
	uid, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	// TENANT SCOPING. This used to delegate to AdminLoops wholesale, on the
	// stated premise that "the operator host is single-tenant during
	// dogfood". That premise expired when real users were onboarded: every
	// authenticated role-`user` caller was served the FLEET's loop inventory
	// — app names, schedules, run health and descriptions for every tenant
	// plus the operator's own apps.
	//
	// Admins keep the fleet-wide view (the /admin/loops tile depends on it);
	// everyone else is scoped to loops carrying their own tenant_sub. The
	// scope is applied inside AdminLoops so BOTH of its response paths (the
	// scheduler's Redis doc and the local filesystem walk) are covered — a
	// filter on only one of them would leak through the other.
	role := ""
	if tok := bearerToken(c); tok != "" {
		if _, r, resolved := resolveRole(tok); resolved {
			role = r
		}
	}
	if !isAdminRole(role) {
		c.Set(loopsTenantScopeKey, uid)
	}
	AdminLoops(c)
}

// --- jobs.jsonl + overrides file helpers ------------------------------------

// The one-shot jobs.jsonl ledger was REMOVED here on 2026-09-04.
//
// jobsLedgerPath() resolved to identity's own ~/.lumilake/jobs.jsonl, but the
// drainer (XpioSchedulerDaemon.drain_oneshots) reads the SCHEDULER's copy on
// its xpio-state PVC in another cluster. Every row written here was invisible:
// the live pod held 3, all state=queued, including two users' quant-research
// backtests that the chatbox had reported as queued a day earlier.
//
// Both callers now write a `run_loop` intent instead (MeLoopRunNow always did;
// agentEnqueueOneshot was migrated). Nothing writes this file — the helpers are
// gone rather than left available to be wired up again.
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

// writeSimpleOverrides is GONE, deliberately. The format now has exactly one
// writer — _write_user_overrides in sdk/scheduling/me_intent_picker.py — because
// identity cannot reach the file it describes: the pod mounts one volume, the
// signing keys, so every write here landed on a pod-local path nothing reads.
// Two writers for one format is also how the emitter drifted from its reader (an
// emptied loop override emitted `name:` with no children, which YAML reads back
// as None). readSimpleOverrides stays: reading a path that may not exist is
// harmless, and me_workflows still asks.
