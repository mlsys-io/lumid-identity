package handler

// Branching-runtime + recommender ops for the agent app page (items 18-20).
//
// These four routes are thin Go shims over the `lumid-trajectory` Python CLI
// (LumidOS/LumidOS/bin/lumid-trajectory). The CLI is the source of truth: it
// reads/writes ONLY the app's local .lumid state (resolving the same dual-read
// paths the runner uses) and prints a single JSON object to stdout. The Go side
// stays thin — bind HOME to the caller's tenant root (exactly as MeLoopRunNow
// does for run-now), shell the subcommand with args passed as exec args (never
// shell-interpolated), parse the one JSON object, and forward it in the
// {ret_code,message,data} envelope.
//
//   GET  /me/apps/:app/next-actions              → next-actions --app
//   GET  /me/apps/:app/loops/:loop/lineage       → lineage --app --loop
//   POST /me/apps/:app/runs/:ts/promote          → promote --app --ts [--loop]
//   POST /me/apps/:app/runs/:ts/discard          → discard --app --ts [--loop]
//
// The CLI resolves the app under $HOME/.xp/apps/<app>; binding HOME to the
// caller's tenant root scopes it to that tenant's install (same isolation the
// other tenant-HOME handlers rely on).

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// trajectoryOpTimeout bounds the CLI subprocess. The CLI only reads/writes
// small local JSON state (no network, no LLM), so this is generous.
const trajectoryOpTimeout = 25 * time.Second

// trajectoryBinPath returns the absolute path to the lumid-trajectory CLI as
// exposed inside the container (codebaseRoot is /var/lib/lumid-codebase = /proj,
// overridable via LUMID_CODEBASE_ROOT). An explicit LUMID_TRAJECTORY_BIN wins.
func trajectoryBinPath() string {
	if v := os.Getenv("LUMID_TRAJECTORY_BIN"); v != "" {
		return v
	}
	return filepath.Join(codebaseRoot(), "LumidOS", "LumidOS", "bin", "lumid-trajectory")
}

// runTrajectoryCLI shells `lumid-trajectory <args...>` with HOME bound to the
// caller's tenant root (so the CLI's Path.home()/.xp/apps lookup resolves to the
// tenant install), bounded by trajectoryOpTimeout. It parses the single JSON
// object the CLI prints to stdout and returns it. `args` are passed as exec
// args — never shell-interpolated — so :app/:loop/:ts can't inject.
func runTrajectoryCLI(userSub string, args ...string) (map[string]any, error, int) {
	bin := trajectoryBinPath()
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		return nil, errTrajectoryUnavailable, http.StatusServiceUnavailable
	}

	ctx, cancel := context.WithTimeout(context.Background(), trajectoryOpTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	// Bind HOME to the tenant root — identical scoping to MeLoopRunNow's
	// tenant-HOME convention. Inherit the rest of the env (PATH so the
	// `#!/usr/bin/env python3` shebang resolves).
	cmd.Env = append(os.Environ(), "HOME="+tenantRoot(userSub))

	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, errTrajectoryTimeout, http.StatusGatewayTimeout
	}
	if err != nil {
		// Surface stderr (capped) so a CLI failure (e.g. missing python dep,
		// unknown app) is diagnosable rather than a bare 500.
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if len(stderr) > 400 {
			stderr = stderr[:400]
		}
		return nil, &trajectoryErr{msg: "trajectory CLI failed: " + err.Error() + truncSep(stderr)}, http.StatusBadGateway
	}

	// The CLI prints exactly one JSON object. Trim any trailing newline.
	var obj map[string]any
	if jerr := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &obj); jerr != nil {
		return nil, &trajectoryErr{msg: "trajectory CLI emitted non-JSON output"}, http.StatusBadGateway
	}
	return obj, nil, http.StatusOK
}

func truncSep(s string) string {
	if s == "" {
		return ""
	}
	return " — " + s
}

type trajectoryErr struct{ msg string }

func (e *trajectoryErr) Error() string { return e.msg }

var (
	errTrajectoryUnavailable = &trajectoryErr{msg: "trajectory CLI not available on this host"}
	errTrajectoryTimeout     = &trajectoryErr{msg: "trajectory CLI timed out"}
)

// MeNextActions — GET /me/apps/:app/next-actions
// Recommender: what the user should do next on this app (run more samples,
// promote a champion, fix a regression, …). Forwards {actions:[...]}.
func MeNextActions(c *gin.Context) {
	userSub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	obj, err, status := runTrajectoryCLI(userSub, "next-actions", "--app", app)
	if err != nil {
		fail(c, status, 1502, err.Error())
		return
	}
	ok(c, "ok", obj)
}

// MeLoopLineage — GET /me/apps/:app/loops/:loop/lineage
// Branch tree for one loop: nodes (runs) + roots, with parent_run_id edges.
// Forwards {nodes:[...], roots:[...], ...}.
func MeLoopLineage(c *gin.Context) {
	userSub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if !slugRe.MatchString(loop) || strings.ContainsAny(loop, "/\\") || strings.Contains(loop, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid loop name")
		return
	}
	obj, err, status := runTrajectoryCLI(userSub, "lineage", "--app", app, "--loop", loop)
	if err != nil {
		fail(c, status, 1502, err.Error())
		return
	}
	ok(c, "ok", obj)
}

// MeRunPromote — POST /me/apps/:app/runs/:ts/promote
// Marks a run as the chosen branch (writes promoted.json; advisory only —
// never rewrites cycle.json history). Optional ?loop= narrows the search.
func MeRunPromote(c *gin.Context) { meRunMark(c, "promote") }

// MeRunDiscard — POST /me/apps/:app/runs/:ts/discard
// Greys out a run (writes discarded.json; advisory only).
func MeRunDiscard(c *gin.Context) { meRunMark(c, "discard") }

// meRunMark backs promote + discard — both take :app/:ts and an optional ?loop=.
func meRunMark(c *gin.Context, verb string) {
	userSub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	ts := c.Param("ts")
	if !slugRe.MatchString(app) || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	// ts is a cycle dir name (e.g. 20060102T150405Z). Reuse slugRe + the
	// traversal guard so it can't escape the cycles dir or inject into argv.
	if !slugRe.MatchString(ts) || strings.ContainsAny(ts, "/\\") || strings.Contains(ts, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid run ts")
		return
	}
	args := []string{verb, "--app", app, "--ts", ts}
	if loop := c.Query("loop"); loop != "" {
		if !slugRe.MatchString(loop) || strings.ContainsAny(loop, "/\\") || strings.Contains(loop, "..") {
			fail(c, http.StatusBadRequest, 1400, "invalid loop name")
			return
		}
		args = append(args, "--loop", loop)
	}
	obj, err, status := runTrajectoryCLI(userSub, args...)
	if err != nil {
		fail(c, status, 1502, err.Error())
		return
	}
	ok(c, verb+"d", obj)
}

// meLoopEnqueueBody — fan-out a batch of variants into the trajectory queue.
// Each variant becomes one queued run (count 1). The shared knobs
// (from_run_ts / branch_label / criteria / priority) apply to every variant.
type meLoopEnqueueBody struct {
	FromRunTs   string           `json:"from_run_ts,omitempty"`
	BranchLabel string           `json:"branch_label,omitempty"`
	Criteria    string           `json:"criteria,omitempty"`
	Priority    int              `json:"priority,omitempty"`
	Variants    []map[string]any `json:"variants"`
}

// MeLoopEnqueue — POST /me/apps/:app/loops/:loop/enqueue
//
// Fan-out (Phase C): for EACH variant in the body, shell `lumid-trajectory
// enqueue` once (count 1) so the trajectory engine queues a run with that
// variant baked in. Best-effort per variant — we attempt them all and report
// how many were successfully queued. HOME is bound to the caller's tenant root
// (via runTrajectoryCLI), and every arg is passed as an exec arg (never
// shell-interpolated), so :app/:loop and the variant JSON can't inject.
func MeLoopEnqueue(c *gin.Context) {
	userSub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if !slugRe.MatchString(loop) || strings.ContainsAny(loop, "/\\") || strings.Contains(loop, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid loop name")
		return
	}
	var body meLoopEnqueueBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if len(body.Variants) == 0 {
		fail(c, http.StatusBadRequest, 1400, "variants must be a non-empty array")
		return
	}

	priority := body.Priority
	queued := 0
	for _, variant := range body.Variants {
		vjson, err := json.Marshal(variant)
		if err != nil {
			continue // skip un-marshalable variant; best-effort
		}
		args := []string{
			"enqueue",
			"--app", app,
			"--loop", loop,
			"--count", "1",
			"--priority", strconv.Itoa(priority),
			"--variant-json", string(vjson),
		}
		if body.FromRunTs != "" {
			args = append(args, "--from-run-ts", body.FromRunTs)
		}
		if body.BranchLabel != "" {
			args = append(args, "--branch-label", body.BranchLabel)
		}
		if body.Criteria != "" {
			args = append(args, "--criteria", body.Criteria)
		}
		args = append(args, "--by", userSub)
		if _, err, _ := runTrajectoryCLI(userSub, args...); err == nil {
			queued++
		}
	}
	ok(c, "queued", gin.H{"queued": queued})
}
