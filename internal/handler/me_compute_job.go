package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Job status for the workflow canvas.
//
// The canvas can draw a Lumilake graph and has a run overlay wired end to end,
// but nothing could ever FILL it: there is no browser-reachable status
// endpoint. api/me.ts has no lumilake route and neither did this router, so the
// panel showed a single frame captured when a chat tool call happened to
// finish, and never updated.
//
// The browser cannot call Lumilake directly. /ll/<site>/ requires a PAT, the
// SPA carries a session, and session-bearer explicitly rejects PATs — so the
// hop has to happen server-side, which is what this is.
//
// READ-ONLY AND NARROW ON PURPOSE. It proxies two GETs (the job record and its
// progress) for a job id the caller already holds. It cannot submit, cancel, or
// list — a surface that polls unattended on page load must not be able to spend
// a GPU or stop someone else's run.
//
// WHAT IT DELIBERATELY DOES NOT PROMISE: per-op state. Measured 2026-09-20 on a
// real completed job (req-FQ89FpUz6jnoyYyyjoPxxX): the `steps` keys are five
// fixed JOB-LIFECYCLE phases — queuing / query parsing / data probing /
// execution / outputs — not workflow op ids, and /jobs/{id}/workflows came back
// empty with batch_progress zeroed. So this returns job-level progress and the
// canvas must render that honestly rather than paint invented per-op rings.

const computeStatusTokenEnv = "LUMILAKE_STATUS_TOKEN" //nolint:gosec // env NAME

var computeSiteRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// A Lumilake job id, as the server issues them: req-<base58ish>.
var computeJobRe = regexp.MustCompile(`^req-[A-Za-z0-9]{6,64}$`)

// computeTerminal is the single definition of "done" for a compute job.
// Computed server-side so every caller agrees: a poller that decides for
// itself eventually decides differently, and a canvas that thinks a failed job
// is still running spins forever.
func computeTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

func computeBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("LUMILAKE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://lum.id/ll"
}

// MeComputeJob proxies GET /me/compute/jobs/:site/:job_id.
func MeComputeJob(c *gin.Context) {
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	site, jobID := c.Param("site"), c.Param("job_id")
	// Validated, not just forwarded: both land in a URL this service builds,
	// and a job id is caller-supplied.
	if !computeSiteRe.MatchString(site) {
		fail(c, http.StatusBadRequest, 1400, "invalid site")
		return
	}
	if !computeJobRe.MatchString(jobID) {
		fail(c, http.StatusBadRequest, 1400, "invalid job id")
		return
	}

	token := strings.TrimSpace(os.Getenv(computeStatusTokenEnv))
	if token == "" {
		// A NAMED 503, not a silent empty result. This ships before the
		// credential exists, and a surface that renders "no progress" is
		// indistinguishable from a job that has not started — so the one thing
		// this must never do is look like a working endpoint with nothing to
		// say.
		fail(c, http.StatusServiceUnavailable, 1503,
			"compute job status is not configured: set "+computeStatusTokenEnv+
				" (a PAT carrying lumilake:jobs:read) in the identity secret")
		return
	}

	base := fmt.Sprintf("%s/%s/api/v1/jobs/%s", computeBaseURL(), site, jobID)
	client := &http.Client{Timeout: 20 * time.Second}
	get := func(url string) (map[string]any, int) {
		req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, url, nil)
		if err != nil {
			return nil, 0
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return nil, resp.StatusCode
		}
		if d, isMap := m["data"].(map[string]any); isMap {
			return d, resp.StatusCode
		}
		return m, resp.StatusCode
	}

	rec, code := get(base)
	if code == 0 {
		fail(c, http.StatusBadGateway, 1502, "compute service unreachable")
		return
	}
	if code >= 400 {
		// Pass the upstream's own code through. A 404 for an unknown job must
		// not read as a server fault, and a 403 must say so rather than look
		// like an empty job.
		fail(c, code, 1400+code%100, fmt.Sprintf("compute service returned %d", code))
		return
	}
	// Progress is best-effort: a job can be perfectly readable while its
	// progress endpoint is not, and losing the status over that would be worse
	// than returning it without phases.
	prog, _ := get(base + "/progress")

	status, _ := rec["status"].(string)
	out := gin.H{
		"job_id": jobID,
		"site":   site,
		"status": status,
		// Terminal is computed HERE so every caller agrees on what "done"
		// means — a poller that decides for itself eventually decides
		// differently.
		"terminal": computeTerminal(status),
		"error":    rec["error"],
	}
	if prog != nil {
		if p, isMap := prog["progress"].(map[string]any); isMap {
			out["progress"] = p
		} else {
			out["progress"] = prog
		}
	}
	ok(c, "", out)
}
