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

	"lumid_identity/internal/common"
	"lumid_identity/models"
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
	// NOT named `ok`: that shadows the ok() response helper used at the end of
	// this function, and the compiler's complaint points at the CALL, 100 lines
	// away from the declaration that caused it.
	sub, authed := currentUserID(c)
	if !authed {
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

	// ── THE GATE: is this job yours? ──
	//
	// Without this the route is a service-token proxy over every job on every
	// site: the upstream credential is ours, not the caller's, so any
	// authenticated user could read the status and error of any job id they
	// happened to learn. Job ids are not guessable, but "hard to guess" is not
	// an authorization model, and a job's error text can carry data.
	//
	// The run store is the only place that knows whose job this is — identity
	// mounts no tenant volume and cannot read the experiments ledger — so the
	// cycle self-reports its job addresses and this is where they are spent.
	//
	// Scoped by user_sub FIRST, which is indexed, so the LIKE only ever scans
	// one caller's own run history. The LIKE is a pre-filter, not the decision:
	// it can match a job id embedded in some other field, so every candidate row
	// is then parsed and matched on the EXACT (job_id, site) pair.
	if !callerOwnsComputeJob(sub, site, jobID) {
		// 404, not 403. A 403 would confirm the job exists to someone who has
		// no business knowing that, turning this route into an oracle for job
		// ids — which is most of what an attacker without one would want.
		fail(c, http.StatusNotFound, 1404, "no such job for this user")
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

// callerOwnsComputeJob reports whether this user has a recorded run that ran
// this exact job on this exact site.
//
// Two-step on purpose. The LIKE is a cheap PRE-FILTER over one user's rows
// (user_sub is indexed, so it never scans another caller's history); the
// decision is the exact (job_id, site) match after parsing. A LIKE alone would
// authorize on a substring — a job id appearing anywhere in the column, under
// any site — which is not the question being asked.
//
// Both halves must match. cloud/home/office are three separate Lumilakes that
// each answer "not found" for the others' jobs, so owning req-X on `office`
// says nothing about req-X on `home`.
func callerOwnsComputeJob(sub, site, jobID string) bool {
	if sub == "" || site == "" || jobID == "" {
		return false
	}
	// A claim from the chat path is checked FIRST and is a single indexed
	// lookup, so the common case costs one row. The run-store scan below is the
	// cycle path, which has no claim because nothing in a scheduled cycle is
	// there to make one.
	var claim models.MeComputeJobClaim
	if err := common.DB.
		Where("site = ? AND job_id = ?", site, jobID).
		First(&claim).Error; err == nil {
		return claim.UserSub == sub
	}

	var rows []models.MeAppRun
	if err := common.DB.
		Select("compute_jobs").
		Where("user_sub = ? AND compute_jobs IS NOT NULL AND compute_jobs LIKE ?",
			sub, "%"+jobID+"%").
		Limit(64).
		Find(&rows).Error; err != nil {
		// Fail CLOSED. An unreadable store is not permission — treating a DB
		// error as "sure, go ahead" would turn an outage into an open proxy.
		return false
	}
	for _, r := range rows {
		if r.ComputeJobs != nil && computeJobsContain(*r.ComputeJobs, site, jobID) {
			return true
		}
	}
	return false
}

// computeJobsContain is the DECISION the LIKE pre-filter only approximates:
// does this stored address list contain this exact (job_id, site) pair?
//
// Separate and pure so it can be tested without a database, because the
// security property lives entirely here. The LIKE above matches a SUBSTRING
// anywhere in the column — "req-a" matches a row holding "req-abc", and it
// matches regardless of which site that row recorded. Authorizing on the
// pre-filter would therefore hand a caller jobs they never ran.
func computeJobsContain(raw, site, jobID string) bool {
	if raw == "" || site == "" || jobID == "" {
		return false
	}
	var refs []computeJobRef
	if json.Unmarshal([]byte(raw), &refs) != nil {
		return false
	}
	for _, ref := range refs {
		if ref.JobID == jobID && ref.Site == site {
			return true
		}
	}
	return false
}

// MeComputeJobClaim — POST /me/compute/jobs, body {"site","job_id"}.
//
// The submitter claiming a job it just started. This exists because the chat
// path writes no run row: run_lumilake_job is an MCP tool call in a sandbox
// with no cycle around it, so without a claim the status route would 404 every
// job a user started from chat — the exact path the workflow canvas serves.
//
// FIRST CLAIM WINS, and deliberately not "last". Re-claiming is a no-op for the
// owner and a 409 for anyone else; an upsert would let a second caller take
// ownership of a job simply by claiming it again.
func MeComputeJobClaimCreate(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var b struct {
		Site  string `json:"site"`
		JobID string `json:"job_id"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	// Validated identically to the read route. These are stored and later
	// compared against path parameters; a value that could not arrive as a path
	// parameter must not be storable as a claim either.
	if !computeSiteRe.MatchString(b.Site) || !computeJobRe.MatchString(b.JobID) {
		fail(c, http.StatusBadRequest, 1400, "invalid site or job_id")
		return
	}
	row := models.MeComputeJobClaim{Site: b.Site, JobID: b.JobID, UserSub: sub}
	// Let the UNIQUE INDEX decide, rather than checking then inserting: two
	// concurrent claims would both pass a check-then-write and the second would
	// overwrite the first.
	if err := common.DB.Create(&row).Error; err != nil {
		var existing models.MeComputeJobClaim
		if e2 := common.DB.Where("site = ? AND job_id = ?", b.Site, b.JobID).
			First(&existing).Error; e2 == nil {
			if existing.UserSub == sub {
				// Idempotent for the owner: a retried claim is not an error.
				ok(c, "", gin.H{"site": b.Site, "job_id": b.JobID, "claimed": true})
				return
			}
			fail(c, http.StatusConflict, 1409, "job already claimed")
			return
		}
		fail(c, http.StatusInternalServerError, 1500, "claim: "+err.Error())
		return
	}
	ok(c, "", gin.H{"site": b.Site, "job_id": b.JobID, "claimed": true})
}
