package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Research Fleet jobs — one API for work run on the fleet.
//
//	POST /me/fleet/jobs              run     a FlowMesh compute graph or a Lumilake
//	                                         workflow (dry_run: validate only)
//	GET  /me/fleet/jobs              get     the caller's jobs, newest first
//	GET  /me/fleet/jobs/:id?view=    get     status | result | logs | trace
//	POST /me/fleet/jobs/:id/cancel   cancel
//
// It replaces a spread of per-backend verbs (submit_workflow, run_workflow,
// run_lumilake_job, workflow_status, lumilake_job_status/result/trace,
// workflow_logs, cancel_workflow, cancel_lumilake_job, optimize_workflow) with
// the grammar in LumidOS docs/architecture/VERBS.md: status, result, logs and
// trace are VIEWS of get, and validation is run(dry_run).
//
// ONE ID FORM, <site>:<kind>:<native>: "home:fm:wfl-3f2a", "cloud:ll:req-9Xc…".
// A FlowMesh workflow id or a Lumilake job id means nothing without its site —
// cloud/home/office each answer "not found" for the others' jobs — so the site
// travels inside the id instead of beside it, where it kept getting dropped.
//
// ONE STATUS VOCABULARY, queued|running|succeeded|failed|canceled, mapped here
// from FlowMesh's PENDING/DISPATCHED/DONE/… and Lumilake's pending/running/
// completed/…, with the upstream word kept as native_status. An unrecognised
// upstream status maps to running, never to a terminal state: a poller that is
// told "done" stops, and stopping on a word nobody mapped loses the result.
//
// WHO THE WORK RUNS AS. Writes go upstream as the CALLER — a short-lived bridge
// JWT for FlowMesh, the per-user lumilake:jobs:write PAT (compute_token.go) for
// Lumilake — so quotas, ownership and audit upstream name the user, not this
// service. Lumilake reads use the read-only service token the canvas status
// route already uses, gated by the ownership check below.

const (
	fleetKindFM = "fm"
	fleetKindLL = "ll"

	fleetFormatFlowMesh = "flowmesh"
	fleetFormatLumilake = "lumilake"

	fleetMaxWorkflowBytes = 1 << 20
	fleetListMax          = 200
	fleetResultTaskMax    = 32

	// The compute-PAT cache is keyed by app; fleet jobs are not an app's.
	fleetPATCacheApp = "__research_fleet"
)

// What a FlowMesh bridge JWT for fleet work may do: submit/validate/cancel a
// workflow and read its tasks, results and logs. Nothing on nodes or workers.
var fleetFlowMeshScopes = []string{
	"flowmesh:workflows:write",
	"flowmesh:workflows:read",
	"flowmesh:tasks:read",
	"flowmesh:results:read",
}

var (
	fleetLabelRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$`)
	fleetNativeFM = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// fleetJobID is <site>:<kind>:<native>.
type fleetJobID struct{ Site, Kind, Native string }

func (id fleetJobID) String() string { return id.Site + ":" + id.Kind + ":" + id.Native }

// parseFleetJobID validates every part: all three land in URLs this service
// builds, and the whole id is caller-supplied.
func parseFleetJobID(s string) (fleetJobID, bool) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || !computeSiteRe.MatchString(parts[0]) {
		return fleetJobID{}, false
	}
	id := fleetJobID{Site: parts[0], Kind: parts[1], Native: parts[2]}
	switch id.Kind {
	case fleetKindFM:
		return id, fleetNativeFM.MatchString(id.Native)
	case fleetKindLL:
		return id, computeJobRe.MatchString(id.Native)
	}
	return fleetJobID{}, false
}

// fleetStatuses maps every upstream status word to the unified vocabulary.
var fleetStatuses = map[string]string{
	// FlowMesh workflow / task
	"PENDING": "queued", "DISPATCHED": "running", "RUNNING": "running",
	"CANCELLING": "running", "DONE": "succeeded", "FAILED": "failed",
	"CANCELLED": "canceled",
	// Lumilake job
	"pending": "queued", "queued": "queued", "optimizing": "running",
	"running": "running", "completed": "succeeded", "failed": "failed",
	"error": "failed", "cancelled": "canceled", "canceled": "canceled",
}

// fleetStatus returns (unified status, terminal) for an upstream status word.
func fleetStatus(native string) (string, bool) {
	s, known := fleetStatuses[strings.TrimSpace(native)]
	if !known {
		return "running", false
	}
	return s, s == "succeeded" || s == "failed" || s == "canceled"
}

func fleetBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("FLEET_BASE_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "https://lum.id"
}

// fleetDefaultSite is where a job without an explicit site runs: the site every
// signed-in user can read on Research Fleet.
func fleetDefaultSite() string {
	if v := strings.TrimSpace(os.Getenv("FLEET_DEFAULT_SITE")); v != "" {
		return v
	}
	return "home"
}

// fleetSiteBase is the federator prefix for one site: /fm/<site> or /ll/<site>.
func fleetSiteBase(kind, site string) string {
	return fmt.Sprintf("%s/%s/%s", fleetBaseURL(), kind, site)
}

// detectFleetFormat tells a Lumilake workflow (top-level `ops:`) from a
// FlowMesh compute graph (apiVersion/kind/spec). "" when it is neither.
func detectFleetFormat(workflow string) string {
	var top map[string]any
	if yaml.Unmarshal([]byte(workflow), &top) != nil || top == nil {
		return ""
	}
	if _, has := top["ops"]; has {
		return fleetFormatLumilake
	}
	if _, has := top["spec"]; has {
		return fleetFormatFlowMesh
	}
	if _, has := top["apiVersion"]; has {
		return fleetFormatFlowMesh
	}
	return ""
}

// declaredWorkflowInputs is a Lumilake workflow's own top-level `inputs:` map,
// or {} when it declares none. Never nil: a nil map would reach the server as
// `inputs: null`.
func declaredWorkflowInputs(workflow string) map[string]any {
	var top struct {
		Inputs map[string]any `yaml:"inputs"`
	}
	if yaml.Unmarshal([]byte(workflow), &top) != nil || top.Inputs == nil {
		return map[string]any{}
	}
	return top.Inputs
}

func fleetKindOf(format string) string {
	if format == fleetFormatLumilake {
		return fleetKindLL
	}
	return fleetKindFM
}

// ── upstream calls ──────────────────────────────────────────────────────────

var errFleetCredential = errors.New("no credential for this compute service")

// fleetWriteBearer is the credential a WRITE goes upstream with: the caller's.
func fleetWriteBearer(userID, kind string) (string, error) {
	if kind == fleetKindLL {
		if tok := computePATCached(userID, fleetPATCacheApp); tok != "" {
			return tok, nil
		}
		return "", errFleetCredential
	}
	email, role := userEmailRole(userID)
	tok, _, _, err := common.IssueBridgeJWT(userID, email, role, "flowmesh", fleetFlowMeshScopes, 15*time.Minute)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFleetCredential, err)
	}
	return tok, nil
}

// fleetReadBearer: reads go as the caller. Lumilake authorizes a job read per
// job, and grants it to the principal that submitted it; the read-only service
// token is refused on a user's job (403 "read on job/<id> denied"). It remains
// the fallback when no caller credential can be minted.
func fleetReadBearer(userID, kind string) (string, error) {
	tok, err := fleetWriteBearer(userID, kind)
	if err == nil || kind != fleetKindLL {
		return tok, err
	}
	if svc := strings.TrimSpace(os.Getenv(computeStatusTokenEnv)); svc != "" {
		return svc, nil
	}
	return "", fmt.Errorf("%w: set %s", errFleetCredential, computeStatusTokenEnv)
}

type fleetCall struct {
	method, url, bearer, contentType string
	headers                          map[string]string
	body                             []byte
}

// fleetDo performs one upstream call and returns the body and status. Status 0
// means the service was unreachable.
func fleetDo(ctx context.Context, call fleetCall) ([]byte, int) {
	var rdr io.Reader
	if call.body != nil {
		rdr = bytes.NewReader(call.body)
	}
	req, err := http.NewRequestWithContext(ctx, call.method, call.url, rdr)
	if err != nil {
		return nil, 0
	}
	req.Header.Set("Authorization", "Bearer "+call.bearer)
	if call.contentType != "" {
		req.Header.Set("Content-Type", call.contentType)
	}
	for k, v := range call.headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode
}

// fleetJSON decodes a response, unwrapping Lumilake's {ok, data} envelope.
func fleetJSON(b []byte) map[string]any {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	if d, isMap := m["data"].(map[string]any); isMap {
		return d
	}
	return m
}

// failUpstream turns a failed upstream call into the caller's error. The
// upstream's own 4xx is passed through: a 404 for an unknown job must not read
// as a server fault, and a 422 on a bad workflow is the caller's to fix.
func failUpstream(c *gin.Context, code int, b []byte) {
	if code == 0 {
		fail(c, http.StatusBadGateway, 1502, "compute service unreachable")
		return
	}
	msg := fmt.Sprintf("compute service returned %d", code)
	if m := fleetJSON(b); m != nil {
		for _, k := range []string{"detail", "error", "message", "msg"} {
			if v, isStr := m[k].(string); isStr && v != "" {
				msg += ": " + v
				break
			}
		}
	}
	status := code
	if code >= 500 {
		status = http.StatusBadGateway
	}
	fail(c, status, 1400+code%100, msg)
}

// ── run ─────────────────────────────────────────────────────────────────────

type fleetRunBody struct {
	Workflow       string         `json:"workflow"`
	Format         string         `json:"format"`
	Inputs         map[string]any `json:"inputs"`
	Site           string         `json:"site"`
	DryRun         bool           `json:"dry_run"`
	Hardware       map[string]any `json:"hardware"`
	OutputLocation map[string]any `json:"output_location"`
	Name           string         `json:"name"`
	Labels         struct {
		Study      string `json:"study"`
		Experiment string `json:"experiment"`
	} `json:"labels"`
}

// MeFleetJobRun — POST /me/fleet/jobs.
func MeFleetJobRun(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var b fleetRunBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if strings.TrimSpace(b.Workflow) == "" || len(b.Workflow) > fleetMaxWorkflowBytes {
		fail(c, http.StatusBadRequest, 1400, "workflow is required (at most 1 MiB of YAML)")
		return
	}
	site := strings.TrimSpace(b.Site)
	if site == "" {
		site = fleetDefaultSite()
	}
	if !computeSiteRe.MatchString(site) {
		fail(c, http.StatusBadRequest, 1400, "invalid site")
		return
	}
	for _, l := range []string{b.Labels.Study, b.Labels.Experiment} {
		if l != "" && !fleetLabelRe.MatchString(l) {
			fail(c, http.StatusBadRequest, 1400, "invalid label "+strconv.Quote(l))
			return
		}
	}
	format := strings.ToLower(strings.TrimSpace(b.Format))
	if format == "" || format == "auto" {
		format = detectFleetFormat(b.Workflow)
		if format == "" {
			fail(c, http.StatusBadRequest, 1400,
				"cannot tell the workflow format: a Lumilake workflow has top-level `ops:`, "+
					"a FlowMesh compute graph has `apiVersion`/`spec`; or pass format explicitly")
			return
		}
	}
	if format != fleetFormatFlowMesh && format != fleetFormatLumilake {
		fail(c, http.StatusBadRequest, 1400, "format must be flowmesh, lumilake or auto")
		return
	}
	kind := fleetKindOf(format)
	bearer, err := fleetWriteBearer(sub, kind)
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, err.Error())
		return
	}

	call := fleetCall{method: http.MethodPost, bearer: bearer}
	base := fleetSiteBase(kind, site)
	if kind == fleetKindFM {
		call.contentType = "text/plain"
		call.body = []byte(b.Workflow)
		call.url = base + "/api/v1/workflows"
		if b.DryRun {
			call.url += "/validate"
		}
	} else {
		// Lumilake requires non-empty inputs keyed by the workflow's declared
		// inputs (422 "inputs is required" otherwise), and a workflow carries
		// defaults in its own top-level `inputs:` block — which is what the
		// SDK's optimize_workflow falls back to as well. A caller's inputs win.
		inputs := b.Inputs
		if len(inputs) == 0 {
			inputs = declaredWorkflowInputs(b.Workflow)
		}
		item := map[string]any{"workflow": b.Workflow, "inputs": inputs}
		if !b.DryRun {
			loc := b.OutputLocation
			if loc == nil {
				loc = map[string]any{"type": "s3", "prefix": fleetOutputPrefix(sub)}
			}
			item["output_location"] = loc
		}
		req := map[string]any{"data": []any{item}}
		if b.Hardware != nil {
			// REQUEST level, never inside data[]: the server accepts it there
			// and silently ignores it (see optimize_workflow in the SDK).
			req["hardware"] = b.Hardware
		}
		call.body, _ = json.Marshal(req)
		call.contentType = "application/json"
		call.headers = map[string]string{"Workflow-Format": "yaml"}
		call.url = base + "/api/v1/jobs"
		if b.DryRun {
			call.url += "/preview"
		}
	}
	body, code := fleetDo(c.Request.Context(), call)
	if code < 200 || code >= 300 {
		failUpstream(c, code, body)
		return
	}
	resp := fleetJSON(body)
	if b.DryRun {
		ok(c, "", gin.H{"dry_run": true, "valid": true, "format": format, "site": site, "detail": resp})
		return
	}

	native := ""
	for _, k := range []string{"workflow_id", "job_id", "id"} {
		if v, isStr := resp[k].(string); isStr && v != "" {
			native = v
			break
		}
	}
	id := fleetJobID{Site: site, Kind: kind, Native: native}
	if _, valid := parseFleetJobID(id.String()); !valid {
		fail(c, http.StatusBadGateway, 1502, "compute service accepted the job but returned no usable id")
		return
	}
	nativeStatus, _ := resp["status"].(string)
	status, terminal := fleetStatus(nativeStatus)
	if nativeStatus == "" {
		status, terminal = "queued", false
	}
	row := models.MeFleetJob{
		Site: site, Kind: kind, NativeID: native, UserSub: sub, Format: format,
		Name: fleetClip(b.Name, 128), Study: b.Labels.Study, Experiment: b.Labels.Experiment,
		Status: status, Terminal: terminal,
	}
	if err := common.DB.Create(&row).Error; err != nil {
		// The job is running and cannot be un-run; say so rather than 500 and
		// leave the caller retrying a submit that already happened.
		fail(c, http.StatusInternalServerError, 1500,
			"job "+id.String()+" started but could not be recorded: "+err.Error())
		return
	}
	// 202, in the same envelope ok() writes: a client parsing ret_code must not
	// have to special-case the one route that accepts rather than completes.
	c.JSON(http.StatusAccepted, gin.H{"ret_code": 0, "message": "", "data": fleetJobView(row)})
}

// fleetClip bounds a string to a column size, with no ellipsis appended.
// fleetOutputPrefix is a Lumilake job's default output location for one user.
// The deployed server accepts only s3/db outputs, and authorizes an S3 prefix by
// exact id, claimed by the first principal to write it: one shared prefix would
// belong to whoever ran the first job, and every other user would get
// "403 write on object-prefix/... denied".
func fleetOutputPrefix(sub string) string { return "fleet-jobs/" + sub + "/" }

func fleetClip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func fleetJobView(r models.MeFleetJob) gin.H {
	id := fleetJobID{Site: r.Site, Kind: r.Kind, Native: r.NativeID}
	out := gin.H{
		"id": id.String(), "site": r.Site, "kind": r.Kind, "format": r.Format,
		"status": r.Status, "terminal": r.Terminal, "created_at": r.CreatedAt,
	}
	if r.Name != "" {
		out["name"] = r.Name
	}
	if r.Study != "" || r.Experiment != "" {
		out["labels"] = gin.H{"study": r.Study, "experiment": r.Experiment}
	}
	return out
}

// ── get (list) ──────────────────────────────────────────────────────────────

// MeFleetJobList — GET /me/fleet/jobs?study=&experiment=&status=&limit=.
//
// Reads this service's own records, never a fan-out across sites: one site's
// task list alone has measured 13.8 MB. Statuses are the last ones observed;
// reading a job (view=status) refreshes its row.
func MeFleetJobList(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	limit := 50
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = min(v, fleetListMax)
	}
	q := common.DB.Where("user_sub = ?", sub)
	if v := c.Query("study"); v != "" {
		q = q.Where("study = ?", v)
	}
	if v := c.Query("experiment"); v != "" {
		q = q.Where("experiment = ?", v)
	}
	if v := c.Query("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	var rows []models.MeFleetJob
	if err := q.Order("created_at desc").Limit(limit).Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read: "+err.Error())
		return
	}
	jobs := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		jobs = append(jobs, fleetJobView(r))
	}
	ok(c, "", gin.H{"jobs": jobs})
}

// ── get (one) ───────────────────────────────────────────────────────────────

// fleetOwnedJob resolves :id to a job the caller owns. A Lumilake job run
// before this API existed (a chat claim or a cycle's run row) is owned through
// the same check the canvas status route uses, and has no fleet row.
func fleetOwnedJob(c *gin.Context) (fleetJobID, *models.MeFleetJob, bool) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return fleetJobID{}, nil, false
	}
	id, valid := parseFleetJobID(c.Param("id"))
	if !valid {
		fail(c, http.StatusBadRequest, 1400, "invalid job id: want <site>:<fm|ll>:<id>")
		return fleetJobID{}, nil, false
	}
	var row models.MeFleetJob
	err := common.DB.Where("site = ? AND kind = ? AND native_id = ?", id.Site, id.Kind, id.Native).
		First(&row).Error
	if err == nil && row.UserSub == sub {
		return id, &row, true
	}
	if err == nil || id.Kind != fleetKindLL || !callerOwnsComputeJob(sub, id.Site, id.Native) {
		// 404, not 403: a 403 would confirm the job exists to someone who has
		// no business knowing that.
		fail(c, http.StatusNotFound, 1404, "no such job for this user")
		return fleetJobID{}, nil, false
	}
	return id, nil, true
}

// MeFleetJobGet — GET /me/fleet/jobs/:id?view=status|result|logs|trace.
func MeFleetJobGet(c *gin.Context) {
	id, row, owned := fleetOwnedJob(c)
	if !owned {
		return
	}
	sub, _ := currentUserID(c)
	bearer, err := fleetReadBearer(sub, id.Kind)
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, err.Error())
		return
	}
	view := c.DefaultQuery("view", "status")
	switch {
	case view == "status":
		fleetStatusView(c, id, row, bearer)
	case view == "result":
		fleetResultView(c, id, bearer)
	case view == "logs" && id.Kind == fleetKindFM:
		fleetLogsView(c, id, bearer)
	case view == "trace" && id.Kind == fleetKindLL:
		fleetTraceView(c, id, bearer)
	case view == "logs" || view == "trace":
		fail(c, http.StatusBadRequest, 1400, fmt.Sprintf(
			"view=%s is not available for %s jobs (FlowMesh: logs; Lumilake: trace, "+
				"which lists the FlowMesh workflows to read logs from)", view, id.Kind))
	default:
		fail(c, http.StatusBadRequest, 1400, "view must be status, result, logs or trace")
	}
}

func fleetGet(c *gin.Context, url, bearer string) (map[string]any, []byte, int) {
	b, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodGet, url: url, bearer: bearer})
	return fleetJSON(b), b, code
}

func fleetStatusView(c *gin.Context, id fleetJobID, row *models.MeFleetJob, bearer string) {
	base := fleetSiteBase(id.Kind, id.Site)
	var rec map[string]any
	var raw []byte
	var code int
	if id.Kind == fleetKindFM {
		rec, raw, code = fleetGet(c, base+"/api/v1/workflows/"+id.Native, bearer)
	} else {
		rec, raw, code = fleetGet(c, base+"/api/v1/jobs/"+id.Native, bearer)
	}
	if code < 200 || code >= 300 {
		failUpstream(c, code, raw)
		return
	}
	native, _ := rec["status"].(string)
	status, terminal := fleetStatus(native)
	out := gin.H{
		"id": id.String(), "site": id.Site, "kind": id.Kind,
		"status": status, "native_status": native, "terminal": terminal,
	}
	if e := rec["error"]; e != nil {
		out["error"] = e
	}
	if id.Kind == fleetKindFM {
		if ids := fleetWorkflowTaskIDs(rec); len(ids) > 0 {
			out["tasks"] = len(ids)
		}
	} else if prog, _, pc := fleetGet(c, base+"/api/v1/jobs/"+id.Native+"/progress", bearer); pc == http.StatusOK {
		// Best-effort, as on the canvas route: a readable job with an
		// unreadable progress endpoint still has a status worth returning.
		if p, isMap := prog["progress"].(map[string]any); isMap {
			out["progress"] = p
		}
	}
	if row != nil {
		out["format"] = row.Format
		if row.Status != status || row.Terminal != terminal {
			common.DB.Model(row).Updates(map[string]any{"status": status, "terminal": terminal})
		}
	}
	ok(c, "", out)
}

// fleetResultView returns the job's outputs plus `metrics`: the merged
// metrics.json of every Python step, which is what an experiment records.
func fleetResultView(c *gin.Context, id fleetJobID, bearer string) {
	base := fleetSiteBase(id.Kind, id.Site)
	if id.Kind == fleetKindLL {
		rec, raw, code := fleetGet(c, base+"/api/v1/jobs/"+id.Native+"/result", bearer)
		if code == http.StatusConflict {
			fail(c, http.StatusConflict, 1409, "job has not finished; read view=status until terminal")
			return
		}
		if code < 200 || code >= 300 {
			failUpstream(c, code, raw)
			return
		}
		outputs := rec["result"]
		if outputs == nil {
			outputs = rec
		}
		ok(c, "", gin.H{"id": id.String(), "outputs": outputs, "metrics": gin.H{}})
		return
	}
	wf, raw, code := fleetGet(c, base+"/api/v1/workflows/"+id.Native, bearer)
	if code < 200 || code >= 300 {
		failUpstream(c, code, raw)
		return
	}
	if _, terminal := fleetStatus(fmt.Sprint(wf["status"])); !terminal {
		fail(c, http.StatusConflict, 1409, "job has not finished; read view=status until terminal")
		return
	}
	names := fleetTaskStageNames(c, base, id.Native, bearer)
	results := []gin.H{}
	metrics := map[string]any{}
	for _, taskID := range fleetWorkflowTaskIDs(wf) {
		if !fleetNativeFM.MatchString(taskID) {
			continue
		}
		res, _, rc := fleetGet(c, base+"/api/v1/results/"+taskID, bearer)
		entry := gin.H{"task_id": taskID}
		if name := names[taskID]; name != "" {
			entry["name"] = name
		}
		if rc == http.StatusOK {
			entry["result"] = res
			if m, isMap := res["metrics"].(map[string]any); isMap {
				for k, v := range m {
					metrics[k] = v
				}
			}
		} else {
			entry["error"] = fmt.Sprintf("result unavailable (%d)", rc)
		}
		results = append(results, entry)
		if len(results) >= fleetResultTaskMax {
			break
		}
	}
	ok(c, "", gin.H{"id": id.String(), "outputs": results, "metrics": metrics})
}

// fleetWorkflowTaskIDs reads a FlowMesh workflow record's task ids: the
// server's `task_ids`, or the ids of a `tasks` list of task objects.
func fleetWorkflowTaskIDs(wf map[string]any) []string {
	var ids []string
	if list, isList := wf["task_ids"].([]any); isList {
		for _, v := range list {
			if id, isStr := v.(string); isStr {
				ids = append(ids, id)
			}
		}
		return ids
	}
	list, _ := wf["tasks"].([]any)
	for _, t := range list {
		if tm, isMap := t.(map[string]any); isMap {
			if id, isStr := tm["task_id"].(string); isStr {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// fleetTaskStageNames maps each task of a FlowMesh workflow to its stage name,
// the part of `task.metadata.name` after the workflow name ("wf:score" ->
// "score"). Best-effort: an unreadable listing leaves results unnamed.
func fleetTaskStageNames(c *gin.Context, base, workflowID, bearer string) map[string]string {
	b, code := fleetDo(c.Request.Context(), fleetCall{
		method: http.MethodGet, url: base + "/api/v1/tasks?workflow_id=" + url.QueryEscape(workflowID), bearer: bearer,
	})
	names := map[string]string{}
	if code != http.StatusOK {
		return names
	}
	var tasks []struct {
		TaskID string `json:"task_id"`
		Task   struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"task"`
	}
	if json.Unmarshal(b, &tasks) != nil {
		return names
	}
	for _, t := range tasks {
		name := t.Task.Metadata.Name
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		names[t.TaskID] = name
	}
	return names
}

func fleetLogsView(c *gin.Context, id fleetJobID, bearer string) {
	limit := 200
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = min(v, 1000)
	}
	url := fmt.Sprintf("%s/api/v1/workflows/%s/logs?limit=%d", fleetSiteBase(id.Kind, id.Site), id.Native, limit)
	b, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodGet, url: url, bearer: bearer})
	if code < 200 || code >= 300 {
		failUpstream(c, code, b)
		return
	}
	var lines any
	if json.Unmarshal(b, &lines) != nil {
		lines = string(b)
	}
	ok(c, "", gin.H{"id": id.String(), "logs": lines})
}

// fleetTraceView lists the FlowMesh workflows a Lumilake job dispatched, as
// fleet ids on the same site, so a caller can read their logs with this API.
func fleetTraceView(c *gin.Context, id fleetJobID, bearer string) {
	rec, raw, code := fleetGet(c, fleetSiteBase(id.Kind, id.Site)+"/api/v1/jobs/"+id.Native+"/workflows", bearer)
	if code < 200 || code >= 300 {
		failUpstream(c, code, raw)
		return
	}
	refs := jobWorkflowRefs(rec)
	workflows := make([]gin.H, 0, len(refs))
	for _, r := range refs {
		st, _ := fleetStatus(r.Status)
		workflows = append(workflows, gin.H{
			"id":     fleetJobID{Site: id.Site, Kind: fleetKindFM, Native: r.WorkflowID}.String(),
			"status": st, "native_status": r.Status,
		})
	}
	ok(c, "", gin.H{"id": id.String(), "workflows": workflows})
}

// ── cancel ──────────────────────────────────────────────────────────────────

// MeFleetJobCancel — POST /me/fleet/jobs/:id/cancel.
func MeFleetJobCancel(c *gin.Context) {
	id, row, owned := fleetOwnedJob(c)
	if !owned {
		return
	}
	sub, _ := currentUserID(c)
	bearer, err := fleetWriteBearer(sub, id.Kind)
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, err.Error())
		return
	}
	path := "/api/v1/workflows/"
	if id.Kind == fleetKindLL {
		path = "/api/v1/jobs/"
	}
	url := fleetSiteBase(id.Kind, id.Site) + path + id.Native + "/cancel"
	b, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodPost, url: url, bearer: bearer})
	if code < 200 || code >= 300 {
		failUpstream(c, code, b)
		return
	}
	// Requested, not done: FlowMesh passes through CANCELLING and a Lumilake
	// job can finish before the cancel lands. The next status read records
	// whichever it was, rather than this call guessing.
	_ = row
	ok(c, "", gin.H{"id": id.String(), "cancel_requested": true})
}
