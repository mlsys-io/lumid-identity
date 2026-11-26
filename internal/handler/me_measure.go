package handler

// /me/measure — measure once, read many times (central measurement, phase B,
// 2026-11-26).
//
// Apps used to wrap their instruments themselves: the MLSys app built a
// one-stage FlowMesh graph around the pinned simulator image and polled it,
// once per student, even when twenty students asked for the same seeded
// template arm. Here an app asks for a MEASUREMENT (instrument + inputs), and
// identity runs it once:
//
//   - The key is the content: instrument, instrument version (the image
//     digest — verdict() and the task seeds ship inside the image) and the
//     canonical inputs. Identical requests from any user share one row.
//   - Single flight: the row is claimed by a unique-key insert; a second
//     identical request while it runs JOINS it instead of submitting again.
//   - No background workers. Status advances when someone reads it (POST or
//     GET), with the executor's credential — the account whose job it is.
//   - A result never says who first ran it: executor_sub stays in identity,
//     and the upstream job id is shown only to the account that ran it.
//   - Cache hits are free. New runs count against a per-user running cap and
//     a daily budget; `fresh` (forced rerun) is rate-limited on top.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	measureMaxInputBytes   = 256 << 10
	measureDefaultTimeoutS = 600
	measureMaxTimeoutS     = 3600
	// A claimed row with no upstream job after this long lost its submitter
	// (the request died between claim and submit); the next reader retries.
	measureClaimStale = 2 * time.Minute
	measureRetryAfter = 5
)

var measureKeyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// measureLimit reads an int env override, else the default.
func measureLimit(env string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(env))); err == nil && v > 0 {
		return v
	}
	return def
}

// ── The registry ────────────────────────────────────────────────────────

// measurePlan is what an instrument makes of a request's inputs.
type measurePlan struct {
	version  string         // goes into the key
	label    string         // human version ("v0.1.3"), for measured_on
	material map[string]any // what the key covers, besides instrument + version
	workflow string         // FlowMesh graph to submit
	site     string
	name     string
}

type measureInstrument struct {
	Name  string `json:"name"`
	About string `json:"about"`
	Share string `json:"share"`
	// Inputs, in words, for the instruments listing (the chat reads it).
	Inputs map[string]string `json:"inputs"`
	plan   func(inputs map[string]any) (measurePlan, error)
	// executor: "fleet" (a FlowMesh graph) or "lqt" (the backtest job API).
	executor string
	// shareOnSettle: whether a result may be reused is known only once it
	// settles (lqt-backtest), so another tenant never joins a running one.
	shareOnSettle bool
	// versions lists the accepted versions, for the listing.
	versions func() []string
}

var measureRegistry = map[string]measureInstrument{
	"mlsys-simulator": {
		Name: "mlsys-simulator",
		About: "The MLSys serving simulator (hello-mlsys-agent `mlab.jobs`), pinned by image digest. Seeded " +
			"and deterministic for a given image, so identical inputs are measured once for everyone.",
		Share: "global",
		Inputs: map[string]string{
			"image":     "the pinned simulator image reference (…@sha256:…); must be an accepted version",
			"job":       "the mlab job to run: evaluate",
			"payload":   "the job's JSON payload (task, profile, candidates, seeds, workloads)",
			"site":      "compute site (default office); not part of the key",
			"timeout_s": "per-job timeout in seconds (default 600); not part of the key",
		},
		plan:     mlsysSimulatorPlan,
		versions: func() []string { return mlsysAcceptedTags() },
		executor: "fleet",
	},
	"lqt-backtest": {
		Name: "lqt-backtest",
		About: "A backtest on recorded market history (the LQT backtest job API), submitted as you. Reused " +
			"by everyone only when it replayed recorded prints over a window pinned in the past and read no " +
			"recorded signals; with recorded signals, by you only (they may be your own). An unpinned window " +
			"or a synthetic replay is never reused.",
		Share: "global",
		Inputs: map[string]string{
			"strategy": "the strategy body the backtest job API takes (program, params, window_secs, until, fill_model)",
			"symbol":   "the instrument to replay (or strategy.symbol)",
			"name":     "a label; not part of the key",
		},
		plan:          lqtBacktestPlan,
		versions:      func() []string { return []string{"harness " + lqtHarness()} },
		executor:      "lqt",
		shareOnSettle: true,
	},
}

// mlsysDefaultImages: tag=ref pairs. MEASURE_MLSYS_IMAGES replaces the list
// (comma separated) when a new image is pinned, without a release.
const mlsysDefaultImages = "v0.1.3=ghcr.io/mlsys-io/hello-mlsys-agent@sha256:3c9e1fbb0b4c7efbaed8cae4411342e2bb6d12ebd0b3308766ea224679f599e2"

var mlsysJobs = map[string]bool{"evaluate": true}

// mlsysImages maps an accepted image reference to its tag.
func mlsysImages() map[string]string {
	raw := strings.TrimSpace(os.Getenv("MEASURE_MLSYS_IMAGES"))
	if raw == "" {
		raw = mlsysDefaultImages
	}
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		tag, ref, found := strings.Cut(strings.TrimSpace(pair), "=")
		if found && strings.Contains(ref, "@sha256:") {
			out[strings.TrimSpace(ref)] = strings.TrimSpace(tag)
		}
	}
	return out
}

func mlsysAcceptedTags() []string {
	tags := []string{}
	for _, t := range mlsysImages() {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func mlsysSimulatorPlan(in map[string]any) (measurePlan, error) {
	image, _ := in["image"].(string)
	tag, accepted := mlsysImages()[image]
	if !accepted {
		return measurePlan{}, fmt.Errorf("image is not an accepted mlsys-simulator version (accepted: %s)",
			strings.Join(mlsysAcceptedTags(), ", "))
	}
	job, _ := in["job"].(string)
	if !mlsysJobs[job] {
		return measurePlan{}, fmt.Errorf("job %q is not measured centrally (accepted: evaluate)", job)
	}
	payload, isMap := in["payload"].(map[string]any)
	if !isMap || len(payload) == 0 {
		return measurePlan{}, errors.New("payload must be a non-empty JSON object")
	}
	site, _ := in["site"].(string)
	if site == "" {
		site = "office"
	}
	if !computeSiteRe.MatchString(site) {
		return measurePlan{}, errors.New("invalid site")
	}
	timeout := measureDefaultTimeoutS
	if n, isNum := in["timeout_s"].(json.Number); isNum {
		if v, err := n.Int64(); err == nil && v > 0 && v <= measureMaxTimeoutS {
			timeout = int(v)
		}
	}
	digest := image[strings.Index(image, "@")+1:]
	material := map[string]any{"job": job, "payload": payload}
	key := measureKey("mlsys-simulator", digest, material)
	wf, err := mlsysWorkflow(image, tag, job, payload, "measure-"+key[:12], timeout)
	if err != nil {
		return measurePlan{}, err
	}
	return measurePlan{version: digest, label: tag, material: material, workflow: wf, site: site,
		name: "measure mlsys-simulator " + key[:12]}, nil
}

// pyStr renders s as a Python string literal. A JSON string literal is one,
// provided HTML escaping is off (it is valid either way, just noisier).
func pyStr(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

// mlsysWorkflow is the one-stage FlowMesh graph the MLSys app used to build
// itself (commands/_mlab.py workflow/job_code): the pinned image, no network.
func mlsysWorkflow(image, tag, job string, payload map[string]any, name string, timeoutS int) (string, error) {
	pj, err := canonicalJSON(payload)
	if err != nil {
		return "", err
	}
	code := "PAYLOAD = " + pyStr(pj) + "\n\n" +
		"def main():\n" +
		"    import json\n" +
		"    from mlab.jobs import run\n" +
		"    return json.loads(run(" + pyStr(job) + ", PAYLOAD))\n"
	graph := map[string]any{
		"apiVersion": "flowmesh/v1", "kind": "Workflow",
		"metadata": map[string]any{"name": name, "annotations": map[string]any{
			"description": "mlsys-simulator " + job + " (" + tag + "), measured once via /me/measure"}},
		"spec": map[string]any{"stages": []any{map[string]any{"name": job, "spec": map[string]any{
			"taskType": "python", "entrypoint": "main", "image": image, "timeoutSeconds": timeoutS,
			"network": "none", "code": code}}}},
	}
	return canonicalJSON(graph)
}

// ── Keys ────────────────────────────────────────────────────────────────

// canonicalJSON: maps marshal with sorted keys; numbers keep their text
// (inputs are decoded with UseNumber), so 42 stays 42.
func canonicalJSON(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func measureKey(instrument, version string, material map[string]any) string {
	s, _ := canonicalJSON(map[string]any{"instrument": instrument, "version": version, "inputs": material})
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ── Handlers ────────────────────────────────────────────────────────────

type measureBody struct {
	Instrument string          `json:"instrument"`
	Inputs     json.RawMessage `json:"inputs"`
	App        string          `json:"app"`
	Workflow   string          `json:"workflow"`
	RunID      string          `json:"run_id"`
	Fresh      bool            `json:"fresh"`
}

// MeMeasureInstruments lists what can be measured.
func MeMeasureInstruments(c *gin.Context) {
	if _, authed := currentUserID(c); !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	names := make([]string, 0, len(measureRegistry))
	for n := range measureRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []gin.H{}
	for _, n := range names {
		in := measureRegistry[n]
		out = append(out, gin.H{"name": in.Name, "about": in.About, "share": in.Share,
			"inputs": in.Inputs, "versions": in.versions()})
	}
	ok(c, "", gin.H{"instruments": out})
}

// MeMeasure: POST /me/measure.
func MeMeasure(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var b measureBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	inst, known := measureRegistry[b.Instrument]
	if !known {
		fail(c, http.StatusBadRequest, 1400, "unknown instrument "+strconv.Quote(b.Instrument)+
			"; GET /me/measure/instruments lists them")
		return
	}
	if len(b.Inputs) == 0 || len(b.Inputs) > measureMaxInputBytes {
		fail(c, http.StatusBadRequest, 1400, "inputs is required (a JSON object of at most 256 KiB)")
		return
	}
	var inputs map[string]any
	dec := json.NewDecoder(bytes.NewReader(b.Inputs))
	dec.UseNumber()
	if err := dec.Decode(&inputs); err != nil || inputs == nil {
		fail(c, http.StatusBadRequest, 1400, "inputs must be a JSON object")
		return
	}
	plan, err := inst.plan(inputs)
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	key := measureKey(inst.Name, plan.version, plan.material)
	labels := models.MeasureRequest{UserSub: sub, Key: key, App: fleetClip(b.App, 128),
		Workflow: fleetClip(b.Workflow, 128), RunID: fleetClip(b.RunID, 200)}

	var row models.MeasureResult
	found := common.DB.First(&row, "mkey = ?", key).Error == nil
	undecided := found && inst.shareOnSettle && row.ExecutorSub != sub &&
		(row.Status == "queued" || row.Status == "running")
	if found && (!measureVisible(&row, sub) || undecided) {
		// Another tenant's private measurement of the same content — or one
		// still running whose reuse is not decided yet: measure it again under
		// this tenant (never reveal or reuse theirs).
		key = measureKey(inst.Name, plan.version, map[string]any{"tenant": sub, "inputs": plan.material})
		labels.Key = key
		row = models.MeasureResult{}
		found = common.DB.First(&row, "mkey = ?", key).Error == nil
	}
	if found {
		measureAdvance(c, &row)
		switch {
		case row.Status == "succeeded" && !b.Fresh && !row.NoReuse:
			common.DB.Model(&row).UpdateColumn("hits", gorm.Expr("hits + 1"))
			row.Hits++
			measureRecord(labels, "cached")
			measureRespond(c, http.StatusOK, &row, sub, true)
			return
		case row.Status == "queued" || row.Status == "running":
			// Running already: join it, fresh or not — the same measurement
			// cannot usefully run twice at once.
			measureRecord(labels, "joined")
			measureRespond(c, http.StatusAccepted, &row, sub, row.ExecutorSub != sub)
			return
		}
		// failed, succeeded + fresh, or a result that must not be reused: run
		// it again below.
	}

	if msg, retry := measureQuota(sub, b.Fresh && found && row.Status == "succeeded" && !row.NoReuse); msg != "" {
		c.Header("Retry-After", strconv.Itoa(retry))
		c.JSON(http.StatusTooManyRequests, gin.H{"ret_code": 1429, "message": msg,
			"data": gin.H{"key": key, "status": "not_measured", "retry_after": retry, "reason": msg}})
		return
	}

	now := time.Now()
	if !found {
		row = models.MeasureResult{Key: key, Instrument: inst.Name, Version: plan.version,
			ShareScope: inst.Share, Status: "queued", Executor: inst.executor, ExecutorSub: sub, ClaimedAt: now}
		row.Inputs, _ = canonicalJSON(plan.material)
		if err := common.DB.Create(&row).Error; err != nil {
			// Lost the race: someone claimed this key a moment ago. Join it.
			if common.DB.First(&row, "mkey = ?", key).Error == nil {
				measureRecord(labels, "joined")
				measureRespond(c, http.StatusAccepted, &row, sub, row.ExecutorSub != sub)
				return
			}
			fail(c, http.StatusInternalServerError, 1500, "could not record the measurement: "+err.Error())
			return
		}
	} else {
		// Re-claim a failed (or freshly re-requested) row, but only if nobody
		// else did in the meantime: compare-and-set on the status we read.
		res := common.DB.Model(&models.MeasureResult{}).
			Where("mkey = ? AND status = ? AND updated_at = ?", key, row.Status, row.UpdatedAt).
			Updates(map[string]any{"status": "queued", "executor_sub": sub, "executor_ref": "",
				"claimed_at": now, "result": "", "error": "", "settled_at": nil, "not_before": nil,
				"no_reuse": false, "share_scope": inst.Share})
		if res.Error != nil || res.RowsAffected == 0 {
			_ = common.DB.First(&row, "mkey = ?", key).Error
			measureRecord(labels, "joined")
			measureRespond(c, http.StatusAccepted, &row, sub, row.ExecutorSub != sub)
			return
		}
		_ = common.DB.First(&row, "mkey = ?", key).Error
	}

	outcome := "submitted"
	if b.Fresh && found {
		outcome = "fresh"
	}
	if inst.executor == "lqt" {
		_, _, err = lqtMeasureSubmit(&row, sub)
	} else {
		err = measureSubmit(c, &row, plan, sub, b.App)
	}
	if err != nil {
		common.DB.Model(&row).Updates(map[string]any{"status": "failed", "error": fleetClip(err.Error(), 1000),
			"settled_at": time.Now()})
		row.Status, row.Error = "failed", err.Error()
		measureRecord(labels, outcome)
		measureRespond(c, http.StatusBadGateway, &row, sub, false)
		return
	}
	measureRecord(labels, outcome)
	measureRespond(c, http.StatusAccepted, &row, sub, false)
}

// MeMeasureGet: GET /me/measure/:key — the same object, advanced.
func MeMeasureGet(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	key := c.Param("key")
	var row models.MeasureResult
	if !measureKeyRe.MatchString(key) || common.DB.First(&row, "mkey = ?", key).Error != nil ||
		!measureVisible(&row, sub) {
		fail(c, http.StatusNotFound, 1404, "no such measurement")
		return
	}
	measureAdvance(c, &row)
	code := http.StatusOK
	if row.Status == "queued" || row.Status == "running" {
		code = http.StatusAccepted
	}
	measureRespond(c, code, &row, sub, row.ExecutorSub != sub)
}

// measureVisible: global rows are everyone's; a tenant row is its tenant's.
func measureVisible(row *models.MeasureResult, sub string) bool {
	return row.ShareScope == "global" || row.ShareScope == "tenant:"+sub
}

// measureQuota returns a refusal and a Retry-After, or "" when allowed.
func measureQuota(sub string, fresh bool) (string, int) {
	var running int64
	common.DB.Model(&models.MeasureResult{}).
		Where("executor_sub = ? AND status IN ?", sub, []string{"queued", "running"}).Count(&running)
	if cap := measureLimit("MEASURE_RUNNING_CAP", 4); running >= int64(cap) {
		return fmt.Sprintf("%d of your measurements are already running (limit %d); "+
			"identical measurements are free, new ones wait", running, cap), 30
	}
	var today int64
	common.DB.Model(&models.MeasureRequest{}).
		Where("user_sub = ? AND outcome IN ? AND created_at > ?", sub, []string{"submitted", "fresh"},
			time.Now().Add(-24*time.Hour)).Count(&today)
	if budget := measureLimit("MEASURE_DAILY_BUDGET", 200); today >= int64(budget) {
		return fmt.Sprintf("daily budget of %d new measurements used; identical measurements are still free",
			budget), 3600
	}
	if fresh {
		var hour int64
		common.DB.Model(&models.MeasureRequest{}).
			Where("user_sub = ? AND outcome = ? AND created_at > ?", sub, "fresh", time.Now().Add(-time.Hour)).
			Count(&hour)
		if limit := measureLimit("MEASURE_FRESH_PER_HOUR", 6); hour >= int64(limit) {
			return fmt.Sprintf("at most %d forced reruns an hour", limit), 600
		}
	}
	return "", 0
}

func measureRecord(r models.MeasureRequest, outcome string) {
	r.Outcome = outcome
	common.DB.Create(&r)
}

// measureSubmit runs the plan's graph on the fleet AS THE CALLER and records
// the job in their fleet jobs, exactly as POST /me/fleet/jobs would.
func measureSubmit(c *gin.Context, row *models.MeasureResult, plan measurePlan, sub, app string) error {
	bearer, err := fleetWriteBearer(sub, fleetKindFM)
	if err != nil {
		return err
	}
	body, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodPost, bearer: bearer,
		contentType: "text/plain", body: []byte(plan.workflow),
		url: fleetSiteBase(fleetKindFM, plan.site) + "/api/v1/workflows"})
	if code < 200 || code >= 300 {
		return fmt.Errorf("compute service refused the job (HTTP %d): %s", code, fleetClip(string(body), 300))
	}
	resp := fleetJSON(body)
	native, _ := resp["workflow_id"].(string)
	id := fleetJobID{Site: plan.site, Kind: fleetKindFM, Native: native}
	if _, valid := parseFleetJobID(id.String()); !valid {
		return errors.New("compute service accepted the job but returned no usable id")
	}
	study := "measure"
	if app != "" && fleetLabelRe.MatchString(app) {
		study = app
	}
	common.DB.Create(&models.MeFleetJob{Site: plan.site, Kind: fleetKindFM, NativeID: native, UserSub: sub,
		Format: fleetFormatFlowMesh, Name: fleetClip(plan.name, 128), Study: study, Experiment: "measure",
		Status: "queued"})
	row.Status, row.ExecutorRef = "running", id.String()
	return common.DB.Model(row).Updates(map[string]any{"status": "running", "executor_ref": id.String()}).Error
}

// measureAdvance moves a queued/running row on by reading its upstream job
// with the executor's credential. An unreachable upstream changes nothing.
func measureAdvance(c *gin.Context, row *models.MeasureResult) {
	if row.Status != "queued" && row.Status != "running" {
		return
	}
	if row.Executor == "lqt" {
		lqtMeasureAdvance(c, row)
		return
	}
	if row.ExecutorRef == "" {
		if time.Since(row.ClaimedAt) > measureClaimStale {
			measureSettle(row, "failed", "", "the submission did not complete; asking again retries it")
		}
		return
	}
	id, valid := parseFleetJobID(row.ExecutorRef)
	if !valid {
		measureSettle(row, "failed", "", "unreadable job reference")
		return
	}
	bearer, err := fleetReadBearer(row.ExecutorSub, id.Kind)
	if err != nil {
		return
	}
	base := fleetSiteBase(id.Kind, id.Site)
	rec, _, code := fleetGet(c, base+"/api/v1/workflows/"+id.Native, bearer)
	if code < 200 || code >= 300 {
		return
	}
	status, terminal := fleetStatus(fmt.Sprint(rec["status"]))
	if !terminal {
		if row.Status != "running" {
			row.Status = "running"
			common.DB.Model(row).Update("status", "running")
		}
		return
	}
	ids := fleetWorkflowTaskIDs(rec)
	if status != "succeeded" {
		msg := ""
		if e := rec["error"]; e != nil {
			msg = fmt.Sprint(e)
		}
		if msg == "" {
			_, msg = fleetFirstFailure(ids, fleetTaskListing(c, base, id.Native, bearer))
		}
		if msg == "" {
			msg = "the job ended " + status
		}
		measureSettle(row, "failed", "", msg)
		return
	}
	for _, taskID := range ids {
		if !fleetNativeFM.MatchString(taskID) {
			continue
		}
		res, _, rc := fleetGet(c, base+"/api/v1/results/"+taskID, bearer)
		if rc != http.StatusOK {
			continue
		}
		if value, isMap := res["value"].(map[string]any); isMap {
			out, _ := canonicalJSON(map[string]any{"value": value, "metrics": res["metrics"]})
			measureSettle(row, "succeeded", out, "")
			return
		}
	}
	measureSettle(row, "failed", "", "the job succeeded but returned no value")
}

func measureSettle(row *models.MeasureResult, status, result, msg string) {
	now := time.Now()
	row.Status, row.Result, row.Error, row.SettledAt = status, result, msg, &now
	common.DB.Model(row).Updates(map[string]any{"status": status, "result": result,
		"error": fleetClip(msg, 1000), "settled_at": now})
}

func measureRespond(c *gin.Context, code int, row *models.MeasureResult, sub string, reused bool) {
	out := gin.H{"key": row.Key, "instrument": row.Instrument, "version": row.Version,
		"status": row.Status, "hits": row.Hits}
	label := ""
	if row.Instrument == "lqt-backtest" {
		label = strings.Replace(row.Version, "harness-", "harness ", 1)
	} else if row.Instrument == "mlsys-simulator" {
		for ref, tag := range mlsysImages() {
			if strings.HasSuffix(ref, row.Version) {
				label = tag
			}
		}
	}
	switch row.Status {
	case "queued", "running":
		out["retry_after"] = measureRetryAfter
		if row.NotBefore != nil && row.ExecutorRef == "" {
			wait := int(time.Until(*row.NotBefore).Seconds()) + 1
			if wait < 1 {
				wait = 1
			}
			out["retry_after"] = wait
			out["reason"] = "the backtest job API is pacing this account; it is submitted after the wait"
		}
	case "failed":
		out["error"] = row.Error
	case "succeeded":
		var res map[string]any
		dec := json.NewDecoder(strings.NewReader(row.Result))
		dec.UseNumber()
		_ = dec.Decode(&res)
		measuredOn := row.Instrument
		if label != "" {
			measuredOn += " " + label
		}
		result := gin.H{"value": res["value"], "metrics": res["metrics"], "instrument": row.Instrument,
			"version": row.Version, "measured_on": measuredOn, "reused": reused, "share": "everyone"}
		if row.ShareScope != "global" {
			result["share"] = "you"
		}
		if row.NoReuse {
			result["share"] = "this run only"
		}
		if row.SettledAt != nil {
			result["measured_at"] = row.SettledAt.UTC().Format(time.RFC3339)
		}
		out["result"] = result
	}
	if row.ExecutorSub == sub && row.ExecutorRef != "" {
		out["executor_ref"] = row.ExecutorRef
	}
	if label != "" {
		out["version_label"] = label
	}
	c.JSON(code, gin.H{"ret_code": 0, "message": "", "data": out})
}
