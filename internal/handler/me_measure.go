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
	material map[string]any // what is stored and replayed
	// keyMaterial, when set, is what the key covers instead of material: the
	// simulator drops each candidate's `id` (a label) so the same design under
	// another name is the same measurement.
	keyMaterial map[string]any
	workflow    string // FlowMesh graph to submit
	site        string
	name        string
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
	// precheck runs before anything is claimed or submitted; a non-empty
	// answer is returned as status not_measured with that reason.
	// wait=true means "not now, ask again" (a slot frees up), not a refusal.
	precheck func(c *gin.Context, sub string, plan measurePlan, app, workflow string) (why string, wait bool)
	// versions lists the accepted versions, for the listing.
	versions func() []string
	// keyAs, when set, is the instrument name the content key covers instead
	// of Name: an app module is keyed as "module" (image digest + run +
	// inputs), so the same computation reached by two names is one row.
	keyAs string
}

// keyName is the instrument name that goes into the content key.
func (in measureInstrument) keyName() string {
	if in.keyAs != "" {
		return in.keyAs
	}
	return in.Name
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
	"mlsys-sandbox": {
		Name: "mlsys-sandbox",
		About: "An MLSys design measured for real on ONE GPU (vLLM in the pinned sandbox image) and scored in " +
			"the pinned tool image. Never reused: every run is a fresh observation. Checks for a free matching " +
			"GPU first and answers not_measured, with the reason, when it cannot run.",
		Share: "tenant",
		Inputs: map[string]string{
			"graph":           "the FlowMesh graph (JSON): one GPU stage on an accepted sandbox image, the rest on accepted mlsys tool images",
			"site":            "compute site (default office)",
			"gpu":             "the GPU stage's requirement ({type, memory}) for the free-GPU check",
			"queue_timeout_s": "how long the job may wait for a GPU before it is cancelled (default 900)",
		},
		plan:     mlsysSandboxPlan,
		versions: func() []string { return sandboxAcceptedTags() },
		executor: "fleet",
		precheck: sandboxPrecheck,
	},
}

// measureScope is the share scope a fresh row starts with.
func measureScope(inst measureInstrument, sub string) string {
	if inst.Share == "tenant" {
		return "tenant:" + sub
	}
	return inst.Share
}

// mlsysDefaultImages: tag=ref pairs. MEASURE_MLSYS_IMAGES replaces the list
// (comma separated) when a new image is pinned, without a release.
const mlsysDefaultImages = "v0.1.3=ghcr.io/mlsys-io/hello-mlsys-agent@sha256:3c9e1fbb0b4c7efbaed8cae4411342e2bb6d12ebd0b3308766ea224679f599e2," +
	// v0.1.4: evaluate accepts resamples (fresh prompt mixes from the development trace).
	"v0.1.4=ghcr.io/mlsys-io/hello-mlsys-agent@sha256:c0fe3c0f9b379553be127a40cb1b44bf7fdb1519fd7558f6905d7173481f0e14"

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
		site = "auto" // picked at submit: the site with the most idle workers (measurePickSite)
	}
	if site != "auto" && !computeSiteRe.MatchString(site) {
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
	keyMaterial := map[string]any{"job": job, "payload": withoutCandidateIDs(payload)}
	key := measureKey("mlsys-simulator", digest, keyMaterial)
	wf, err := mlsysWorkflow(image, tag, job, payload, "measure-"+key[:12], timeout)
	if err != nil {
		return measurePlan{}, err
	}
	return measurePlan{version: digest, label: tag, material: material, keyMaterial: keyMaterial, workflow: wf, site: site,
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

// keyed is what the key covers: keyMaterial when the instrument set one.
func (p measurePlan) keyed() map[string]any {
	if p.keyMaterial != nil {
		return p.keyMaterial
	}
	return p.material
}

// withoutCandidateIDs copies a simulator payload with each candidate's `id`
// removed — the design is its infra + strategy (the app's own config_hash);
// the id is the name someone gave it.
func withoutCandidateIDs(payload map[string]any) map[string]any {
	out := make(map[string]any, len(payload))
	for k, v := range payload {
		out[k] = v
	}
	if cands, ok := payload["candidates"].([]any); ok {
		stripped := make([]any, len(cands))
		for i, c := range cands {
			if m, isMap := c.(map[string]any); isMap {
				cp := make(map[string]any, len(m))
				for k, v := range m {
					if k != "id" {
						cp[k] = v
					}
				}
				stripped[i] = cp
			} else {
				stripped[i] = c
			}
		}
		out["candidates"] = stripped
	}
	return out
}

// candidateIDs lists a stored or requested material's candidate ids in order.
func candidateIDs(material map[string]any) []string {
	payload, _ := material["payload"].(map[string]any)
	cands, _ := payload["candidates"].([]any)
	ids := make([]string, len(cands))
	for i, c := range cands {
		if m, ok := c.(map[string]any); ok {
			ids[i], _ = m["id"].(string)
		}
	}
	return ids
}

// renameCandidates rewrites every `candidate_id` in a stored result from the
// first requester's names to this requester's, matched by position (equal keys
// mean the same candidates in the same order). Anything it cannot map is left.
func renameCandidates(result, storedInputs string, requested map[string]any) string {
	var stored map[string]any
	if json.Unmarshal([]byte(storedInputs), &stored) != nil {
		return result
	}
	from, to := candidateIDs(stored), candidateIDs(requested)
	if len(from) == 0 || len(from) != len(to) {
		return result
	}
	rename := map[string]string{}
	for i := range from {
		if from[i] != "" && to[i] != "" && from[i] != to[i] {
			rename[from[i]] = to[i]
		}
	}
	if len(rename) == 0 {
		return result
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(result))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return result
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if s, isStr := val.(string); isStr && k == "candidate_id" {
					if n, ok := rename[s]; ok {
						t[k] = n
					}
					continue
				}
				t[k] = walk(val)
			}
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		}
		return x
	}
	out, err := canonicalJSON(walk(v))
	if err != nil {
		return result
	}
	return out
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

// MeMeasureInstruments lists what can be measured; with ?app=<app>, also
// the compute modules of the caller's own install of that app; with
// ?public=1, also every public module of other owners' published apps
// (owner-qualified, `public: true`, from the TTL-cached index — see
// me_measure_public_modules.go), minus the apps the caller's own installs
// shadow.
func MeMeasureInstruments(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
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
		item := gin.H{"name": in.Name, "kind": "instrument", "about": in.About, "share": in.Share,
			"inputs": in.Inputs, "versions": in.versions()}
		// What a fresh run of it usually uses (median of recent metered runs).
		if g, cp, t, k := measureEstimate(in.Name); k > 0 {
			est := gin.H{"from_runs": k, "cost_usd": currentRates().cost(g, cp, t)}
			if g > 0 {
				est["gpu_s"], est["gpu_type"] = round3(g), t
			}
			if cp > 0 {
				est["cpu_s"] = round3(cp)
			}
			item["estimate"] = est
		}
		out = append(out, item)
	}
	app := strings.TrimSpace(c.Query("app"))
	own := moduleListing(sub, app)
	mods := own
	resp := gin.H{}
	if truthyParam(c.Query("public")) {
		shadow := map[string]bool{}
		for _, name := range moduleInstalledApps(sub) {
			shadow[name] = true
		}
		if own != nil {
			shadow[app] = true
		}
		pub, status := publicModuleListing(sub, shadow)
		mods = append(append([]gin.H{}, own...), pub...)
		resp["public_modules"] = status
	}
	for _, item := range mods {
		if name, _ := item["name"].(string); name != "" && item["refused"] == nil {
			if g, cp, t, k := measureEstimate(name); k > 0 {
				item["estimate"] = gin.H{"from_runs": k, "cost_usd": currentRates().cost(g, cp, t), "cpu_s": round3(cp)}
			}
		}
		out = append(out, item)
	}
	resp["instruments"] = out
	ok(c, "", resp)
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
		// An app compute module: "<app>.<module>" (the caller's own install)
		// or "<owner>/<app>.<module>" (a public one). Refusals in words.
		if mod, _, isModule, refusal := resolveModule(sub, b.Instrument, b.App); isModule {
			if refusal != nil {
				fail(c, refusal.code, 1000+refusal.code, refusal.why)
				return
			}
			inst, known = moduleInstrument(b.Instrument, mod), true
		}
	}
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
	key := measureKey(inst.keyName(), plan.version, plan.keyed())
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
		key = measureKey(inst.keyName(), plan.version, map[string]any{"tenant": sub, "inputs": plan.keyed()})
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
			// Same design, the requester's names: a hit answers with THEIR
			// candidate ids, not the first requester's.
			row.Result = renameCandidates(row.Result, row.Inputs, plan.material)
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

	if inst.precheck != nil {
		if why, wait := inst.precheck(c, sub, plan, labels.App, labels.Workflow); why != "" {
			if wait {
				// Not a refusal: a slot frees up soon. Nothing is claimed or
				// recorded; asking again after retry_after proceeds.
				c.Header("Retry-After", "30")
				c.JSON(http.StatusAccepted, gin.H{"ret_code": 0, "message": "", "data": gin.H{"key": key,
					"instrument": inst.Name, "status": "waiting", "reason": why, "retry_after": 30}})
				return
			}
			measureRecord(labels, "not_measured")
			c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "", "data": gin.H{"key": key,
				"instrument": inst.Name, "status": "not_measured", "reason": why}})
			return
		}
	}
	// The app's compute budget (spec compute.budget): refuse a fresh run that
	// would go over it. Reused and joined answers above cost nothing.
	if why := budgetRefusal(sub, labels.App, labels.Workflow, inst.Name, labels.App); why != "" {
		measureRecord(labels, "not_measured")
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "", "data": gin.H{"key": key,
			"instrument": inst.Name, "status": "not_measured", "reason": why, "budget": true}})
		return
	}
	// Where it runs. NUS is admin+ by policy (2026-11-26); an unnamed site is
	// the one with the most idle workers among those this caller may use.
	if plan.site == "auto" {
		plan.site = measurePickSite(c, sub)
	} else if plan.site != "" && measureAdminSites()[plan.site] && !measureIsAdmin(sub) {
		fail(c, http.StatusForbidden, 1403, "the "+plan.site+" fleet runs jobs for admins only; leave site empty to use office or home")
		return
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
			ShareScope: measureScope(inst, sub), Status: "queued", Executor: inst.executor, ExecutorSub: sub,
			ClaimedAt: now, NoReuse: inst.Name == "mlsys-sandbox"}
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
				"no_reuse": inst.Name == "mlsys-sandbox", "share_scope": measureScope(inst, sub)})
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
	} else if inst.executor == "llm" {
		err = llmMeasureSubmit(&row, plan, sub, labels.App)
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
	if id := measureRecord(labels, outcome); id != 0 {
		row.ChargedRequestID = id
		common.DB.Model(&row).Update("charged_request_id", id)
	}
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

func measureRecord(r models.MeasureRequest, outcome string) uint {
	r.Outcome = outcome
	if common.DB.Create(&r).Error != nil {
		return 0
	}
	return r.ID
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
	if row.Executor == "llm" {
		llmAdvance(row)
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
	if !terminal && status == "queued" && row.Instrument == "mlsys-sandbox" && sandboxQueueTimedOut(c, row, id, bearer) {
		return
	}
	if !terminal {
		if row.Status != "running" {
			row.Status = "running"
			common.DB.Model(row).Update("status", "running")
		}
		return
	}
	ids := fleetWorkflowTaskIDs(rec)
	// What it used, failed or not: a GPU that ran and failed was still spent.
	measureRecordUsage(c, row, base, id.Native, bearer)
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
		if row.Executor == "module" {
			msg = moduleFailureWords(msg)
		}
		measureSettle(row, "failed", "", msg)
		return
	}
	// Every stage's value by its stage name; `value` is the first one (a
	// one-stage graph's only one), which is what the simulator reads.
	var first map[string]any
	var metrics any
	values := map[string]any{}
	var names map[string]fleetTask
	if len(ids) > 1 {
		names = fleetTaskListing(c, base, id.Native, bearer)
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
			if first == nil {
				first, metrics = value, res["metrics"]
			}
			if n := names[taskID].Name; n != "" {
				values[n] = value
			}
		}
	}
	if first == nil {
		measureSettle(row, "failed", "", "the job succeeded but returned no value")
		return
	}
	if row.Executor == "module" {
		// One stage; its value is the module's own output object, re-checked
		// against the output limit here (the wrapper already stops at 1 MiB).
		out, why := moduleSettleValue(first)
		if why != "" {
			measureSettle(row, "failed", "", why)
			return
		}
		first, values = out, map[string]any{"module": out}
	}
	out, _ := canonicalJSON(map[string]any{"value": first, "values": values, "metrics": metrics})
	measureSettle(row, "succeeded", out, "")
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
	} else if row.Instrument == "mlsys-sandbox" {
		for ref, tag := range sandboxImages() {
			if strings.HasSuffix(ref, row.Version) {
				label = tag
			}
		}
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
		if u := usageBlock(row, reused); u != nil {
			out["usage"] = u
		}
	case "not_measured":
		out["reason"] = row.Error
	case "succeeded":
		var res map[string]any
		dec := json.NewDecoder(strings.NewReader(row.Result))
		dec.UseNumber()
		_ = dec.Decode(&res)
		measuredOn := row.Instrument
		if label != "" {
			measuredOn += " " + label
		}
		result := gin.H{"value": res["value"], "values": res["values"], "metrics": res["metrics"], "instrument": row.Instrument,
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
		if u := usageBlock(row, reused); u != nil {
			result["usage"] = u
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

// ── Where a measurement runs ────────────────────────────────────────────

// measureSites: the fleet sites any user's measurements may use, in order of
// preference for ties. MEASURE_SITES overrides (comma separated).
func measureSites() []string {
	return splitSites(os.Getenv("MEASURE_SITES"), "office,home")
}

// measureAdminSites: sites only admins may use (NUS: not our hardware, no user
// GPU quota). MEASURE_ADMIN_SITES overrides.
func measureAdminSites() map[string]bool {
	out := map[string]bool{}
	for _, s := range splitSites(os.Getenv("MEASURE_ADMIN_SITES"), "nus") {
		out[s] = true
	}
	return out
}

func splitSites(raw, def string) []string {
	if strings.TrimSpace(raw) == "" {
		raw = def
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" && computeSiteRe.MatchString(s) {
			out = append(out, s)
		}
	}
	return out
}

func measureIsAdmin(sub string) bool {
	_, role := userEmailRole(sub)
	return role == "admin" || role == "super_admin"
}

// measurePickSite reads each usable site's FlowMesh workers as the caller and
// picks the one with the most idle python workers. Unreadable sites are
// skipped; if none answers, the first site is used.
func measurePickSite(c *gin.Context, sub string) string {
	order := measureSites()
	if measureIsAdmin(sub) {
		for s := range measureAdminSites() {
			order = append(order, s)
		}
	}
	idle := map[string]int{}
	for _, site := range order {
		if n, ok := measureIdleWorkers(c, sub, site); ok {
			idle[site] = n
		}
	}
	return pickSite(order, idle)
}

// pickSite: the most idle workers wins; ties go to the earlier site; with no
// readings at all, the first site.
func pickSite(order []string, idle map[string]int) string {
	best, bestN := "", -1
	for _, s := range order {
		if n, ok := idle[s]; ok && n > bestN {
			best, bestN = s, n
		}
	}
	if best == "" && len(order) > 0 {
		return order[0]
	}
	return best
}

func measureIdleWorkers(c *gin.Context, sub, site string) (int, bool) {
	bearer, err := fleetReadBearer(sub, fleetKindFM)
	if err != nil {
		return 0, false
	}
	b, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodGet, bearer: bearer,
		url: fleetSiteBase(fleetKindFM, site) + "/api/v1/workers"})
	if code != http.StatusOK {
		return 0, false
	}
	var list []map[string]any
	if json.Unmarshal(b, &list) != nil {
		var wrapped map[string]any
		if json.Unmarshal(b, &wrapped) != nil {
			return 0, false
		}
		if raw, ok := wrapped["workers"].([]any); ok {
			for _, w := range raw {
				if m, ok := w.(map[string]any); ok {
					list = append(list, m)
				}
			}
		}
	}
	n := 0
	for _, w := range list {
		if w["cordoned"] == true || w["stale"] == true || !strings.EqualFold(fmt.Sprint(w["status"]), "IDLE") {
			continue
		}
		caps, _ := w["capabilities"].(map[string]any)
		types, _ := caps["supported_task_types"].([]any)
		for _, t := range types {
			if t == "python" {
				n++
				break
			}
		}
	}
	return n, true
}
