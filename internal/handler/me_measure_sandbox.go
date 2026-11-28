package handler

// The mlsys-sandbox instrument (central measurement, phase D, 2026-11-26).
//
// A design measured for real on ONE GPU (vLLM in the pinned sandbox image),
// then scored on CPU in the pinned tool image. The stage code is the app's;
// what identity owns is the INSTRUMENT around it:
//
//   - pinned versions: exactly one GPU stage, on an accepted sandbox image;
//     every other stage on an accepted mlsys tool image;
//   - a free-GPU check against the site's FlowMesh workers before anything is
//     submitted, and a per-user GPU quota (one running, a daily budget);
//   - `not_measured` as a first-class answer with the reason in words — no
//     matching GPU, every one busy, over quota, or nobody picked the job up
//     within the queue timeout (the job is then cancelled, not left queued);
//   - never reused: a real GPU run is a fresh observation every time.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const sandboxDefaultQueueS = 900

// sandboxDefaultImages: tag=ref pairs; MEASURE_MLSYS_SANDBOX_IMAGES replaces them.
// sandbox-v0.2.1 (2026-11-28) measures several workloads per GPU session and
// has the Qwen3 0.6B/1.7B weights baked in; v0.1.0 stays accepted for installs
// that still pin it.
const sandboxDefaultImages = "sandbox-v0.1.0=ghcr.io/mlsys-io/hello-mlsys-agent-sandbox@sha256:" +
	"e9eaf0de8bf7d2c1f77618137c4f5a679906dbd681e47c8f7b822dee58236400," +
	"sandbox-v0.2.1=ghcr.io/mlsys-io/hello-mlsys-agent-sandbox@sha256:" +
	"96ee81521a5c776ef1911abac43aae13baf4e42577d0f108b2f49fab7e63a434," +
	// sandbox-v0.2.2: measures resampled workloads, sent as exact trace text + sha256.
	"sandbox-v0.2.2=ghcr.io/mlsys-io/hello-mlsys-agent-sandbox@sha256:" +
	"30dc8313a95cfbf9672a2bf5fb720ab25736d14d7b881167b81666ffc77f5040," +
	// sandbox-v0.2.3: energy per request on the card (NVML counter, idle-subtracted).
	"sandbox-v0.2.3=ghcr.io/mlsys-io/hello-mlsys-agent-sandbox@sha256:" +
	"90c4ddaa78ea40c47717efabc85afce206df7a371a80b7720f34519acb4d4029"

func sandboxImages() map[string]string {
	raw := strings.TrimSpace(os.Getenv("MEASURE_MLSYS_SANDBOX_IMAGES"))
	if raw == "" {
		raw = sandboxDefaultImages
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

func sandboxAcceptedTags() []string {
	tags := []string{}
	for _, t := range sandboxImages() {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func mlsysSandboxPlan(in map[string]any) (measurePlan, error) {
	text, _ := in["graph"].(string)
	if text == "" || len(text) > measureMaxInputBytes {
		return measurePlan{}, errors.New("graph is required: the FlowMesh graph (JSON) the sandbox runs")
	}
	var g map[string]any
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		return measurePlan{}, errors.New("graph must be a JSON FlowMesh graph")
	}
	spec, _ := g["spec"].(map[string]any)
	stages, _ := spec["stages"].([]any)
	if len(stages) == 0 {
		return measurePlan{}, errors.New("graph has no stages")
	}
	tools := mlsysImages()
	sandbox := sandboxImages()
	gpuStages, label, version := 0, "", ""
	for _, s := range stages {
		st, _ := s.(map[string]any)
		ss, _ := st["spec"].(map[string]any)
		image, _ := ss["image"].(string)
		res, _ := ss["resources"].(map[string]any)
		hw, _ := res["hardware"].(map[string]any)
		if _, wantsGPU := hw["gpu"]; wantsGPU {
			gpuStages++
			tag, ok := sandbox[image]
			if !ok {
				return measurePlan{}, fmt.Errorf("the GPU stage must run an accepted sandbox image (accepted: %s)",
					strings.Join(sandboxAcceptedTags(), ", "))
			}
			label, version = tag, image[strings.Index(image, "@")+1:]
			continue
		}
		if _, ok := tools[image]; !ok {
			return measurePlan{}, fmt.Errorf("stage %v must run an accepted mlsys tool image (accepted: %s)",
				st["name"], strings.Join(mlsysAcceptedTags(), ", "))
		}
	}
	if gpuStages != 1 {
		return measurePlan{}, fmt.Errorf("the sandbox measures on exactly one GPU stage (this graph has %d)", gpuStages)
	}
	site, _ := in["site"].(string)
	if site == "" {
		site = "office"
	}
	if !computeSiteRe.MatchString(site) {
		return measurePlan{}, errors.New("invalid site")
	}
	queue := sandboxDefaultQueueS
	if n, isNum := in["queue_timeout_s"].(json.Number); isNum {
		if v, err := n.Int64(); err == nil && v >= 60 && v <= measureMaxTimeoutS {
			queue = int(v)
		}
	}
	gpu, _ := in["gpu"].(map[string]any)
	wf, err := canonicalJSON(g)
	if err != nil {
		return measurePlan{}, err
	}
	meta, _ := g["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	material := map[string]any{"graph": g, "site": site, "gpu": gpu, "queue_timeout_s": queue, "once": lqtNonce()}
	return measurePlan{version: version, label: label, material: material, workflow: wf, site: site,
		name: fleetClip("measure mlsys-sandbox "+name, 128)}, nil
}

// sandboxPrecheck: quota, then a free matching GPU. "" = go ahead.
//
// wait=true is "not now": the caller's GPU slots are full (the smaller of the
// app's declared `compute.budget.parallel` and MEASURE_GPU_RUNNING_CAP), or
// every matching GPU is busy. Asking again later proceeds. The daily count
// and "no such GPU" are refusals.
func sandboxPrecheck(c *gin.Context, sub string, plan measurePlan, app, workflow string) (string, bool) {
	var running int64
	common.DB.Model(&models.MeasureResult{}).Where("executor_sub = ? AND instrument = ? AND status IN ?",
		sub, "mlsys-sandbox", []string{"queued", "running"}).Count(&running)
	limit := measureLimit("MEASURE_GPU_RUNNING_CAP", 2)
	if p := appParallel(sub, app, workflow); p > 0 && p < limit {
		limit = p
	}
	if running >= int64(limit) {
		return fmt.Sprintf("waiting for a GPU slot (%d of %d in use)", running, limit), true
	}
	// A measurement that never got a GPU (not_measured: no worker picked it up,
	// refused) used nothing, so it does not count against the day.
	var today int64
	common.DB.Model(&models.MeasureResult{}).Where("executor_sub = ? AND instrument = ? AND created_at > ? AND status <> ?",
		sub, "mlsys-sandbox", time.Now().Add(-24*time.Hour), "not_measured").Count(&today)
	if budget := gpuDailyBudget(sub); today >= int64(budget) {
		return fmt.Sprintf("your daily budget of %d GPU measurements is used; it resets over the next 24 hours", budget), false
	}
	req, _ := plan.material["gpu"].(map[string]any)
	total, idle, names, readable := sandboxGPUs(c, sub, plan.site, req)
	if !readable {
		return "", false // the queue timeout decides
	}
	words := sandboxGPUWords(req)
	if total == 0 {
		return fmt.Sprintf("no GPU worker at %s has %s", plan.site, words), false
	}
	if idle == 0 {
		return fmt.Sprintf("waiting for a free %s at %s (all %d busy: %s)",
			words, plan.site, total, strings.Join(names, ", ")), true
	}
	return "", false
}

func sandboxGPUWords(req map[string]any) string {
	if t, _ := req["type"].(string); t != "" {
		return t
	}
	if req["memory"] != nil {
		return "the requested GPU memory"
	}
	return "any GPU"
}

// sandboxGPUs reads the site's FlowMesh workers as the caller and counts the
// ones that can take the GPU stage, and the idle ones among them.
func sandboxGPUs(c *gin.Context, sub, site string, req map[string]any) (total, idle int, names []string, readable bool) {
	bearer, err := fleetReadBearer(sub, fleetKindFM)
	if err != nil {
		return 0, 0, nil, false
	}
	b, code := fleetDo(c.Request.Context(), fleetCall{method: http.MethodGet, bearer: bearer,
		url: fleetSiteBase(fleetKindFM, site) + "/api/v1/workers"})
	if code != http.StatusOK {
		return 0, 0, nil, false
	}
	var list []map[string]any
	if json.Unmarshal(b, &list) != nil {
		var wrapped map[string]any
		if json.Unmarshal(b, &wrapped) != nil {
			return 0, 0, nil, false
		}
		for _, k := range []string{"workers", "data"} {
			if raw, ok := wrapped[k].([]any); ok {
				for _, w := range raw {
					if m, ok := w.(map[string]any); ok {
						list = append(list, m)
					}
				}
				break
			}
		}
	}
	seen := map[string]bool{}
	for _, w := range list {
		if name, ok := sandboxWorkerMatches(w, req); ok {
			total++
			seen[name] = true
			if strings.EqualFold(fmt.Sprint(w["status"]), "IDLE") {
				idle++
			}
		}
	}
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return total, idle, names, true
}

// sandboxWorkerMatches mirrors the app's matches(): a non-cordoned, fresh
// python worker with a GPU of the requested type and memory.
func sandboxWorkerMatches(w map[string]any, req map[string]any) (string, bool) {
	if w["cordoned"] == true || w["stale"] == true {
		return "", false
	}
	caps, _ := w["capabilities"].(map[string]any)
	types, _ := caps["supported_task_types"].([]any)
	python := false
	for _, t := range types {
		python = python || t == "python"
	}
	if !python {
		return "", false
	}
	hw, _ := w["hardware"].(map[string]any)
	gpu, _ := hw["gpu"].(map[string]any)
	devices, _ := gpu["devices"].([]any)
	wantType, _ := req["type"].(string)
	wantMem := 0.0
	switch m := req["memory"].(type) {
	case json.Number:
		wantMem, _ = m.Float64()
	case float64:
		wantMem = m
	}
	for _, d := range devices {
		dev, _ := d.(map[string]any)
		name := fmt.Sprint(dev["name"])
		if wantType != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(wantType)) {
			continue
		}
		mem, _ := dev["memory_total_bytes"].(float64)
		// The app already shaves the requested size (a "24 GB" card reports
		// 23.9 GiB), so compare as given.
		if wantMem > 0 && mem < wantMem {
			continue
		}
		return name, true
	}
	return "", false
}

// sandboxQueueTimedOut cancels a sandbox job no GPU picked up in time and
// settles the row as not_measured. Called while the upstream says "queued".
func sandboxQueueTimedOut(c *gin.Context, row *models.MeasureResult, id fleetJobID, bearer string) bool {
	queue := sandboxDefaultQueueS
	if n, ok := lqtMaterial(row)["queue_timeout_s"].(json.Number); ok {
		if v, err := n.Int64(); err == nil && v > 0 {
			queue = int(v)
		}
	}
	if time.Since(row.ClaimedAt) <= time.Duration(queue)*time.Second {
		return false
	}
	fleetDo(c.Request.Context(), fleetCall{method: http.MethodPost, bearer: bearer,
		url: fleetSiteBase(id.Kind, id.Site) + "/api/v1/workflows/" + id.Native + "/cancel"})
	measureSettle(row, "not_measured", "", fmt.Sprintf(
		"no GPU worker at %s picked the job up within %d minutes, so it was cancelled; try again later",
		id.Site, queue/60))
	return true
}

// gpuDailyBudget: MEASURE_GPU_DAILY_BUDGET (default 12) GPU measurements per user
// per rolling 24 h, overridable per user with MEASURE_GPU_DAILY_BUDGET_USERS
// ("<sub>=<n>,<sub>=<n>"; a sub prefix of 8+ characters is enough). Operator
// decision 2026-11-28: a research round that has budget left (GPU-minutes) should
// not stall on the daily RATE for one named account.
func gpuDailyBudget(sub string) int {
	def := measureLimit("MEASURE_GPU_DAILY_BUDGET", 12)
	for _, pair := range strings.Split(os.Getenv("MEASURE_GPU_DAILY_BUDGET_USERS"), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		k = strings.TrimSpace(k)
		if !ok || len(k) < 8 || !strings.HasPrefix(sub, k) {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}
