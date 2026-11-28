package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const testSandboxImage = "ghcr.io/mlsys-io/hello-mlsys-agent-sandbox@sha256:" +
	"3333333333333333333333333333333333333333333333333333333333333333"

func sandboxGraph(gpuImage, scoreImage string, gpuStages int) string {
	stages := []any{}
	for i := 0; i < gpuStages; i++ {
		stages = append(stages, map[string]any{"name": "measure", "spec": map[string]any{"taskType": "python",
			"image": gpuImage, "resources": map[string]any{"hardware": map[string]any{"gpu": map[string]any{"type": "RTX 5080"}}}}})
	}
	stages = append(stages, map[string]any{"name": "score", "dependsOn": []any{"measure"},
		"spec": map[string]any{"taskType": "python", "image": scoreImage}})
	b, _ := json.Marshal(map[string]any{"apiVersion": "flowmesh/v1", "kind": "Workflow",
		"metadata": map[string]any{"name": "mlsys-sandbox-9.2-c32"}, "spec": map[string]any{"stages": stages}})
	return string(b)
}

func sandboxInputs(graph string, extra string) map[string]any {
	b, _ := json.Marshal(graph)
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"graph":` + string(b) + extra + `}`))
	dec.UseNumber()
	_ = dec.Decode(&m)
	return m
}

func TestSandboxPlanEnforcesTheInstrument(t *testing.T) {
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	t.Setenv("MEASURE_MLSYS_SANDBOX_IMAGES", "st="+testSandboxImage)
	good := sandboxGraph(testSandboxImage, testSimImage, 1)
	p, err := mlsysSandboxPlan(sandboxInputs(good, ""))
	if err != nil {
		t.Fatal(err)
	}
	if p.label != "st" || p.site != "office" || !strings.HasPrefix(p.version, "sha256:3333") {
		t.Errorf("plan = %+v", p)
	}
	p2, _ := mlsysSandboxPlan(sandboxInputs(good, ""))
	if measureKey("mlsys-sandbox", p.version, p.material) == measureKey("mlsys-sandbox", p2.version, p2.material) {
		t.Error("two GPU runs share a key; a real measurement is never reused")
	}
	for name, g := range map[string]string{
		"no GPU stage":             sandboxGraph(testSandboxImage, testSimImage, 0),
		"two GPU stages":           sandboxGraph(testSandboxImage, testSimImage, 2),
		"unpinned sandbox image":   sandboxGraph("ghcr.io/x/sandbox:latest", testSimImage, 1),
		"tool stage on other code": sandboxGraph(testSandboxImage, "python:3.12", 1),
	} {
		if _, err := mlsysSandboxPlan(sandboxInputs(g, "")); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := mlsysSandboxPlan(map[string]any{"graph": "not json"}); err == nil {
		t.Error("non-JSON graph accepted")
	}
}

func TestSandboxWorkerMatches(t *testing.T) {
	w := func(name string, mem float64, extra map[string]any) map[string]any {
		m := map[string]any{"status": "IDLE", "capabilities": map[string]any{"supported_task_types": []any{"python"}},
			"hardware": map[string]any{"gpu": map[string]any{"devices": []any{
				map[string]any{"name": name, "memory_total_bytes": mem}}}}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	gib := float64(1 << 30)
	cases := []struct {
		name   string
		worker map[string]any
		req    map[string]any
		want   bool
	}{
		{"the card asked for", w("NVIDIA GeForce RTX 5080", 16*gib, nil), map[string]any{"type": "RTX 5080"}, true},
		{"another card", w("NVIDIA RTX PRO 4000", 24*gib, nil), map[string]any{"type": "RTX 5080"}, false},
		{"enough memory", w("NVIDIA RTX PRO 4000", 24*gib, nil), map[string]any{"memory": json.Number("24000000000")}, true},
		{"too little memory", w("NVIDIA GeForce RTX 5080", 16*gib, nil), map[string]any{"memory": json.Number("24000000000")}, false},
		{"cordoned", w("NVIDIA GeForce RTX 5080", 16*gib, map[string]any{"cordoned": true}), map[string]any{}, false},
		{"no python", w("NVIDIA GeForce RTX 5080", 16*gib, map[string]any{"capabilities": map[string]any{}}), map[string]any{}, false},
	}
	for _, tc := range cases {
		if _, got := sandboxWorkerMatches(tc.worker, tc.req); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

// ── The full flow against a fake FlowMesh (needs TEST_MYSQL_DSN) ────────

type fakeSandboxFM struct {
	mu      sync.Mutex
	workers string
	state   string // PENDING | DONE
	posts   int
	cancels int
}

func (f *fakeSandboxFM) handler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/fm/home/api/v1/workers":
		_, _ = w.Write([]byte(f.workers))
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows":
		f.posts++
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-sbx001","status":"PENDING"}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/workflows/wfl-sbx001":
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-sbx001","status":"` + f.state + `","task_ids":["tsk-m","tsk-s"]}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/tasks":
		// Usage records as FlowMesh keeps them: a GPU stage (one device) that
		// ran 412 s on a 5080, and a CPU scoring stage of 8 s.
		_, _ = w.Write([]byte(`[{"task_id":"tsk-m","task":{"metadata":{"name":"g:measure"},` +
			`"spec":{"resources":{"hardware":{"gpu":{"count":1,"type":"RTX 5080"}}}}},` +
			`"usages":[{"runtime_sec":412,"hardware":{"gpu":{"devices":[{"name":"NVIDIA GeForce RTX 5080"}]}}}]},` +
			`{"task_id":"tsk-s","task":{"metadata":{"name":"g:score"}},` +
			`"usages":[{"runtime_sec":8,"hardware":{"gpu":{"devices":[]}}}]}]`))
	case r.Method == "GET" && p == "/fm/home/api/v1/results/tsk-m":
		_, _ = w.Write([]byte(`{"task_type":"python","value":{"ok":true,"records":{"development":{}}}}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/results/tsk-s":
		_, _ = w.Write([]byte(`{"task_type":"python","value":{"ok":true,"results":[{"workload":"development"}]}}`))
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows/wfl-sbx001/cancel":
		f.cancels++
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

const idle5080 = `[{"status":"IDLE","capabilities":{"supported_task_types":["python"]},` +
	`"hardware":{"gpu":{"devices":[{"name":"NVIDIA GeForce RTX 5080","memory_total_bytes":17000000000}]}}}]`

func sandboxTestSetup(t *testing.T) (*fakeSandboxFM, string) {
	t.Helper()
	_, owner, _ := fleetTestSetup(t)
	f := &fakeSandboxFM{workers: idle5080, state: "PENDING"}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv("FLEET_BASE_URL", srv.URL)
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	t.Setenv("MEASURE_MLSYS_SANDBOX_IMAGES", "st="+testSandboxImage)
	measureCleanup(t, subOf(t, owner))
	return f, owner
}

func sandboxBody(extra string) string {
	g, _ := json.Marshal(sandboxGraph(testSandboxImage, testSimImage, 1))
	return `{"instrument":"mlsys-sandbox","app":"mlsys-research","inputs":{"graph":` + string(g) +
		`,"site":"home","gpu":{"type":"RTX 5080"}` + extra + `}}`
}

func TestSandboxSaysNotMeasuredBeforeTakingAGPU(t *testing.T) {
	f, owner := sandboxTestSetup(t)
	f.workers = strings.Replace(idle5080, `"IDLE"`, `"BUSY"`, 1)
	// Every matching GPU busy is "wait", not a refusal: nothing is claimed.
	code, got := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner)
	if code != http.StatusAccepted || got["status"] != "waiting" || !strings.Contains(got["reason"].(string), "busy") ||
		f.posts != 0 {
		t.Fatalf("busy = %d %v (submits %d)", code, got, f.posts)
	}
	f.workers = strings.Replace(idle5080, "RTX 5080", "RTX PRO 4000", 1)
	code, got = measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner)
	if code != 200 || got["status"] != "not_measured" || !strings.Contains(got["reason"].(string), "no GPU worker") {
		t.Fatalf("no match = %d %v", code, got)
	}
}

func TestSandboxRunsReturnsEveryStageAndIsNeverReused(t *testing.T) {
	f, owner := sandboxTestSetup(t)
	code, first := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner)
	if code != http.StatusAccepted || first["status"] != "running" || f.posts != 1 {
		t.Fatalf("submit = %d %v", code, first)
	}
	// Two GPU measurements at a time per user (MEASURE_GPU_RUNNING_CAP=2);
	// the third waits for a slot instead of failing.
	if code, again := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner); code != http.StatusAccepted ||
		again["status"] != "running" || f.posts != 2 {
		t.Fatalf("second while running = %d %v", code, again)
	}
	if code, third := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner); code != http.StatusAccepted ||
		third["status"] != "waiting" || !strings.Contains(third["reason"].(string), "2 of 2 in use") || f.posts != 2 {
		t.Fatalf("third while two run = %d %v", code, third)
	}
	f.state = "DONE"
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner)
	res, _ := got["result"].(map[string]any)
	values, _ := res["values"].(map[string]any)
	if code != 200 || got["status"] != "succeeded" || values["measure"] == nil || values["score"] == nil {
		t.Fatalf("settled = %d %v", code, got)
	}
	if res["share"] != "this run only" || res["measured_on"] != "mlsys-sandbox st" {
		t.Errorf("share/measured_on = %v / %v", res["share"], res["measured_on"])
	}
	// What it used, from the fleet's own usage records.
	use, _ := res["usage"].(map[string]any)
	if use["gpu_s"] != 412.0 || use["cpu_s"] != 8.0 || use["gpu_type"] != "RTX 5080" || use["metered"] != "measured" {
		t.Fatalf("usage = %v", use)
	}
	if c, _ := use["cost_usd"].(float64); c <= 0 {
		t.Fatalf("cost_usd = %v", use["cost_usd"])
	}
	// /me/usage charges it to this user's app, once.
	code, u := measureCall(t, "GET", "/api/v1/me/usage?app=mlsys-research", "", owner)
	used, _ := u["used"].(map[string]any)
	if code != 200 || used["gpu_s"] != 412.0 || used["runs"] != 1.0 || used["running"] != 1.0 {
		t.Fatalf("/me/usage = %d %v", code, u)
	}
}

func TestSandboxBudgetRefusesARunThatWouldGoOver(t *testing.T) {
	f, owner := sandboxTestSetup(t)
	sub := subOf(t, owner)
	spec := "name: mlsys-research\ncompute:\n  budget: {gpu_minutes: 10, per: total, parallel: 1}\n"
	common.DB.Save(&models.MeAppSpec{UserSub: sub, App: "mlsys-research", SpecYAML: spec, UpdatedAt: time.Now()})
	t.Cleanup(func() { common.DB.Where("user_sub = ?", sub).Delete(&models.MeAppSpec{}) })
	// parallel: 1 from the spec wins over the platform cap of 2.
	_, first := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner)
	if code, again := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner); code != http.StatusAccepted ||
		again["status"] != "waiting" || !strings.Contains(again["reason"].(string), "1 of 1") {
		t.Fatalf("parallel 1 = %d %v", code, again)
	}
	f.state = "DONE"
	measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner) // settles: 412 s used
	// The next run is estimated at 412 s; 412 + 412 > 600 s, so it is refused, in words.
	code, got := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(""), owner)
	if code != 200 || got["status"] != "not_measured" || got["budget"] != true ||
		!strings.Contains(got["reason"].(string), "GPU-min left") {
		t.Fatalf("over budget = %d %v", code, got)
	}
}

func TestSandboxNobodyPickingItUpIsCancelledAsNotMeasured(t *testing.T) {
	f, owner := sandboxTestSetup(t)
	_, first := measureCall(t, "POST", "/api/v1/me/measure", sandboxBody(`,"queue_timeout_s":60`), owner)
	key := first["key"].(string)
	common.DB.Model(&models.MeasureResult{}).Where("mkey = ?", key).Update("claimed_at", time.Now().Add(-2*time.Minute))
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+key, "", owner)
	if code != 200 || got["status"] != "not_measured" || !strings.Contains(got["reason"].(string), "cancelled") || f.cancels != 1 {
		t.Fatalf("timed out = %d %v (cancels %d)", code, got, f.cancels)
	}
}
