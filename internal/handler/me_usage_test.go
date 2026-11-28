package handler

import (
	"testing"

	"lumid_identity/models"
)

func TestParseFleetUsageSumsGPUAndCPUTasks(t *testing.T) {
	body := []byte(`[
	 {"task":{"spec":{"resources":{"hardware":{"gpu":{"count":2}}}}},
	  "usages":[{"runtime_sec":100,"hardware":{"gpu":{"devices":[{"name":"NVIDIA GeForce RTX 5080"}]}}},
	            {"runtime_sec":20,"hardware":{"gpu":{"devices":[]}}}]},
	 {"task":{"spec":{"resources":{"hardware":{"cpu":"4"}}}},"usages":[{"runtime_sec":10,"hardware":{"gpu":{}}}]},
	 {"task":{},"usages":[{"runtime_sec":5,"hardware":{"gpu":{}}}]}
	]`)
	u := parseFleetUsage(body)
	// 120 s × 2 GPUs (a retry included); 10 s × 4 cores + 5 s × 1 core.
	if !u.Read || u.GPUS != 240 || u.CPUS != 45 || u.GPUType != "RTX 5080" || u.Metered != "measured" {
		t.Fatalf("usage = %+v", u)
	}
}

func TestParseFleetUsageFallsBackToWallTimeAsAnEstimate(t *testing.T) {
	u := parseFleetUsage([]byte(`[{"task":{"spec":{"resources":{"hardware":{"gpu":{"type":"RTX 5080"}}}}},
	  "started_ts":1000,"finished_ts":1300}]`))
	if u.GPUS != 300 || u.Metered != "estimated" {
		t.Fatalf("usage = %+v", u)
	}
	if bad := parseFleetUsage([]byte(`{"not":"a list"}`)); bad.Read {
		t.Fatalf("unreadable listing read as usage: %+v", bad)
	}
}

func TestUsageBlockReusedCostsNothingAndSaysWhatItSaved(t *testing.T) {
	g, c := 412.0, 8.0
	row := &models.MeasureResult{GPUS: &g, CPUS: &c, GPUType: "RTX 5080", Metered: "measured"}
	own := usageBlock(row, false)
	if own["gpu_s"] != 412.0 || own["metered"] != "measured" || own["cost_usd"].(float64) <= 0 {
		t.Fatalf("own = %v", own)
	}
	re := usageBlock(row, true)
	if re["gpu_s"] != 0.0 || re["cost_usd"] != 0.0 || re["saved_gpu_s"] != 412.0 || re["metered"] != "reused" {
		t.Fatalf("reused = %v", re)
	}
	if usageBlock(&models.MeasureResult{}, false) != nil {
		t.Fatal("an unmetered measurement must say nothing, not 0")
	}
}

func TestRatesOverrideAndMatchLongDeviceNames(t *testing.T) {
	t.Setenv("USAGE_RATES", `{"gpu_hour":{"RTX 5080":0.36},"cpu_core_hour":0.036}`)
	r := currentRates()
	if r.gpuRate("NVIDIA GeForce RTX 5080") != 0.36 || r.gpuRate("Mystery GPU") != 0.5 {
		t.Fatalf("rates = %+v", r)
	}
	if got := r.cost(3600, 100, "RTX 5080"); got != 0.361 {
		t.Fatalf("cost = %v", got)
	}
	t.Setenv("USAGE_RATES", "{broken")
	if currentRates().GPUHour["RTX 5080"] != 0.25 {
		t.Fatal("malformed USAGE_RATES must fall back to the defaults")
	}
	if shortGPUName("NVIDIA GeForce RTX 5080") != "RTX 5080" {
		t.Fatal("short name")
	}
}

func TestParseSpecBudgetsAppAndWorkflowLevels(t *testing.T) {
	sb := parseSpecBudgets([]byte(`
compute:
  site: office
  budget: {gpu_minutes: 168, per: total, parallel: 2}
workflows:
- id: sandbox
  compute: {budget: {gpu_minutes: 60, per: day, parallel: 1}}
- id: simulate
`))
	if sb.App.GPUMinutes != 168 || sb.App.Parallel != 2 || sb.App.Per != "total" {
		t.Fatalf("app = %+v", sb.App)
	}
	if w := sb.Workflows["sandbox"]; w.GPUMinutes != 60 || w.Per != "day" || w.Parallel != 1 {
		t.Fatalf("workflow = %+v", w)
	}
	if _, ok := sb.Workflows["simulate"]; ok {
		t.Fatal("a workflow without a budget has none")
	}
	if !parseSpecBudgets([]byte("::not yaml")).App.empty() {
		t.Fatal("bad yaml = no budget")
	}
}

func TestRequestedCount(t *testing.T) {
	for _, c := range []struct {
		in   any
		want float64
	}{{2.0, 2}, {"4", 4}, {map[string]any{"count": 3.0}, 3}, {map[string]any{"type": "RTX 5080"}, 1}, {nil, 0}} {
		if got := requestedCount(c.in); got != c.want {
			t.Errorf("requestedCount(%v) = %v", c.in, got)
		}
	}
}
