package handler

// Usage metering and compute budgets (2026-11-28).
//
// What a measurement actually used — GPU and CPU device-seconds, read from
// the fleet's own per-task usage records — is stored on its MeasureResult
// when it settles. Only the request that actually ran it is charged
// (ChargedRequestID); a request a cached or running result answered is
// charged nothing and is told what it saved.
//
// The contract is shared with the scheduler (LumidOS sdk/apps/usage.py):
//   - numbers: gpu_s, cpu_s, cost_usd, saved_gpu_s, saved_cpu_s
//   - words:   gpu_type, metered = measured | estimated | reused
//   - a field nobody measured is ABSENT, never 0.
//
// Rates are platform config (USAGE_RATES) and NOTIONAL: owned hardware has no
// bill, so the dollar figure is a unit for comparing CPU and GPU work, and
// every surface shows device-minutes first.
//
// Budgets are declared by the app (spec `compute.budget`, app-level and per
// workflow; both apply) and enforced here, where real spend happens.

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// usageDefaultRates: notional $/hour, the same defaults as LumidOS usage.py.
var usageDefaultRates = usageRates{
	CPUCoreHour: 0.02,
	GPUHour: map[string]float64{
		"RTX 5080": 0.25, "RTX 5090": 0.40, "RTX PRO 4000": 0.30, "RTX 6000 Ada": 0.80,
		"H100": 2.00, "H200": 2.50, "*": 0.50,
	},
	Notional: true,
}

type usageRates struct {
	CPUCoreHour float64            `json:"cpu_core_hour"`
	GPUHour     map[string]float64 `json:"gpu_hour"`
	Notional    bool               `json:"notional"`
}

// currentRates: USAGE_RATES (JSON) merged over the defaults; malformed → defaults.
func currentRates() usageRates {
	r := usageRates{CPUCoreHour: usageDefaultRates.CPUCoreHour, GPUHour: map[string]float64{},
		Notional: usageDefaultRates.Notional}
	for k, v := range usageDefaultRates.GPUHour {
		r.GPUHour[k] = v
	}
	raw := strings.TrimSpace(os.Getenv("USAGE_RATES"))
	if raw == "" {
		return r
	}
	var given struct {
		CPUCoreHour *float64           `json:"cpu_core_hour"`
		GPUHour     map[string]float64 `json:"gpu_hour"`
		Notional    *bool              `json:"notional"`
	}
	if json.Unmarshal([]byte(raw), &given) != nil {
		return r
	}
	if given.CPUCoreHour != nil && *given.CPUCoreHour >= 0 {
		r.CPUCoreHour = *given.CPUCoreHour
	}
	for k, v := range given.GPUHour {
		if v >= 0 {
			r.GPUHour[k] = v
		}
	}
	if given.Notional != nil {
		r.Notional = *given.Notional
	}
	return r
}

// gpuRate: exact name, else the longest known name inside the reported one
// ("NVIDIA GeForce RTX 5080" → "RTX 5080"), else "*".
func (r usageRates) gpuRate(gpuType string) float64 {
	if v, ok := r.GPUHour[gpuType]; ok && gpuType != "" {
		return v
	}
	low, best := strings.ToLower(gpuType), ""
	for k := range r.GPUHour {
		if k != "*" && gpuType != "" && strings.Contains(low, strings.ToLower(k)) && len(k) > len(best) {
			best = k
		}
	}
	if best != "" {
		return r.GPUHour[best]
	}
	return r.GPUHour["*"]
}

func (r usageRates) cost(gpuS, cpuS float64, gpuType string) float64 {
	usd := cpuS/3600*r.CPUCoreHour + gpuS/3600*r.gpuRate(gpuType)
	return math.Round(usd*1e6) / 1e6
}

// shortGPUName: the rate table's name for a device when one matches, so the
// UI reads "RTX 5080", not "NVIDIA GeForce RTX 5080".
func shortGPUName(name string) string {
	low, best := strings.ToLower(name), ""
	for k := range currentRates().GPUHour {
		if k != "*" && strings.Contains(low, strings.ToLower(k)) && len(k) > len(best) {
			best = k
		}
	}
	if best != "" {
		return best
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(name, "NVIDIA "), "GeForce "))
}

// fleetUsage is what one fleet workflow used.
type fleetUsage struct {
	GPUS, CPUS float64
	GPUType    string
	Metered    string // measured | estimated
	Read       bool
}

// fleetWorkflowUsage reads a FlowMesh workflow's tasks and sums their usage
// records: runtime × GPUs requested for a GPU task, runtime × CPU cores
// requested (1 when unstated) for a CPU task. A task with no usage record but
// start/finish stamps counts its wall time as an estimate.
func fleetWorkflowUsage(c *gin.Context, base, workflowID, bearer string) fleetUsage {
	b, code := fleetDo(c.Request.Context(), fleetCall{
		method: http.MethodGet, url: base + "/api/v1/tasks?workflow_id=" + url.QueryEscape(workflowID), bearer: bearer,
	})
	if code != http.StatusOK {
		return fleetUsage{}
	}
	return parseFleetUsage(b)
}

type fleetTaskUsageRow struct {
	Usages []struct {
		RuntimeSec float64 `json:"runtime_sec"`
		Hardware   struct {
			GPU struct {
				Devices []struct {
					Name string `json:"name"`
				} `json:"devices"`
			} `json:"gpu"`
		} `json:"hardware"`
	} `json:"usages"`
	StartedTS  *float64 `json:"started_ts"`
	FinishedTS *float64 `json:"finished_ts"`
	Task       struct {
		Spec struct {
			Resources struct {
				Hardware struct {
					CPU any `json:"cpu"`
					GPU any `json:"gpu"`
				} `json:"hardware"`
			} `json:"resources"`
		} `json:"spec"`
	} `json:"task"`
}

func parseFleetUsage(body []byte) fleetUsage {
	var tasks []fleetTaskUsageRow
	if json.Unmarshal(body, &tasks) != nil {
		return fleetUsage{}
	}
	out := fleetUsage{Read: true, Metered: "measured"}
	for _, t := range tasks {
		gpus := requestedCount(t.Task.Spec.Resources.Hardware.GPU)
		cores := requestedCount(t.Task.Spec.Resources.Hardware.CPU)
		if cores <= 0 {
			cores = 1
		}
		rt, name := 0.0, ""
		for _, u := range t.Usages {
			if u.RuntimeSec > 0 {
				rt += u.RuntimeSec
			}
			if name == "" && len(u.Hardware.GPU.Devices) > 0 {
				name = u.Hardware.GPU.Devices[0].Name
			}
		}
		if len(t.Usages) == 0 && t.StartedTS != nil && t.FinishedTS != nil && *t.FinishedTS > *t.StartedTS {
			rt = *t.FinishedTS - *t.StartedTS
			out.Metered = "estimated"
		}
		if rt <= 0 {
			continue
		}
		if gpus > 0 {
			out.GPUS += rt * gpus
			if out.GPUType == "" && name != "" {
				out.GPUType = shortGPUName(name)
			}
		} else {
			out.CPUS += rt * cores
		}
	}
	out.GPUS = math.Round(out.GPUS*1000) / 1000
	out.CPUS = math.Round(out.CPUS*1000) / 1000
	return out
}

// requestedCount reads a FlowMesh resource request: a number, a numeric
// string, or {count: n}. A GPU block with no count asks for one device.
func requestedCount(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		var f float64
		if _, err := fmt.Sscanf(x, "%g", &f); err == nil {
			return f
		}
	case map[string]any:
		if n, ok := x["count"]; ok {
			return requestedCount(n)
		}
		if len(x) > 0 {
			return 1
		}
	}
	return 0
}

// measureRecordUsage stores what a settled measurement used (best-effort).
func measureRecordUsage(c *gin.Context, row *models.MeasureResult, base, native, bearer string) {
	u := fleetWorkflowUsage(c, base, native, bearer)
	if !u.Read {
		return
	}
	upd := map[string]any{"metered": u.Metered, "gpu_type": fleetClip(u.GPUType, 64)}
	row.Metered, row.GPUType = u.Metered, fleetClip(u.GPUType, 64)
	if u.GPUS > 0 {
		v := u.GPUS
		row.GPUS, upd["gpu_s"] = &v, v
	}
	if u.CPUS > 0 {
		v := u.CPUS
		row.CPUS, upd["cpu_s"] = &v, v
	}
	common.DB.Model(row).Updates(upd)
}

// usageBlock: what a response tells the requester this measurement used.
// A reused answer used nothing and says what it saved. nil when unmetered.
func usageBlock(row *models.MeasureResult, reused bool) gin.H {
	if row.CostUSD != nil {
		return llmUsageBlock(row, reused)
	}
	if row.GPUS == nil && row.CPUS == nil {
		return nil
	}
	gpu, cpu := 0.0, 0.0
	if row.GPUS != nil {
		gpu = *row.GPUS
	}
	if row.CPUS != nil {
		cpu = *row.CPUS
	}
	out := gin.H{}
	if row.GPUType != "" {
		out["gpu_type"] = row.GPUType
	}
	if reused {
		out["gpu_s"], out["cpu_s"], out["cost_usd"] = 0.0, 0.0, 0.0
		if row.GPUS != nil {
			out["saved_gpu_s"] = gpu
		}
		if row.CPUS != nil {
			out["saved_cpu_s"] = cpu
		}
		out["metered"] = "reused"
		return out
	}
	if row.GPUS != nil {
		out["gpu_s"] = gpu
	}
	if row.CPUS != nil {
		out["cpu_s"] = cpu
	}
	out["cost_usd"] = currentRates().cost(gpu, cpu, row.GPUType)
	out["metered"] = row.Metered
	if row.Metered == "" {
		out["metered"] = "measured"
	}
	return out
}

// ── Estimates ────────────────────────────────────────────────────────────

// measureEstimate: the median usage of an instrument's last 20 settled,
// metered runs — what the next one will likely cost. ok=false with no history.
func measureEstimate(instrument string) (gpuS, cpuS float64, gpuType string, n int) {
	var rows []models.MeasureResult
	common.DB.Where("instrument = ? AND status IN ? AND (gpu_s IS NOT NULL OR cpu_s IS NOT NULL)",
		instrument, []string{"succeeded", "failed"}).
		Order("settled_at DESC").Limit(20).Find(&rows)
	if len(rows) == 0 {
		return 0, 0, "", 0
	}
	g, cp := []float64{}, []float64{}
	types := map[string]int{}
	for _, r := range rows {
		if r.GPUS != nil {
			g = append(g, *r.GPUS)
		}
		if r.CPUS != nil {
			cp = append(cp, *r.CPUS)
		}
		if r.GPUType != "" {
			types[r.GPUType]++
		}
	}
	for t, k := range types {
		if k > types[gpuType] {
			gpuType = t
		}
	}
	return median(g), median(cp), gpuType, len(rows)
}

// measureCostEstimate: the median own cost (cost_usd) of the instrument's last
// 20 settled measurements that recorded one (pooled-llm), and how many.
func measureCostEstimate(instrument string) (float64, int) {
	var costs []float64
	common.DB.Model(&models.MeasureResult{}).
		Where("instrument = ? AND status IN ? AND cost_usd IS NOT NULL", instrument, []string{"succeeded", "failed"}).
		Order("settled_at DESC").Limit(20).Pluck("cost_usd", &costs)
	return median(costs), len(costs)
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// ── Budgets ──────────────────────────────────────────────────────────────

// computeBudget: the spec's `compute.budget`. Zero fields are "no limit".
type computeBudget struct {
	GPUMinutes float64 `yaml:"gpu_minutes" json:"gpu_minutes,omitempty"`
	CPUMinutes float64 `yaml:"cpu_minutes" json:"cpu_minutes,omitempty"`
	USD        float64 `yaml:"usd" json:"usd,omitempty"`
	Per        string  `yaml:"per" json:"per,omitempty"` // total | day | week
	Parallel   int     `yaml:"parallel" json:"parallel,omitempty"`
}

func (b computeBudget) empty() bool {
	return b.GPUMinutes <= 0 && b.CPUMinutes <= 0 && b.USD <= 0 && b.Parallel <= 0
}

// since: the start of the budget's current window.
func (b computeBudget) since(now time.Time) time.Time {
	switch b.Per {
	case "day":
		return now.Add(-24 * time.Hour)
	case "week":
		return now.Add(-7 * 24 * time.Hour)
	}
	return time.Time{}
}

type specBudgets struct {
	App       computeBudget
	Workflows map[string]computeBudget
}

// parseSpecBudgets reads `compute.budget` at app level and per workflow.
func parseSpecBudgets(specYAML []byte) specBudgets {
	var doc struct {
		Compute struct {
			Budget computeBudget `yaml:"budget"`
		} `yaml:"compute"`
		Workflows []struct {
			ID      string `yaml:"id"`
			Compute struct {
				Budget computeBudget `yaml:"budget"`
			} `yaml:"compute"`
		} `yaml:"workflows"`
	}
	out := specBudgets{Workflows: map[string]computeBudget{}}
	if yaml.Unmarshal(specYAML, &doc) != nil {
		return out
	}
	out.App = doc.Compute.Budget
	for _, w := range doc.Workflows {
		if w.ID != "" && !w.Compute.Budget.empty() {
			out.Workflows[w.ID] = w.Compute.Budget
		}
	}
	return out
}

// appBudgets: the caller's installed spec for app (the stored echo, else the
// published bundle), parsed. Empty when the app declares none.
func appBudgets(sub, app string) specBudgets {
	if app == "" {
		return specBudgets{}
	}
	if row := storedAppSpec(sub, app); row != nil {
		return parseSpecBudgets([]byte(row.SpecYAML))
	}
	if b, ok := fetchRepoSpecYAML(sub, app); ok {
		return parseSpecBudgets(b)
	}
	return specBudgets{}
}

// spent sums what the caller's charged measurements for app (and workflow,
// when given) used since t.
type spent struct {
	GPUS, CPUS, USD          float64
	SavedGPUS, SavedCPUS     float64
	SavedUSD                 float64 // pooled-llm answers reused instead of paid again
	TokensIn, TokensOut      int     // pooled-llm calls this user paid for
	Runs, Reused, Unmetered  int
	Running                  int
	ByDevice                 map[string]float64
	ByWorkflow, ByInstrument map[string]gin.H
	ByDay                    map[string]float64
}

func usageSpent(sub, app, workflow string, t time.Time) spent {
	type joined struct {
		ReqID      uint      `gorm:"column:req_id"`
		Workflow   string    `gorm:"column:workflow"`
		Instrument string    `gorm:"column:instrument"`
		Charged    uint      `gorm:"column:charged"`
		Outcome    string    `gorm:"column:outcome"`
		Status     string    `gorm:"column:status"`
		GPUS       *float64  `gorm:"column:gpu_s"`
		CPUS       *float64  `gorm:"column:cpu_s"`
		GPUType    string    `gorm:"column:gpu_type"`
		CostUSD    *float64  `gorm:"column:cost_usd"` // a pooled-llm call's own cost
		TokensIn   *int      `gorm:"column:tokens_in"`
		TokensOut  *int      `gorm:"column:tokens_out"`
		CreatedAt  time.Time `gorm:"column:created_at"`
	}
	q := common.DB.Table("measure_requests AS q").
		Select("q.id AS req_id, q.workflow, r.instrument, r.charged_request_id AS charged, q.outcome, r.status, r.gpu_s AS gpu_s, "+
			"r.cpu_s AS cpu_s, r.gpu_type, r.cost_usd AS cost_usd, r.tokens_in AS tokens_in, r.tokens_out AS tokens_out, q.created_at").
		Joins("JOIN measure_results AS r ON r.mkey = q.mkey").
		Where("q.user_sub = ? AND q.outcome IN ?", sub, []string{"submitted", "fresh", "cached", "joined"})
	if !t.IsZero() {
		q = q.Where("q.created_at >= ?", t)
	}
	if app != "" {
		q = q.Where("q.app = ?", app)
	}
	if workflow != "" {
		q = q.Where("q.workflow = ?", workflow)
	}
	var rows []joined
	q.Scan(&rows)
	rates := currentRates()
	s := spent{ByDevice: map[string]float64{}, ByWorkflow: map[string]gin.H{}, ByInstrument: map[string]gin.H{},
		ByDay: map[string]float64{}}
	for _, r := range rows {
		gpu, cpu := 0.0, 0.0
		if r.GPUS != nil {
			gpu = *r.GPUS
		}
		if r.CPUS != nil {
			cpu = *r.CPUS
		}
		// Rows from before ChargedRequestID existed: the submitting request paid.
		charged := r.Charged == r.ReqID || (r.Charged == 0 && (r.Outcome == "submitted" || r.Outcome == "fresh"))
		if !charged {
			s.Reused++
			s.SavedGPUS += gpu
			s.SavedCPUS += cpu
			if r.CostUSD != nil {
				s.SavedUSD += *r.CostUSD
			}
			continue
		}
		if r.Status == "queued" || r.Status == "running" {
			s.Running++
			continue
		}
		s.Runs++
		if r.GPUS == nil && r.CPUS == nil && r.CostUSD == nil {
			s.Unmetered++
			continue
		}
		usd := rates.cost(gpu, cpu, r.GPUType)
		if r.CostUSD != nil {
			usd += *r.CostUSD
		}
		if r.TokensIn != nil {
			s.TokensIn += *r.TokensIn
		}
		if r.TokensOut != nil {
			s.TokensOut += *r.TokensOut
		}
		s.GPUS += gpu
		s.CPUS += cpu
		s.USD += usd
		if gpu > 0 {
			dev := r.GPUType
			if dev == "" {
				dev = "GPU"
			}
			s.ByDevice[dev] += gpu
		}
		if cpu > 0 {
			s.ByDevice["CPU"] += cpu
		}
		for _, kv := range []struct {
			m   map[string]gin.H
			key string
		}{{s.ByWorkflow, r.Workflow}, {s.ByInstrument, r.Instrument}} {
			k := kv.key
			if k == "" {
				k = "(unnamed)"
			}
			cur := kv.m[k]
			if cur == nil {
				cur = gin.H{"gpu_s": 0.0, "cpu_s": 0.0, "cost_usd": 0.0, "runs": 0}
			}
			cur["gpu_s"] = cur["gpu_s"].(float64) + gpu
			cur["cpu_s"] = cur["cpu_s"].(float64) + cpu
			cur["cost_usd"] = math.Round((cur["cost_usd"].(float64)+usd)*1e6) / 1e6
			cur["runs"] = cur["runs"].(int) + 1
			kv.m[k] = cur
		}
		s.ByDay[r.CreatedAt.UTC().Format("2006-01-02")] += gpu
	}
	return s
}

// budgetRefusal: words when a fresh measurement of instrument would take
// the app (or workflow) over its budget; "" when it fits or nothing is set.
func budgetRefusal(sub, app, workflow, instrument, appLabel string) string {
	if app == "" {
		return ""
	}
	sb := appBudgets(sub, app)
	gpuEst, cpuEst, gpuType, _ := measureEstimate(instrument)
	usdEst := currentRates().cost(gpuEst, cpuEst, gpuType)
	// A pooled-llm call has no device time; its own cost is the estimate.
	if llmUSD, k := measureCostEstimate(instrument); k > 0 {
		usdEst += llmUSD
	}
	check := func(b computeBudget, scope, wf string) string {
		if b.empty() {
			return ""
		}
		s := usageSpent(sub, app, wf, b.since(time.Now()))
		// Over when already spent, or when the usual run would take it over.
		// With no history the estimate is 0 and only "already spent" applies.
		if b.GPUMinutes > 0 && (s.GPUS >= b.GPUMinutes*60 || (gpuEst > 0 && s.GPUS+gpuEst > b.GPUMinutes*60)) {
			left := math.Max(0, b.GPUMinutes-s.GPUS/60)
			return fmt.Sprintf("%s has %s of %s GPU-min left; this run takes about %s",
				scope, fmtMin(left), fmtMin(b.GPUMinutes), fmtMin(gpuEst/60))
		}
		if b.CPUMinutes > 0 && (s.CPUS >= b.CPUMinutes*60 || (cpuEst > 0 && s.CPUS+cpuEst > b.CPUMinutes*60)) {
			left := math.Max(0, b.CPUMinutes-s.CPUS/60)
			return fmt.Sprintf("%s has %s of %s CPU-min left; this run takes about %s",
				scope, fmtMin(left), fmtMin(b.CPUMinutes), fmtMin(cpuEst/60))
		}
		if b.USD > 0 && (s.USD >= b.USD || (usdEst > 0 && s.USD+usdEst > b.USD)) {
			return fmt.Sprintf("%s has $%.2f of $%.2f left; this run costs about $%.2f",
				scope, math.Max(0, b.USD-s.USD), b.USD, usdEst)
		}
		return ""
	}
	if why := check(sb.App, "Your "+appLabel+" budget", ""); why != "" {
		return why
	}
	if wb, ok := sb.Workflows[workflow]; ok {
		if why := check(wb, "The "+workflow+" workflow's budget", workflow); why != "" {
			return why
		}
	}
	return ""
}

// appParallel: the app's (or workflow's) declared parallel limit, 0 = none.
func appParallel(sub, app, workflow string) int {
	sb := appBudgets(sub, app)
	p := sb.App.Parallel
	if wb, ok := sb.Workflows[workflow]; ok && wb.Parallel > 0 && (p == 0 || wb.Parallel < p) {
		p = wb.Parallel
	}
	return p
}

func fmtMin(m float64) string {
	switch {
	case m < 1:
		return "under a minute"
	case m < 10:
		return fmt.Sprintf("%.1f min", m)
	}
	return fmt.Sprintf("%.0f min", m)
}

// ── GET /me/usage, GET /me/usage/rates ──────────────────────────────────

// MeUsage: what the caller's measurements used, for one app or all of them,
// against the app's declared budget.
//
//	GET /api/v1/me/usage?app=<name>&since=<RFC3339>
func MeUsage(c *gin.Context) {
	sub, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := strings.TrimSpace(c.Query("app"))
	if app != "" && !fleetLabelRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	sb := appBudgets(sub, app)
	since := sb.App.since(time.Now())
	if raw := c.Query("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			fail(c, http.StatusBadRequest, 1400, "since must be RFC3339")
			return
		}
		since = t
	}
	s := usageSpent(sub, app, "", since)
	used := gin.H{"gpu_s": round3(s.GPUS), "cpu_s": round3(s.CPUS), "cost_usd": math.Round(s.USD*1e6) / 1e6,
		"tokens_in": s.TokensIn, "tokens_out": s.TokensOut,
		"runs": s.Runs, "running": s.Running, "unmetered_runs": s.Unmetered, "by_device": s.ByDevice, "by_workflow": s.ByWorkflow,
		"by_instrument": s.ByInstrument, "by_day": s.ByDay}
	out := gin.H{"app": app, "since": nil, "used": used,
		"saved": gin.H{"gpu_s": round3(s.SavedGPUS), "cpu_s": round3(s.SavedCPUS), "reused_runs": s.Reused,
			"cost_usd": math.Round(s.SavedUSD*1e6) / 1e6},
		"rates": currentRates()}
	if !since.IsZero() {
		out["since"] = since.UTC().Format(time.RFC3339)
	}
	if !sb.App.empty() {
		out["budget"] = sb.App
		rem := gin.H{}
		if sb.App.GPUMinutes > 0 {
			rem["gpu_s"] = round3(math.Max(0, sb.App.GPUMinutes*60-s.GPUS))
		}
		if sb.App.CPUMinutes > 0 {
			rem["cpu_s"] = round3(math.Max(0, sb.App.CPUMinutes*60-s.CPUS))
		}
		if sb.App.USD > 0 {
			rem["cost_usd"] = math.Max(0, sb.App.USD-s.USD)
		}
		out["remaining"] = rem
	}
	if len(sb.Workflows) > 0 {
		wf := gin.H{}
		for id, b := range sb.Workflows {
			ws := usageSpent(sub, app, id, b.since(time.Now()))
			wf[id] = gin.H{"budget": b, "used": gin.H{"gpu_s": round3(ws.GPUS), "cpu_s": round3(ws.CPUS),
				"cost_usd": math.Round(ws.USD*1e6) / 1e6, "runs": ws.Runs}}
		}
		out["workflows"] = wf
	}
	ests := gin.H{}
	for name := range measureRegistry {
		if g, cp, t, n := measureEstimate(name); n > 0 {
			ests[name] = gin.H{"gpu_s": round3(g), "cpu_s": round3(cp), "gpu_type": t, "from_runs": n,
				"cost_usd": currentRates().cost(g, cp, t)}
		}
	}
	out["estimates"] = ests
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "", "data": out})
}

// MeUsageRates: the platform's per-device rates (notional).
func MeUsageRates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "", "data": currentRates()})
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }
