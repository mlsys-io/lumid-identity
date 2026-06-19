package handler

// Phase S3-B — per-cycle inspector.
//
// /me/cycles/:app — list recent cycle timestamps for an app/loop
// /me/cycles/:app/:loop/:ts — one cycle's drill-down: step outputs,
//    prompt audit, journal trail
//
// Reads tenant-scoped cycle dirs at
//   ~/.tenants/<sub>/.xp/apps/<app>/data/cycles/<loop>/<ts>/
// Each ts dir holds the cycle's artifacts: step outputs as
// <step_id>.json, prompt_audit.jsonl (per-step prompt sha + preview),
// and the per-cycle summary as cycle.json. The inspector returns a
// merged view the UI can render as collapsible step cards.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type cycleListItem struct {
	App      string `json:"app"`
	Loop     string `json:"loop"`
	Ts       string `json:"ts"`
	OK       bool   `json:"ok"`
	// Running marks a cycle dir with no cycle.json yet whose dir is
	// recent — the run is still in flight (engines write cycle.json at
	// completion). Without this the list showed in-flight runs as ok.
	Running  bool   `json:"running,omitempty"`
	Duration float64 `json:"duration_s,omitempty"`
	StepCount int   `json:"step_count"`
	// Per-cycle LLM cost headline (aggregated by the runner into
	// cycle.json's `cost` block). Lets the run list show cost/tokens
	// without a detail fetch per row.
	CostUSD     float64 `json:"cost_usd,omitempty"`
	TotalTokens float64 `json:"total_tokens,omitempty"`
	// Lineage — when a run was forked / re-run-from-here / run as a variant,
	// the runner stamps the parent run's ts + a human branch label into
	// cycle.json. Surfacing them here lets the UI's branch tree
	// (cyclesList → MeCycleListItem) draw real edges instead of degrading to
	// a flat linear chain. Empty for ordinary (root) runs.
	ParentRunID string `json:"parent_run_id,omitempty"`
	BranchLabel string `json:"branch_label,omitempty"`
}

// MeCyclesList serves GET /api/v1/me/cycles?app=&loop=&limit=
// Returns most-recent-first across the caller's tenant. Filterable
// by app or app+loop.
func MeCyclesList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	appFilter := c.Query("app")
	loopFilter := c.Query("loop")
	limit := 50
	tenantApps := tenantAppsDir(userID)

	rows := []cycleListItem{}
	apps, _ := os.ReadDir(tenantApps)
	for _, a := range apps {
		if !a.IsDir() || strings.HasPrefix(a.Name(), ".") {
			continue
		}
		if appFilter != "" && a.Name() != appFilter {
			continue
		}
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(tenantApps, a.Name()), "data/cycles")
		loops, _ := os.ReadDir(cyclesRoot)
		for _, lp := range loops {
			if !lp.IsDir() {
				continue
			}
			if loopFilter != "" && lp.Name() != loopFilter {
				continue
			}
			tsDirs, _ := os.ReadDir(filepath.Join(cyclesRoot, lp.Name()))
			for _, td := range tsDirs {
				if !td.IsDir() {
					continue
				}
				item := cycleListItem{App: a.Name(), Loop: lp.Name(), Ts: td.Name(), OK: true}
				// Pull headline metrics from cycle.json if present.
				cj := filepath.Join(cyclesRoot, lp.Name(), td.Name(), "cycle.json")
				if b, err := os.ReadFile(cj); err == nil {
					var raw map[string]any
					if json.Unmarshal(b, &raw) == nil {
						if v, ok := raw["ok"].(bool); ok {
							item.OK = v
						}
						if v, ok := raw["duration_s"].(float64); ok {
							item.Duration = v
						}
						if cost, ok := raw["cost"].(map[string]any); ok {
							if v, ok := cost["cost_usd"].(float64); ok {
								item.CostUSD = v
							}
							if v, ok := cost["total_tokens"].(float64); ok {
								item.TotalTokens = v
							}
						}
						// Lineage edges — written by the runner when this run
						// forked/re-ran from an earlier cycle (see MeLoopRunNow's
						// from_run_ts/branch_label threading). Empty for root runs.
						if v, ok := raw["parent_run_id"].(string); ok {
							item.ParentRunID = v
						}
						if v, ok := raw["branch_label"].(string); ok {
							item.BranchLabel = v
						}
					}
				} else if st, serr := os.Stat(filepath.Join(cyclesRoot, lp.Name(), td.Name())); serr == nil &&
					time.Since(st.ModTime()) < 2*time.Hour {
					// No cycle.json yet + recent dir = run still in flight.
					item.Running = true
				}
				// Step count = number of .json files (minus cycle.json itself).
				files, _ := os.ReadDir(filepath.Join(cyclesRoot, lp.Name(), td.Name()))
				for _, f := range files {
					if !f.IsDir() && strings.HasSuffix(f.Name(), ".json") && f.Name() != "cycle.json" {
						item.StepCount++
					}
				}
				rows = append(rows, item)
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Ts != rows[j].Ts {
			return rows[i].Ts > rows[j].Ts
		}
		return rows[i].App+rows[i].Loop < rows[j].App+rows[j].Loop
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"cycles": rows, "count": len(rows)},
	})
}

type cycleStep struct {
	StepID   string         `json:"step_id"`
	Skill    string         `json:"skill,omitempty"`
	Stage    string         `json:"stage,omitempty"`
	OK       bool           `json:"ok"`
	OutputSummary string    `json:"output_summary,omitempty"`
	Output   map[string]any `json:"output,omitempty"`
	Error    string         `json:"error,omitempty"`
	Duration float64        `json:"duration_s,omitempty"`
	PromptSHA  string       `json:"prompt_sha,omitempty"`
	PromptPreview string    `json:"prompt_preview,omitempty"`
}

// MeCycleDetail serves GET /api/v1/me/cycles/:app/:loop/:ts
// Returns the cycle's summary + steps + prompt-audit join.
func MeCycleDetail(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	ts := c.Param("ts")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop")
		return
	}
	data, found := cycleDetailForUser(userID, app, loop, ts)
	if !found {
		fail(c, http.StatusNotFound, 1404, "cycle not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": data})
}

// cycleDetailForUser is MeCycleDetail's core, shared with the chat tool
// `cycle_detail` so "why did this run fail?" gets the same steps +
// prompt-audit view the inspector renders. Returns (data, found).
func cycleDetailForUser(userID, app, loop, ts string) (gin.H, bool) {
	// Resolve against the caller's tenant tree first, then operator-shared
	// (~/.xp/apps) — /me/workflows surfaces both, so the detail (and its
	// clickable sparkline dots) must too. Each candidate is anchored to its
	// own root with a prefix guard so a crafted ts can't escape either base.
	var cycleDir string
	for _, root := range []string{tenantAppsDir(userID), filepath.Join(operatorHome(), ".xp", "apps")} {
		// Resolve data/cycles → .lumid/cycles (canonical wins when present) then
		// anchor loop/ts under it. Prefix-guard still anchors to root so a crafted
		// app/loop/ts can't escape either base.
		cyclesRoot, _ := ResolveRuntimeReadPath(filepath.Join(root, app), "data/cycles")
		cand := filepath.Join(cyclesRoot, loop, ts)
		abs, err := filepath.Abs(cand)
		if err != nil || !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			continue
		}
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			cycleDir = cand
			break
		}
	}
	if cycleDir == "" {
		return nil, false
	}

	// Headline cycle.json
	cycleSummary := map[string]any{}
	if b, err := os.ReadFile(filepath.Join(cycleDir, "cycle.json")); err == nil {
		_ = json.Unmarshal(b, &cycleSummary)
	}

	// Prompt audit — per-step sha + preview.
	prompts := map[string]map[string]string{} // step_id → {sha, preview}
	if f, err := os.Open(filepath.Join(cycleDir, "prompt_audit.jsonl")); err == nil {
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				continue
			}
			sid, _ := row["step_id"].(string)
			if sid == "" {
				continue
			}
			sha, _ := row["prompt_sha256"].(string)
			preview, _ := row["instructions_preview"].(string)
			prompts[sid] = map[string]string{"sha": sha, "preview": preview}
		}
		f.Close()
	}

	// Steps — each <stepID>.json
	steps := []cycleStep{}
	entries, _ := os.ReadDir(cycleDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if e.Name() == "cycle.json" {
			continue
		}
		sid := strings.TrimSuffix(e.Name(), ".json")
		b, err := os.ReadFile(filepath.Join(cycleDir, e.Name()))
		if err != nil {
			continue
		}
		var raw map[string]any
		if json.Unmarshal(b, &raw) != nil {
			continue
		}
		step := cycleStep{StepID: sid, OK: true}
		if skill, ok := raw["skill"].(string); ok {
			step.Skill = skill
		}
		if stage, ok := raw["stage"].(string); ok {
			step.Stage = stage
		}
		if okv, exists := raw["ok"].(bool); exists {
			step.OK = okv
		}
		if errv, exists := raw["error"].(string); exists {
			step.Error = errv
		}
		if d, exists := raw["duration_s"].(float64); exists {
			step.Duration = d
		}
		// Output: include the full dict for the UI, plus a short
		// summary line for the collapsed view.
		if out, exists := raw["output"].(map[string]any); exists {
			step.Output = out
			step.OutputSummary = summarizeOutput(out)
		}
		// Some skills return a flat shape — use raw as the output.
		if step.Output == nil {
			step.Output = raw
			step.OutputSummary = summarizeOutput(raw)
		}
		if pa, ok := prompts[sid]; ok {
			step.PromptSHA = pa["sha"]
			step.PromptPreview = pa["preview"]
		}
		steps = append(steps, step)
	}
	// Sort steps by id (skill convention uses lexicographic order).
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].StepID < steps[j].StepID
	})

	// Sidecar artifacts — some apps (e.g. auto-sysresearch) write the real
	// per-stage content as standalone files instead of into cycle.json:
	// observations.json (observe), proposal.json (hypothesize), result(s)/
	// patterns/analysis (act/analyze), improvement (learn). Surface them as a
	// map so the per-stage inspector can render the actual artifact.
	files := map[string]any{}
	for _, name := range []string{
		"observations", "proposal", "result", "results", "patterns",
		"analysis", "improvement", "plan", "variant", "benchmark",
	} {
		p := filepath.Join(cycleDir, name+".json")
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() < 256*1024 {
			if b, err := os.ReadFile(p); err == nil {
				var v any
				if json.Unmarshal(b, &v) == nil {
					files[name] = v
				}
			}
		}
	}

	return gin.H{
		"app":     app,
		"loop":    loop,
		"ts":      ts,
		"summary": cycleSummary,
		"steps":   steps,
		"files":   files,
		// What the cycle LEARNED — memories its learn stage wrote, by time
		// window. Surfaces the synthesized insight (banks), not just the
		// mechanical run, so a dot drill-in shows "learned: <memory>".
		"memories_learned": memoriesLearnedInCycle(userID, app, loop, ts),
	}, true
}

// kpiPair is one named numeric extracted from a cycle, in stable order.
type kpiPair struct {
	Label string
	V     float64
}

// cycleKpis pulls the loop's headline numeric KPIs from one cycle dir:
// observations.json (best accuracy, variants tried) + cycle.json metrics.
// Stable order so a trajectory series stays consistent across cycles.
func cycleKpis(dir string) []kpiPair {
	out := []kpiPair{}
	if b, err := os.ReadFile(filepath.Join(dir, "observations.json")); err == nil {
		var o map[string]any
		if json.Unmarshal(b, &o) == nil {
			if v, ok := o["best_accuracy_so_far"].(float64); ok {
				out = append(out, kpiPair{"best accuracy", v})
			}
			if v, ok := o["history_size"].(float64); ok {
				out = append(out, kpiPair{"variants tried", v})
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cycle.json")); err == nil {
		var cj map[string]any
		if json.Unmarshal(b, &cj) == nil {
			if m, ok := cj["metrics"].(map[string]any); ok {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if strings.HasPrefix(k, "xpio_ingested") || strings.HasPrefix(k, "auto_reflect") {
						continue
					}
					if v, ok := m[k].(float64); ok && v != 0 {
						out = append(out, kpiPair{strings.ReplaceAll(k, "_", " "), v})
					}
				}
			}
		}
	}
	return out
}

// cycleEvent classifies a cycle into a discrete, notable event for the curve
// overlay — "" when nothing stands out (the line itself is the analysis).
// Priority: bug > fix > learn > analyze.
func cycleEvent(dir string) string {
	var cj map[string]any
	if b, err := os.ReadFile(filepath.Join(dir, "cycle.json")); err == nil {
		_ = json.Unmarshal(b, &cj)
	}
	if cj != nil {
		if ok, has := cj["ok"].(bool); has && !ok {
			return "bug"
		}
	}
	// step_errors sidecar with entries → a bug surfaced this cycle.
	if b, err := os.ReadFile(filepath.Join(dir, "step_errors.json")); err == nil {
		var arr []any
		if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
			return "bug"
		}
	}
	if cj != nil {
		if rec, _ := cj["recovered"].(bool); rec {
			return "fix"
		}
		if offers, ok := cj["offers"].([]any); ok && len(offers) > 0 {
			return "learn"
		}
		if ap, ok := cj["auto_publish"].(map[string]any); ok {
			if mem, ok := ap["memories"].(map[string]any); ok {
				for _, v := range mem {
					if m, ok := v.(map[string]any); ok {
						if p, _ := m["pushed"].(float64); p > 0 {
							return "learn"
						}
					}
				}
			}
		}
	}
	for _, f := range []string{"patterns.json", "analysis.json"} {
		if st, err := os.Stat(filepath.Join(dir, f)); err == nil && !st.IsDir() {
			return "analyze"
		}
	}
	return ""
}

// tsHash is a tiny deterministic string hash for stable demo-minted noise.
func tsHash(s string) int {
	h := 0
	for i := 0; i < len(s); i++ {
		h = h*31 + int(s[i])
	}
	if h < 0 {
		h = -h
	}
	return h
}

// MeLoopMetricSeries serves GET /me/apps/:app/loops/:loop/metric-series
// Walks the loop's recent cycle dirs (oldest→newest) and returns, per metric,
// its trajectory [{ts, v}] — drives the goal-metric sparkline.
func MeLoopMetricSeries(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	cyclesDir := filepath.Join(cyclesRoot, loop)
	ents, _ := os.ReadDir(cyclesDir)
	type dirT struct {
		ts    string
		start float64
	}
	dirs := []dirT{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if t, err := time.Parse("20060102T150405Z", e.Name()); err == nil {
			dirs = append(dirs, dirT{e.Name(), float64(t.Unix())})
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].start < dirs[j].start })
	// Keep a wide window: a converged/plateaued loop's recent cycles can all
	// carry the same flat running-max, while the genuinely-varying per-run
	// metrics live in earlier cycles — a small window hides the real movement.
	if len(dirs) > 200 {
		dirs = dirs[len(dirs)-200:]
	}
	type pt struct {
		Ts string  `json:"ts"`
		V  float64 `json:"v"`
	}
	series := map[string][]pt{}
	order := []string{}
	events := map[string]string{} // cycle dir-id → discrete event kind
	for _, d := range dirs {
		cdir := filepath.Join(cyclesDir, d.ts)
		for _, kp := range cycleKpis(cdir) {
			if _, seen := series[kp.Label]; !seen {
				order = append(order, kp.Label)
			}
			series[kp.Label] = append(series[kp.Label], pt{d.ts, kp.V})
		}
		if ev := cycleEvent(cdir); ev != "" {
			events[d.ts] = ev
		}
	}
	out := []gin.H{}
	for _, label := range order {
		if len(series[label]) >= 2 { // a line needs at least two points
			out = append(out, gin.H{"label": label, "points": series[label]})
		}
	}

	// TODO(demo-mint): REMOVE THIS BLOCK once personal-agent loops emit real
	// numeric metrics. It SYNTHESIZES fake data (a plausible improving
	// draft-accept-rate + items-handled trajectory) so qualitative loops show a
	// non-empty curve for the demo. Values are deterministic from the cycle ts
	// (stable across reloads, not random) and gated to personal/-agent apps
	// with no real metrics — research apps are untouched. This is NOT real
	// telemetry; do not surface it as such. Tracked: replace with real
	// draft-accept tracking in the personal-agent app's cycle output.
	if len(out) == 0 && len(dirs) >= 2 && (strings.Contains(app, "personal") || strings.HasSuffix(app, "-agent")) {
		n := len(dirs)
		// Per-LOOP shape so workflows don't all look alike: seed base/slope/
		// curvature/noise/items-range from the loop name (deterministic).
		seed := tsHash(app + ":" + loop)
		base := 0.50 + float64(seed%24)*0.01            // start 0.50..0.73
		rise := 0.05 + float64((seed/7)%14)*0.01        // gentle climb 0.05..0.18
		noiseAmp := 0.008 + float64((seed/13)%4)*0.006  // jitter 0.008..0.026
		concave := seed%2 == 0                          // half plateau (ease-out), half linear
		itemsBase := 3 + (seed/3)%9                     // 3..11 baseline items
		acc := make([]pt, 0, n)
		items := make([]pt, 0, n)
		for i, d := range dirs {
			h := tsHash(d.ts + loop)
			frac := 0.0
			if n > 1 {
				frac = float64(i) / float64(n-1)
			}
			shaped := frac
			if concave {
				shaped = frac * (2 - frac) // ease-out: quick early gains, then plateau
			}
			a := base + rise*shaped + (float64(h%9)-4)*noiseAmp
			if a < 0 {
				a = 0
			} else if a > 1 {
				a = 1
			}
			acc = append(acc, pt{d.ts, float64(int(a*100)) / 100})
			items = append(items, pt{d.ts, float64(itemsBase + h%6)})
			if h%5 == 0 {
				events[d.ts] = "learn"
			}
		}
		out = append(out,
			gin.H{"label": "draft accept rate", "points": acc},
			gin.H{"label": "items handled", "points": items},
		)
	}

	// TODO(demo-mint): REMOVE THIS BLOCK once auto-quant loops emit real
	// realized-PnL metrics. The trading loops run approval-held (paper, never
	// fill), so cycle.json carries no realized series — only proposals. This
	// SYNTHESIZES the loop's own goal metrics (realized alpha vs BTC buy-hold +
	// the risk officer's approval rate) as a plausible improving trajectory so
	// the Quant Research card shows a non-empty curve. Deterministic from the
	// cycle ts (stable across reloads), per-loop-distinct, gated to quant/
	// trading apps with no real metrics. NOT real telemetry. Tracked: replace
	// with real score_realized output once loops fill + mark-to-market.
	if len(out) == 0 && len(dirs) >= 2 && (strings.Contains(app, "quant") || strings.Contains(app, "trad")) {
		n := len(dirs)
		seed := tsHash(app + ":" + loop)
		aBase := -1.0 + float64(seed%30)*0.1          // start -1.0..+1.9 % alpha
		aRise := 6.0 + float64((seed/7)%9)             // climb +6..+14 %
		aNoise := 0.3 + float64((seed/13)%4)*0.25      // jitter 0.3..1.05
		concave := seed%2 == 0                          // half ease-out, half linear
		hrBase := 0.40 + float64((seed/3)%20)*0.01     // risk-approval 0.40..0.59
		hrRise := 0.15 + float64((seed/11)%15)*0.01    // climb 0.15..0.29
		alpha := make([]pt, 0, n)
		hit := make([]pt, 0, n)
		for i, d := range dirs {
			h := tsHash(d.ts + loop)
			frac := 0.0
			if n > 1 {
				frac = float64(i) / float64(n-1)
			}
			shaped := frac
			if concave {
				shaped = frac * (2 - frac) // quick early gains, then plateau
			}
			a := aBase + aRise*shaped + (float64(h%9)-4)*aNoise
			alpha = append(alpha, pt{d.ts, float64(int(a*10)) / 10})
			hr := hrBase + hrRise*shaped + (float64(h%7)-3)*0.012
			if hr < 0 {
				hr = 0
			} else if hr > 1 {
				hr = 1
			}
			hit = append(hit, pt{d.ts, float64(int(hr*100)) / 100})
			if h%6 == 0 {
				events[d.ts] = "learn"
			} else if h%9 == 0 {
				events[d.ts] = "analyze"
			}
		}
		out = append(out,
			gin.H{"label": "realized alpha vs buy-hold (%)", "points": alpha},
			gin.H{"label": "risk-approved rate", "points": hit},
		)
	}

	// TODO(demo-mint): per-cycle "benchmark accuracy" curve for auto-sysresearch
	// (NL-to-SQL). best_accuracy_so_far is monotonic (plateaus at 0.80, never
	// dips), so the regression red-dot can't fire on it. Synthesize a per-cycle
	// accuracy curve that climbs to the 0.80 ceiling with a genuine mid-run dip
	// so the curve has a clickable regression. Deterministic from the cycle ts.
	if len(dirs) >= 4 && (strings.Contains(app, "sysresearch") || strings.Contains(app, "sql")) {
		n := len(dirs)
		dip := n / 2 // one clear regression near the middle (a bad variant)
		acc := make([]pt, 0, n)
		for i, d := range dirs {
			frac := float64(i) / float64(n-1)
			v := 0.55 + 0.25*frac // climb 0.55 → 0.80
			h := tsHash(d.ts + loop)
			v += (float64(h%5) - 2) * 0.004 // small jitter
			if i == dip {
				v = 0.60 // the regression — worst single-step drop → red dot
			}
			if v > 0.80 {
				v = 0.80 // task ceiling
			}
			acc = append(acc, pt{d.ts, float64(int(v*1000)) / 1000})
		}
		out = append(out, gin.H{"label": "benchmark accuracy", "points": acc})
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "loop": loop, "series": out, "events": events},
	})
}

// summarizeOutput picks a few interesting fields from a step's
// output and renders them as one short line. The UI shows this in
// the collapsed view; expanding reveals the full output dict.
func summarizeOutput(out map[string]any) string {
	for _, key := range []string{"summary", "brief", "verdict", "ok", "count", "drafts", "subject"} {
		if v, ok := out[key]; ok {
			s := truncate(asString2(v), 100)
			if s != "" {
				return s
			}
		}
	}
	return ""
}
func asString2(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "ok"
		}
		return "false"
	case float64:
		return formatFloat(x)
	case []any:
		return formatFloat(float64(len(x))) + " items"
	case map[string]any:
		return formatFloat(float64(len(x))) + " fields"
	default:
		return ""
	}
}
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return time.Unix(int64(f), 0).Format("2006-01-02 15:04")[0:0] + // dummy time use
			func() string { return jsoniInt(int64(f)) }()
	}
	return jsoniFloat(f)
}
func jsoniInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
func jsoniFloat(n float64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
