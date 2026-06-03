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
	Duration float64 `json:"duration_s,omitempty"`
	StepCount int   `json:"step_count"`
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
		cyclesRoot := filepath.Join(tenantApps, a.Name(), "data", "cycles")
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
					}
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
	// Resolve against the caller's tenant tree first, then operator-shared
	// (~/.xp/apps) — /me/workflows surfaces both, so the detail (and its
	// clickable sparkline dots) must too. Each candidate is anchored to its
	// own root with a prefix guard so a crafted ts can't escape either base.
	var cycleDir string
	for _, root := range []string{tenantAppsDir(userID), filepath.Join(operatorHome(), ".xp", "apps")} {
		cand := filepath.Join(root, app, "data", "cycles", loop, ts)
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
		fail(c, http.StatusNotFound, 1404, "cycle not found")
		return
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

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":     app,
			"loop":    loop,
			"ts":      ts,
			"summary": cycleSummary,
			"steps":   steps,
			"files":   files,
		},
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
