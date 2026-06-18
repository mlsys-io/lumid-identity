package handler

// Chat-tool implementations for the observability surface (C3). The
// Studio pages render this data via /me/* HTTP endpoints; these wrappers
// expose the SAME internals to the chat agent so "why did this run
// fail?" / "how are my workflows doing?" resolve in-conversation.
//
// Read-only tools: cycle_detail, loops_health, experiment_case,
// loop_metric_series, app_config_get.
// Mutating (approval-gated via destructiveTools): review_action,
// app_config_set.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// toolCycleDetail — the run inspector's view: steps with status/output/
// error + prompt audit + sidecar artifacts. ts may be "latest".
func toolCycleDetail(userID, app, loop, ts string) (map[string]any, bool) {
	if app == "" || loop == "" {
		return map[string]any{"error": "app and loop required"}, false
	}
	if ts == "" || ts == "latest" {
		resolved, err := agentLatestCycleTs(userID, app, loop)
		if err != nil {
			return map[string]any{"error": "no runs found for " + app + "/" + loop}, false
		}
		ts = resolved
	}
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		return map[string]any{"error": "invalid app or loop"}, false
	}
	data, found := cycleDetailForUser(userID, app, loop, ts)
	if !found {
		return map[string]any{"error": "run not found: " + app + "/" + loop + "/" + ts}, false
	}
	return map[string]any(data), true
}

// toolLoopsHealth — compact per-workflow health rows (the same scheduler
// state + journal truth the NeedsAttentionRail renders): status
// (never|ok|failing|stale|manual), consecutive failures, last error.
func toolLoopsHealth(userID string) (map[string]any, bool) {
	home := operatorHome()
	state := readSchedulerState(home)
	apps := discoverManifestLoops(home)
	now := time.Now().Unix()

	type row struct {
		App                 string `json:"app"`
		Loop                string `json:"loop"`
		Schedule            string `json:"schedule,omitempty"`
		Status              string `json:"status"`
		ConsecutiveFailures int    `json:"consecutive_failures,omitempty"`
		LastRunTS           int64  `json:"last_run_ts,omitempty"`
		LastError           string `json:"last_error,omitempty"`
	}
	rows := []row{}
	for _, app := range apps {
		for _, L := range app.Loops {
			s := state.Loops["xpio:"+app.App+":"+L.Name]
			r := row{
				App: app.App, Loop: L.Name, Schedule: L.Schedule,
				ConsecutiveFailures: s.ConsecutiveFailures,
				LastRunTS:           int64(s.LastRunTS),
			}
			switch {
			case L.Schedule == "" || L.Schedule == "@trigger" || L.Schedule == "manual":
				r.Status = "manual"
			case s.LastRunTS == 0:
				r.Status = "never"
			case s.ConsecutiveFailures > 0:
				r.Status = "failing"
			case now-int64(s.LastRunTS) > 60*60*48:
				r.Status = "stale"
			default:
				r.Status = "ok"
			}
			if r.Status == "failing" {
				if _, latestPath, _ := loadLoopDetail(home, app.App, L.Name); latestPath != "" {
					appDir := filepath.Join(home, ".xp", "apps", app.App)
					if errs, _ := loadLastErrors(latestPath, appDir); len(errs) > 0 {
						r.LastError = errs[0].Error
					}
				}
			}
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		// Failures first — that's what the agent is usually asked about.
		pi := map[string]int{"failing": 0, "stale": 1, "ok": 2, "never": 3, "manual": 4}
		if pi[rows[i].Status] != pi[rows[j].Status] {
			return pi[rows[i].Status] < pi[rows[j].Status]
		}
		return rows[i].App+rows[i].Loop < rows[j].App+rows[j].Loop
	})
	summary := map[string]int{}
	for _, r := range rows {
		summary[r.Status]++
	}
	return map[string]any{"loops": rows, "summary": summary}, true
}

// toolReviewAction — approve / revamp / dismiss an item in a run's
// review queue. Approval-gated (destructiveTools).
func toolReviewAction(userID string, args map[string]any) (map[string]any, bool) {
	app, _ := args["app"].(string)
	loop, _ := args["loop"].(string)
	decision, _ := args["decision"].(string)
	if app == "" || loop == "" || decision == "" {
		return map[string]any{"error": "app, loop, and decision (approve|revamp|dismiss) required"}, false
	}
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		return map[string]any{"error": "invalid app or loop"}, false
	}
	body := cycleReviewBody{Decision: decision}
	if v, ok := args["step_id"].(string); ok {
		body.StepID = v
	}
	if v, ok := args["step_instructions"].(string); ok {
		body.StepInstructions = v
	}
	if v, ok := args["outbox_ref"].(string); ok {
		body.OutboxRef = v
	}
	if code, msg := applyCycleReview(userID, app, loop, body); code != 0 {
		return map[string]any{"error": msg}, false
	}
	return map[string]any{"app": app, "loop": loop, "decision": decision, "applied": true}, true
}

// toolExperimentCase — one experiment case's rows + latest-by-question
// (mirrors MeAppExperimentCase).
func toolExperimentCase(userID, app, id, caseID string) (map[string]any, bool) {
	if app == "" || id == "" || caseID == "" {
		return map[string]any{"error": "app, experiment id, and case_id required"}, false
	}
	if !slugRe.MatchString(app) || !slugRe.MatchString(id) || !slugRe.MatchString(caseID) {
		return map[string]any{"error": "invalid path"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	rows := readExpRows(appDir, id, expResultsTailCap)
	caseRows := []expRow{}
	latestByQ := map[string]any{}
	for _, r := range rows {
		if r.Dims["case_id"] != caseID {
			continue
		}
		caseRows = append(caseRows, r)
		if q := r.Dims["q_id"]; q != "" {
			latestByQ[q] = map[string]any{"ts": r.TS, "metrics": r.Metrics}
		}
	}
	return map[string]any{"case_id": caseID, "rows": caseRows, "latest_by_question": latestByQ}, true
}

// toolCasebook — the data casebook a workflow's goal metrics are scored on
// (mirrors MeCasebook): per-case latest score + history + metric evolution,
// scoped to the loop's declared experiment. Reuses the same builder funcs.
func toolCasebook(userID, app, loop string) (map[string]any, bool) {
	if app == "" {
		return map[string]any{"error": "app required"}, false
	}
	if !slugRe.MatchString(app) || (loop != "" && !slugRe.MatchString(loop)) {
		return map[string]any{"error": "invalid app or loop"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	expAllow := map[string]bool{}
	for _, x := range loopExperiments(appDir, loop) {
		expAllow[x] = true
	}
	scores, metricEvo := casebookScoresFromExperiments(appDir, expAllow, loop != "")
	cases := casebookRoster(appDir, scores)
	return map[string]any{
		"app": app, "loop": loop,
		"cases": cases, "metrics_evolution": metricEvo,
		"version_history": casebookVersionHistory(appDir, loop),
	}, true
}

// toolLoopMetricSeries — a workflow's KPI trajectory over its recent
// runs (compact window for chat: last 50 cycles).
func toolLoopMetricSeries(userID, app, loop string) (map[string]any, bool) {
	if app == "" || loop == "" {
		return map[string]any{"error": "app and loop required"}, false
	}
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		return map[string]any{"error": "invalid app or loop"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	cyclesDir := filepath.Join(appDir, "data", "cycles", loop)
	ents, _ := os.ReadDir(cyclesDir)
	dirs := []string{}
	for _, e := range ents {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) > 50 {
		dirs = dirs[len(dirs)-50:]
	}
	type pt struct {
		Ts string  `json:"ts"`
		V  float64 `json:"v"`
	}
	series := map[string][]pt{}
	order := []string{}
	for _, d := range dirs {
		for _, kp := range cycleKpis(filepath.Join(cyclesDir, d)) {
			if _, seen := series[kp.Label]; !seen {
				order = append(order, kp.Label)
			}
			series[kp.Label] = append(series[kp.Label], pt{d, kp.V})
		}
	}
	out := []map[string]any{}
	for _, label := range order {
		out = append(out, map[string]any{"label": label, "points": series[label]})
	}
	return map[string]any{"app": app, "loop": loop, "series": out, "cycles_scanned": len(dirs)}, true
}

// toolKnowledgeAgents — the CALLER's knowledge agents (tenant-scoped).
// The xp_agents bridge tool is operator-scoped (dispatchLumidosTool
// carries no user identity), so tenant chat must use this instead.
func toolKnowledgeAgents(userID string) (map[string]any, bool) {
	kgRoot := filepath.Join(operatorHome(), ".tenants", userID, ".xp", "kg", "agents")
	type row struct {
		ID    string `json:"id"`
		Count int    `json:"memory_count"`
	}
	rows := []row{}
	dirs, err := os.ReadDir(kgRoot)
	if err == nil {
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			bank := filepath.Join(kgRoot, d.Name(), "bank.jsonl")
			b, err := os.ReadFile(bank)
			if err != nil {
				continue
			}
			n := 0
			for _, c := range b {
				if c == '\n' {
					n++
				}
			}
			rows = append(rows, row{ID: d.Name(), Count: n})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return map[string]any{"agents": rows, "count": len(rows)}, true
}

// toolKnowledgeMemories — newest memories from one of the CALLER's
// agent banks (tenant-scoped twin of the operator xp_memories bridge).
func toolKnowledgeMemories(userID, agent string, limit int) (map[string]any, bool) {
	if agent == "" || !slugRe.MatchString(agent) {
		return map[string]any{"error": "valid agent id required"}, false
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	bankPath := filepath.Join(operatorHome(), ".tenants", userID, ".xp", "kg", "agents", agent, "bank.jsonl")
	abs, _ := filepath.Abs(bankPath)
	if !startsWithPath(abs, filepath.Join(operatorHome(), ".tenants", userID)) {
		return map[string]any{"error": "invalid path"}, false
	}
	b, err := os.ReadFile(bankPath)
	if err != nil {
		return map[string]any{"error": "bank not found for agent " + agent}, false
	}
	lines := splitNonEmptyLines(string(b))
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	memories := make([]json.RawMessage, 0, len(lines))
	for _, l := range lines {
		memories = append(memories, json.RawMessage(l))
	}
	return map[string]any{"agent": agent, "memories": memories, "returned": len(memories)}, true
}

func startsWithPath(p, root string) bool {
	return p == root || len(p) > len(root) && p[:len(root)+1] == root+string(os.PathSeparator)
}

func splitNonEmptyLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// toolAppConfigGet — the app's xpcloud.yaml (runtime source of truth).
func toolAppConfigGet(userID, app string) (map[string]any, bool) {
	if app == "" || !slugRe.MatchString(app) {
		return map[string]any{"error": "valid app required"}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return map[string]any{"error": "xpcloud.yaml not found"}, false
	}
	if len(b) > configMaxBytes {
		b = b[:configMaxBytes]
	}
	return map[string]any{"app": app, "yaml": string(b), "sha": contentSHA(b)}, true
}

// toolAppConfigSet — overwrite the app's xpcloud.yaml. Validated YAML +
// optional optimistic lock (base_sha). Approval-gated (destructiveTools).
func toolAppConfigSet(userID string, args map[string]any) (map[string]any, bool) {
	app, _ := args["app"].(string)
	yamlText, _ := args["yaml"].(string)
	baseSHA, _ := args["base_sha"].(string)
	if app == "" || !slugRe.MatchString(app) || yamlText == "" {
		return map[string]any{"error": "app and yaml required"}, false
	}
	if len(yamlText) > configMaxBytes {
		return map[string]any{"error": "config exceeds 64 KB limit"}, false
	}
	var check any
	if err := yaml.Unmarshal([]byte(yamlText), &check); err != nil {
		return map[string]any{"error": "invalid YAML: " + err.Error()}, false
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		return map[string]any{"error": "app not found: " + app}, false
	}
	curPath, _ := ResolveSpecPath(appDir)
	if baseSHA != "" {
		if cur, err := os.ReadFile(curPath); err == nil && contentSHA(cur) != baseSHA {
			return map[string]any{"error": "config changed since you loaded it — call app_config_get again and reapply"}, false
		}
	}
	yamlPath := SpecWritePath(appDir)
	tmp := yamlPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(yamlText), 0644); err != nil {
		return map[string]any{"error": "cannot write config"}, false
	}
	if err := os.Rename(tmp, yamlPath); err != nil {
		_ = os.Remove(tmp)
		return map[string]any{"error": "cannot save config"}, false
	}
	// Avoid orphaning a pre-existing legacy file with stale content.
	if curPath != yamlPath {
		_ = os.Remove(curPath)
	}
	return map[string]any{"app": app, "saved": true, "sha": contentSHA([]byte(yamlText))}, true
}
