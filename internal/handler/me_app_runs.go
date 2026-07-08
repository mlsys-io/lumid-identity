package handler

// Generic cross-node run store for xpio app cycles (app-agnostic). Trajectory +
// experiment metrics are runtime data on the scheduler PVC identity can't read,
// so the cycle self-reports each run here and the Studio surfaces reconstruct
// history from it. App-specific metrics ride in an opaque JSON blob; the score /
// series are pulled by the app's OWN declared metric name — nothing hardcoded.
//
//   POST /api/v1/internal/app-runs   — record/upsert a run (self-report + backfill)

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type appRunBody struct {
	UserSub   string         `json:"user_sub"`
	App       string         `json:"app"`
	Loop      string         `json:"loop"`
	RunTs     int64          `json:"run_ts"`
	Model     string         `json:"model"`
	Ok        bool           `json:"ok"`
	DurationS *float64       `json:"duration_s"`
	Metrics   map[string]any `json:"metrics"` // the cycle's own summary — any shape
	Source    string         `json:"source"`
}

// InternalAppRunRecord — POST /api/v1/internal/app-runs (X-Bridge-Secret).
// Idempotent upsert on (user_sub, app, loop, run_ts). App-agnostic.
func InternalAppRunRecord(c *gin.Context) {
	var b appRunBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if b.UserSub == "" || b.App == "" || b.Loop == "" || b.RunTs == 0 {
		fail(c, http.StatusBadRequest, 1400, "user_sub, app, loop, run_ts required")
		return
	}
	src := b.Source
	if src == "" {
		src = "self_report"
	}
	mj := "{}"
	if b.Metrics != nil {
		if raw, err := json.Marshal(b.Metrics); err == nil {
			mj = string(raw)
		}
	}
	row := models.MeAppRun{
		UserSub: b.UserSub, App: b.App, Loop: b.Loop, RunTs: b.RunTs,
		Model: b.Model, Ok: b.Ok, DurationS: b.DurationS, Metrics: mj, Source: src,
	}
	// `loop` is a MySQL reserved word — must be backtick-quoted in raw SQL.
	res := common.DB.Where("user_sub = ? AND app = ? AND `loop` = ? AND run_ts = ?",
		b.UserSub, b.App, b.Loop, b.RunTs).Assign(row).FirstOrCreate(&models.MeAppRun{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+res.Error.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "recorded",
		"data": gin.H{"app": b.App, "loop": b.Loop, "run_ts": b.RunTs}})
}

// loopMetricName resolves the primary metric NAME for a loop from the app's
// published spec (the experiment attached to the loop → metric.name). Generic;
// returns "" when the loop declares no experiment/metric.
func loopMetricName(userSub, app, loop string) string {
	spec, ok := fetchRepoSpecYAML(userSub, app)
	if !ok {
		return ""
	}
	m := parseExpManifestBytes(spec)
	byExp := map[string]string{}
	for _, d := range m.Experiments {
		if d.Metric != nil {
			if s, ok := d.Metric["name"].(string); ok {
				byExp[d.ID] = s
			}
		}
	}
	for exp, loops := range expLoops(m) {
		for _, ln := range loops {
			if ln == loop {
				return byExp[exp]
			}
		}
	}
	// Single-experiment apps: fall back to that experiment's metric.
	if len(byExp) == 1 {
		for _, v := range byExp {
			return v
		}
	}
	return ""
}

// appRunsFor returns the caller's runs for an app (optionally one loop), oldest
// first. The cross-node source for trajectory + experiment metrics.
func appRunsFor(userSub, app, loop string) []models.MeAppRun {
	var rows []models.MeAppRun
	q := common.DB.Where("user_sub = ? AND app = ?", userSub, app)
	if loop != "" {
		q = q.Where("`loop` = ?", loop) // reserved word — backtick-quote
	}
	if q.Order("run_ts ASC").Find(&rows).Error != nil {
		return nil
	}
	return rows
}

// metricFromBlob recursively finds `name` in a run's metrics JSON and returns it
// as a float. App-agnostic: the caller passes the app's OWN declared metric name
// (experiments[].metric.name), so e.g. "exact_recall" is found wherever the app
// nested it. Returns nil if absent/non-numeric.
func metricFromBlob(metricsJSON, name string) *float64 {
	if name == "" || metricsJSON == "" {
		return nil
	}
	var doc any
	if json.Unmarshal([]byte(metricsJSON), &doc) != nil {
		return nil
	}
	var walk func(v any) *float64
	walk = func(v any) *float64 {
		switch t := v.(type) {
		case map[string]any:
			if hit, ok := t[name]; ok {
				if f, ok := hit.(float64); ok {
					return &f
				}
			}
			for _, sub := range t {
				if r := walk(sub); r != nil {
					return r
				}
			}
		case []any:
			for _, sub := range t {
				if r := walk(sub); r != nil {
					return r
				}
			}
		}
		return nil
	}
	return walk(doc)
}

// trajNodesFromRuns synthesizes the trajectory (nodes + cycles) from run-store
// rows — the cross-node reconstruction. Linear chain, one node per run,
// chronological. Scored by the app's declared metric (metricName) when present.
func trajNodesFromRuns(runs []models.MeAppRun, metricName string) ([]trajNode, []trajCycle) {
	sort.Slice(runs, func(i, j int) bool { return runs[i].RunTs < runs[j].RunTs })
	nodes := make([]trajNode, 0, len(runs))
	cycles := make([]trajCycle, 0, len(runs))
	var parent string
	for i, r := range runs {
		ts := strconv.FormatInt(r.RunTs, 10)
		score := metricFromBlob(r.Metrics, metricName)
		n := trajNode{
			ID: "run:" + ts, Kind: "run", CycleTs: ts, RunTs: ts,
			Depth: i, ParentID: parent, Scored: score != nil, Score: score,
			Label:        r.Model,
			Config:       map[string]any{"model": r.Model},
			DurationS:    r.DurationS,
			AgentVersion: "v" + strconv.Itoa(i+1),
		}
		nodes = append(nodes, n)
		parent = n.ID
		cycles = append(cycles, trajCycle{Ts: ts, NVariants: 1, ChampionID: n.ID, ChampionScore: score})
	}
	return nodes, cycles
}

// expStateFromRuns computes a generic experiment-state overlay from run-store
// rows using the app's declared metric name. Returns nil if no run carries it.
func expStateFromRuns(runs []models.MeAppRun, metricName string, baseline float64) map[string]any {
	sort.Slice(runs, func(i, j int) bool { return runs[i].RunTs < runs[j].RunTs })
	series := []map[string]any{}
	var latest *float64
	for _, r := range runs {
		v := metricFromBlob(r.Metrics, metricName)
		if v == nil {
			continue
		}
		series = append(series, map[string]any{"run_ts": r.RunTs, "value": *v})
		latest = v
	}
	if latest == nil {
		return nil
	}
	return map[string]any{
		"n_results":    len(series),
		"metric":       *latest,
		"series":       series,
		"criteria_met": *latest >= baseline,
	}
}
