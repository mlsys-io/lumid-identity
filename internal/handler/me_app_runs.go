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
	Outputs   any            `json:"outputs"`
	// Offers + step_errors — what the run SAID. See models.MeAppRun.Events.
	Events any `json:"events"`
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
	oj := ""
	if b.Outputs != nil {
		if raw, err := json.Marshal(b.Outputs); err == nil {
			// 64 KiB ceiling. Truncating to a marker beats storing a
			// half-written JSON fragment that every reader would then fail to
			// parse, and beats refusing the whole run report over its artifact.
			if len(raw) <= 64*1024 {
				oj = string(raw)
			} else {
				oj = `{"_truncated":true,"_bytes":` + strconv.Itoa(len(raw)) + `}`
			}
		}
	}
	mj := "{}"
	if b.Metrics != nil {
		if raw, err := json.Marshal(b.Metrics); err == nil {
			mj = string(raw)
		}
	}
	// Run EVENTS — the offer the cycle emitted, and the step errors behind a
	// failure. Marshalled like outputs and bounded the same way: a run that
	// says something must not be able to say 64 KiB of it.
	var ej *string
	if b.Events != nil {
		if raw, err := json.Marshal(b.Events); err == nil && len(raw) > 2 {
			e := string(raw)
			if len(e) > 16*1024 {
				e = `{"_truncated":true,"_bytes":` + strconv.Itoa(len(raw)) + `}`
			}
			ej = &e
		}
	}
	row := models.MeAppRun{
		UserSub: b.UserSub, App: b.App, Loop: b.Loop, RunTs: b.RunTs,
		Model: b.Model, Ok: b.Ok, DurationS: b.DurationS, Metrics: mj, Source: src,
	}
	// Same append-only reasoning as outputs: a later report carrying none must
	// not blank what an earlier one said.
	if ej != nil {
		row.Events = ej
	}
	// Assign() would overwrite a stored artifact with "" on a later report that
	// carries none (a re-report, a backfill). An artifact is append-only from
	// the store's point of view: only a NEW one replaces it.
	if oj != "" {
		row.Outputs = oj
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
// appAliases returns every historical name a bundle's run rows may be filed
// under, including `app` itself.
//
// Run rows are keyed on (user_sub, app), so a RENAMED app orphans its own
// history: rows written as `lqt-mailbox` are unreachable from `quant-research`
// surfaces and vice versa. The surfaces then read empty forever with no
// diagnostic, while the Strategies table — which is server-scoped and
// slug-independent — still shows real rows. The user sees "my strategies exist
// but backtesting is broken", which is not what happened.
//
// Keep this list tiny and explicit. It is a compatibility shim for renames that
// already shipped, not a general aliasing feature: a wrong entry here silently
// merges two apps' histories, which is a worse failure than the one it fixes.
func appAliases(app string) []string {
	groups := [][]string{
		{"quant-research", "lqt-mailbox"},
	}
	for _, g := range groups {
		for _, name := range g {
			if name == app {
				return g
			}
		}
	}
	return []string{app}
}

func appRunsFor(userSub, app, loop string) []models.MeAppRun {
	var rows []models.MeAppRun
	q := common.DB.Where("user_sub = ? AND app IN ?", userSub, appAliases(app))
	if loop != "" {
		q = q.Where("`loop` = ?", loop) // reserved word — backtick-quote
	}
	if q.Order("run_ts ASC").Find(&rows).Error != nil {
		return nil
	}
	return rows
}

// metricFromBlob finds `name` in a run's metrics JSON and returns it as a
// float. App-agnostic: the caller passes the app's OWN declared metric name
// (experiments[].metric.name), so e.g. "exact_recall" is found wherever the app
// nested it. Returns nil if absent/non-numeric.
//
// TIES BREAK BY SORTED KEY, and the search is breadth-first so the preference
// is explicit rather than emergent: a top-level `score` is the run's own metric,
// one buried inside some payload is somebody else's. models/me_app_run.go:29-33
// records that collision as the reason the run artifact got its own `outputs`
// column instead of living inside `metrics`.
//
// The BUG this replaces was the tie-break, not the depth order. The previous
// walk reached siblings by ranging a Go map, and Go randomises map iteration —
// so when two sibling subtrees both carried the key, WHICH ONE ANSWERED CHANGED
// BETWEEN CALLS. The same stored run could report two different scores on two
// refreshes, with nothing in the output naming where the number came from, and
// that value feeds trajNode.Score and expStateFromRuns' criteria_met.
func metricFromBlob(metricsJSON, name string) *float64 {
	v, _ := metricFromBlobPath(metricsJSON, name)
	return v
}

// metricFromBlobPath is metricFromBlob plus the dotted path the value was found
// at ("" when not found) — so a caller can say WHERE a number came from instead
// of asserting it.
func metricFromBlobPath(metricsJSON, name string) (*float64, string) {
	if name == "" || metricsJSON == "" {
		return nil, ""
	}
	var doc any
	if json.Unmarshal([]byte(metricsJSON), &doc) != nil {
		return nil, ""
	}
	type node struct {
		v    any
		path string
	}
	// Depth-bounded so a pathological blob cannot walk forever; 12 is far past
	// anything an app writes and still terminates on a cyclic-looking structure
	// produced by a bad encoder.
	const maxDepth = 12
	level := []node{{v: doc, path: ""}}
	for depth := 0; depth < maxDepth && len(level) > 0; depth++ {
		var next []node
		for _, n := range level {
			switch t := n.v.(type) {
			case map[string]any:
				// This level first: an exact hit here outranks anything deeper.
				if hit, ok := t[name]; ok {
					if f, ok := hit.(float64); ok {
						return &f, joinPath(n.path, name)
					}
				}
				// Descend in sorted key order so the choice is reproducible.
				keys := make([]string, 0, len(t))
				for k := range t {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					next = append(next, node{v: t[k], path: joinPath(n.path, k)})
				}
			case []any:
				for i, sub := range t {
					next = append(next, node{v: sub, path: n.path + "[" + strconv.Itoa(i) + "]"})
				}
			}
		}
		level = next
	}
	return nil, ""
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
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

// lastRunFromDB returns the most recent recorded run for a loop, from the
// cross-node table. The journal file is the richer log but only exists where the
// scheduler wrote it; identity (service tier) cannot read that PVC, so for a
// cloud-installed app the journal is absent and this is the only evidence a
// cycle ever happened.
func lastRunFromDB(userSub, app, loop string) (float64, bool, bool) {
	if common.DB == nil {
		return 0, false, false
	}
	var row models.MeAppRun
	// Alias-aware like appRunsFor: a renamed app must not appear to have never
	// run. The WRITE path (upsertAppRun) deliberately keeps its exact key — a
	// write matching several names would merge histories rather than record one.
	err := common.DB.Where("user_sub = ? AND app IN ? AND `loop` = ?", userSub, appAliases(app), loop).
		Order("run_ts DESC").Limit(1).First(&row).Error
	if err != nil || row.RunTs == 0 {
		return 0, false, false
	}
	return float64(row.RunTs), row.Ok, true
}
