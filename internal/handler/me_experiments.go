// Experiments — read-only observability for the xpio `experiments[]`
// opinion (hypothesis × variants × dataset/casebook × metric).
//
//	GET /me/apps/:app/experiments              list (declaration ⊕ state)
//	GET /me/apps/:app/experiments/:id          detail (+series, +cases)
//	GET /me/apps/:app/experiments/:id/case/:caseId   per-case drill
//
// The runtime ledger (data/experiments/<id>/{results.jsonl,state.json}) is
// written by sdk/apps/experiments.py; we only read. `dims.case_id` rows
// power the casebook view: per-case score histories, not just run logs.
// NO synthetic data here (unlike me_cycle.go's demo-mint) — experiments
// show real results or honest emptiness.
package handler

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const expResultsTailCap = 500

type expDecl struct {
	ID         string           `yaml:"id" json:"id"`
	Hypothesis string           `yaml:"hypothesis" json:"hypothesis"`
	Kind       string           `yaml:"kind" json:"kind"`
	DatasetID  string           `yaml:"dataset_id" json:"dataset_id,omitempty"`
	Benchmark  string           `yaml:"benchmark_id" json:"benchmark_id,omitempty"`
	Metric     map[string]any   `yaml:"metric" json:"metric,omitempty"`
	Arms       []map[string]any `yaml:"arms" json:"arms,omitempty"`
	Baseline   any              `yaml:"baseline" json:"baseline,omitempty"`
	Criteria   string           `yaml:"success_criteria" json:"success_criteria,omitempty"`
	MinSamples int              `yaml:"min_samples" json:"min_samples,omitempty"`
	Status     string           `yaml:"status" json:"status,omitempty"`
}

type expManifest struct {
	Experiments []expDecl `yaml:"experiments"`
	Loops       []struct {
		Name   string `yaml:"name"`
		Engine struct {
			Experiment string `yaml:"experiment"`
		} `yaml:"engine"`
		Steps []struct {
			Experiment string `yaml:"experiment"`
		} `yaml:"steps"`
	} `yaml:"loops"`
}

func readExpManifest(appDir string) expManifest {
	if specPath, ok := ResolveSpecPath(appDir); ok {
		if b, err := os.ReadFile(specPath); err == nil {
			return parseExpManifestBytes(b)
		}
	}
	return expManifest{}
}

// parseExpManifestBytes parses the experiments block from raw spec bytes,
// accepting BOTH shapes: the list form `experiments: [{id: x, …}]` and the map
// form `experiments: {x: {…}}` (the key is the id). Lets the cross-node fallback
// build the experiments surface for a tenant app identity can't read on disk.
func parseExpManifestBytes(b []byte) expManifest {
	var m expManifest
	_ = yaml.Unmarshal(b, &m) // list form + loops[]
	if len(m.Experiments) == 0 {
		var mm struct {
			Experiments map[string]expDecl `yaml:"experiments"`
		}
		if yaml.Unmarshal(b, &mm) == nil {
			for id, d := range mm.Experiments {
				if d.ID == "" {
					d.ID = id
				}
				m.Experiments = append(m.Experiments, d)
			}
		}
	}
	return m
}

// expLoops — experiment id → loops attached to it.
func expLoops(m expManifest) map[string][]string {
	out := map[string][]string{}
	for _, l := range m.Loops {
		ids := map[string]bool{}
		if l.Engine.Experiment != "" {
			ids[l.Engine.Experiment] = true
		}
		for _, st := range l.Steps {
			if st.Experiment != "" {
				ids[st.Experiment] = true
			}
		}
		for id := range ids {
			out[id] = append(out[id], l.Name)
		}
	}
	return out
}

func readExpState(appDir, id string) map[string]any {
	st := map[string]any{}
	p, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "experiments", id, "state.json"))
	b, err := os.ReadFile(p)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	return st
}

type expRow struct {
	TS        string             `json:"ts"`
	CycleTS   string             `json:"cycle_ts,omitempty"`
	VariantID string             `json:"variant_id"`
	Metrics   map[string]float64 `json:"metrics"`
	Dims      map[string]string  `json:"dims,omitempty"`
	N         *int               `json:"n,omitempty"`
	// U1 unified-vocabulary mirrors: rows may carry `experiment` (≡ variant_id)
	// and `item` (≡ dims). normalize() folds them onto the canonical fields so
	// the rest of the handler keeps reading VariantID/Dims unchanged.
	Experiment string            `json:"experiment,omitempty"`
	Item       map[string]string `json:"item,omitempty"`
}

// normalize folds U1 mirror keys onto the canonical fields (legacy wins when
// both are present — the Python ledger writes both identically).
func (r *expRow) normalize() {
	if r.VariantID == "" && r.Experiment != "" {
		r.VariantID = r.Experiment
	}
	if r.Dims == nil && r.Item != nil {
		r.Dims = r.Item
	}
}

// readExpRows returns up to the LAST `cap` rows of the results ledger.
func readExpRows(appDir, id string, capN int) []expRow {
	p, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "experiments", id, "results.jsonl"))
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	rows := make([]expRow, 0, 64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r expRow
		if json.Unmarshal([]byte(line), &r) == nil {
			r.normalize()
			if r.VariantID != "" {
				rows = append(rows, r)
			}
		}
	}
	if len(rows) > capN {
		rows = rows[len(rows)-capN:]
	}
	return rows
}

// loadAppExperiments — declarations merged with ledger state. Shared with
// the chat tools (list_experiments).
func loadAppExperiments(appDir string) []gin.H {
	m := readExpManifest(appDir)
	loops := expLoops(m)
	out := make([]gin.H, 0, len(m.Experiments))
	for _, d := range m.Experiments {
		if d.ID == "" {
			continue
		}
		st := readExpState(appDir, d.ID)
		row := gin.H{
			"id": d.ID, "hypothesis": d.Hypothesis, "kind": d.Kind,
			"dataset_id": d.DatasetID, "metric": d.Metric,
			"benchmark_id": d.Benchmark, "baseline": d.Baseline,
			"success_criteria": d.Criteria, "min_samples": d.MinSamples,
			"status":       strOr(d.Status, "active"),
			"loops":        loops[d.ID],
			"n_results":    0,
			"criteria_met": false,
		}
		for _, k := range []string{
			"n_results", "variants", "best_variant", "baseline_value",
			"delta", "delta_pp", "criteria_met", "criteria_reason",
			"verdict", "updated_at", "metric", "higher_is_better",
		} {
			if v, ok := st[k]; ok && v != nil {
				if k == "metric" {
					// state stores the resolved metric NAME; keep the
					// declaration's metric object and expose the resolved
					// name separately.
					row["metric_name"] = v
					continue
				}
				row[k] = v
			}
		}
		out = append(out, row)
	}
	return out
}

func strOr(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// baselineFromDecl extracts a numeric success threshold from an experiment
// declaration — `baseline: {value: X}` or `baseline: X`. App-agnostic; used to
// compute criteria_met from the run-store metric. Returns 0 when unspecified.
func baselineFromDecl(d expDecl) float64 {
	switch v := d.Baseline.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case map[string]any:
		if x, ok := v["value"].(float64); ok {
			return x
		}
		if x, ok := v["value"].(int); ok {
			return float64(x)
		}
	}
	return 0
}

// loadExperimentDetail — state + results tail + per-variant series +
// per-case grouping (casebook observability). Shared with chat tools.
func loadExperimentDetail(appDir, id string) (gin.H, bool) {
	m := readExpManifest(appDir)
	var decl *expDecl
	for i := range m.Experiments {
		if m.Experiments[i].ID == id {
			decl = &m.Experiments[i]
			break
		}
	}
	if decl == nil {
		return nil, false
	}
	st := readExpState(appDir, id)
	rows := readExpRows(appDir, id, expResultsTailCap)
	metricName, _ := st["metric"].(string)
	if metricName == "" {
		if mm, ok := decl.Metric["name"].(string); ok {
			metricName = mm
		}
	}

	// per-variant series over the primary metric (same point shape as
	// MeMetricSeries so the UI reuses sparkline/curve code)
	seriesBy := map[string][]gin.H{}
	for _, r := range rows {
		v, ok := r.Metrics[metricName]
		if !ok {
			continue
		}
		// case/q rows are grouped under cases below; the variant series
		// uses run-level rows (no dims) when any exist, else everything.
		seriesBy[r.VariantID] = append(seriesBy[r.VariantID], gin.H{"ts": r.TS, "v": v})
	}
	series := make([]gin.H, 0, len(seriesBy))
	for vid, pts := range seriesBy {
		series = append(series, gin.H{"variant_id": vid, "points": pts})
	}
	sort.Slice(series, func(i, j int) bool {
		return series[i]["variant_id"].(string) < series[j]["variant_id"].(string)
	})

	// cases: rows with dims.case_id and NO q_id (case-level), grouped —
	// the casebook view payload.
	type caseAgg struct {
		pts    []gin.H
		sum    float64
		latest float64
		prev   float64
		n      int
	}
	caseMap := map[string]*caseAgg{}
	for _, r := range rows {
		cid := r.Dims["case_id"]
		if cid == "" || r.Dims["q_id"] != "" {
			continue
		}
		v, ok := r.Metrics[metricName]
		if !ok {
			continue
		}
		ca := caseMap[cid]
		if ca == nil {
			ca = &caseAgg{}
			caseMap[cid] = ca
		}
		ca.pts = append(ca.pts, gin.H{"ts": r.TS, "v": v})
		ca.sum += v
		ca.prev = ca.latest
		ca.latest = v
		ca.n++
	}
	cases := make([]gin.H, 0, len(caseMap))
	for cid, ca := range caseMap {
		row := gin.H{
			"case_id": cid, "n": ca.n,
			"latest": ca.latest,
			"mean":   ca.sum / float64(ca.n),
			"points": ca.pts,
		}
		if ca.n > 1 {
			row["delta_vs_prev"] = ca.latest - ca.prev
		}
		cases = append(cases, row)
	}
	sort.Slice(cases, func(i, j int) bool {
		return cases[i]["case_id"].(string) < cases[j]["case_id"].(string)
	})

	detail := gin.H{
		"id": decl.ID, "hypothesis": decl.Hypothesis, "kind": decl.Kind,
		"dataset_id": decl.DatasetID, "metric": decl.Metric,
		"metric_name": metricName, "baseline": decl.Baseline,
		"success_criteria": decl.Criteria, "min_samples": decl.MinSamples,
		"status":  strOr(decl.Status, "active"),
		"loops":   expLoops(m)[decl.ID],
		"state":   st,
		"results": rows,
		"series":  series,
		"cases":   cases,
	}
	return detail, true
}

// ─── handlers ───────────────────────────────────────────────────────

// MeExperiments — GET /api/v1/me/experiments: cross-app aggregate
// (Workstream F). Iterates the caller's apps (tenant first, operator-
// shared after, tenant shadowing) and annotates each experiment with
// its owning app. Cheap — local file reads only.
func MeExperiments(c *gin.Context) {
	userID, okk := currentUserID(c)
	if !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	// Make the per-pod cache match what the user has installed, so this answers
	// the same on either replica.
	ensureTenantAppsMaterialised(userID)
	all := []gin.H{}
	seen := map[string]bool{}
	for _, root := range appListRoots(userID) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || seen[e.Name()] {
				continue
			}
			seen[e.Name()] = true
			exps := loadAppExperiments(filepath.Join(root, e.Name()))
			for _, exp := range exps {
				exp["app"] = e.Name()
				all = append(all, exp)
			}
		}
	}
	// Newest movement first; experiments without an updated_at sort last.
	sort.SliceStable(all, func(i, j int) bool {
		ui, _ := all[i]["updated_at"].(string)
		uj, _ := all[j]["updated_at"].(string)
		return ui > uj
	})
	ok(c, "ok", gin.H{"experiments": all, "count": len(all)})
}

func MeAppExperiments(c *gin.Context) {
	userID, okk := currentUserID(c)
	if !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) || strings.Contains(app, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		// Cross-node: identity can't read the tenant PVC (svc node ≠ scheduler
		// node; kind=agent apps in .xp/agents). Fall back to the published spec
		// for the experiment DECLARATIONS (runtime ledger state stays absent —
		// that's PVC-only). Kills the hard 404 + surfaces declared experiments.
		if spec, okf := fetchRepoSpecYAML(userID, app); okf {
			m := parseExpManifestBytes(spec)
			loops := expLoops(m)
			// Overlay run-store metrics (me_app_runs) onto the declaration —
			// the runtime ledger is PVC-only, so the cross-node run store is the
			// metric source. App-agnostic. baselineFromDecl reads the declared
			// success threshold so criteria_met is computed generically.
			exps := make([]gin.H, 0, len(m.Experiments))
			for _, d := range m.Experiments {
				if d.ID == "" {
					continue
				}
				row := gin.H{
					"id": d.ID, "hypothesis": d.Hypothesis, "kind": d.Kind,
					"dataset_id": d.DatasetID, "metric": d.Metric,
					"benchmark_id": d.Benchmark, "baseline": d.Baseline,
					"success_criteria": d.Criteria, "min_samples": d.MinSamples,
					"status": strOr(d.Status, "active"), "loops": loops[d.ID],
					"n_results": 0, "criteria_met": false,
				}
				mname := ""
				if d.Metric != nil {
					if s, ok := d.Metric["name"].(string); ok {
						mname = s
					}
				}
				if st := expStateFromRuns(appRunsFor(userID, app, ""), mname, baselineFromDecl(d)); st != nil {
					for k, v := range st {
						row[k] = v
					}
				}
				exps = append(exps, row)
			}
			ok(c, "ok", gin.H{"experiments": exps, "count": len(exps)})
			return
		}
		// Not resolvable anywhere — graceful empty (the app may still be
		// installing); the UI renders a clean empty state, not a console 404.
		ok(c, "ok", gin.H{"experiments": []gin.H{}, "count": 0})
		return
	}
	exps := loadAppExperiments(appDir)
	ok(c, "ok", gin.H{"experiments": exps, "count": len(exps)})
}

func MeAppExperiment(c *gin.Context) {
	userID, okk := currentUserID(c)
	if !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app, id := c.Param("app"), c.Param("id")
	if !slugRe.MatchString(app) || strings.Contains(app, "/") ||
		!slugRe.MatchString(id) || strings.Contains(id, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid app or experiment")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	detail, found := loadExperimentDetail(appDir, id)
	if !found {
		fail(c, http.StatusNotFound, 1404, "experiment not found")
		return
	}
	ok(c, "ok", detail)
}

// MeAppExperimentCase — the per-case drill: that case's rows, q-level
// included, plus latest values per question.
func MeAppExperimentCase(c *gin.Context) {
	userID, okk := currentUserID(c)
	if !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app, id, caseID := c.Param("app"), c.Param("id"), c.Param("caseId")
	if !slugRe.MatchString(app) || strings.Contains(app, "/") ||
		!slugRe.MatchString(id) || strings.Contains(id, "/") ||
		!slugRe.MatchString(caseID) || strings.Contains(caseID, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid path")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}
	rows := readExpRows(appDir, id, expResultsTailCap)
	caseRows := make([]expRow, 0, 16)
	latestByQ := map[string]gin.H{}
	for _, r := range rows {
		if r.Dims["case_id"] != caseID {
			continue
		}
		caseRows = append(caseRows, r)
		if q := r.Dims["q_id"]; q != "" {
			latestByQ[q] = gin.H{"ts": r.TS, "metrics": r.Metrics}
		}
	}
	ok(c, "ok", gin.H{
		"case_id": caseID, "rows": caseRows, "latest_by_question": latestByQ,
	})
}
