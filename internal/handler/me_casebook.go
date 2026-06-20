package handler

// P2b — the Data tab as a first-class evolving CASEBOOK.
//
//   GET /me/apps/:app/casebook?loop=  — the eval-set an app's goal metrics
//        are scored on, with per-case latest score + score history + the
//        casebook's own evolution (cases added over time, metric trajectory).
//
// MeAppDatasets (me_datasets.go) only lists bundled static files, which is
// EMPTY for command-driven (Pattern B) apps like mbb-ai whose casebook is
// per-case files (`Case_*.json`) plus per-case scores mined from experiments.
// This handler reads the SAME tenant app dir (resolveAppDir / tenantAppsDir)
// and assembles the cases + scores from three on-disk sources:
//
//   1. declared `datasets[]` in xpcloud.yaml / manifest.json — the casebook's
//      identity (id, version, mount path).
//   2. per-case files under the bundle data dir (data/seed, data/cases,
//      data/inbox, Case_*.json, queries.jsonl) — the case roster + a preview
//      of each case's scalar fields.
//   3. per-case + per-metric SCORES mined from experiments:
//      data/experiments/<id>/results.jsonl rows carry
//      {metrics:{...}, cycle_ts, dims:{case_id, q_id}} — we group by
//      dims.case_id for latest_score + score_history, and per cycle_ts for the
//      metric-evolution trajectory.
//
// Everything is best-effort and read-only: a missing shape yields an empty
// array, never an error, so a fresh app (no experiments yet) still renders a
// case roster.

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

// loopExperiments returns the experiment names a loop declares in xpcloud.yaml
// (engine.experiment + any steps[].experiment). This is the strict
// metrics→workflow binding: an experiment's scores belong to the loop that
// runs it, even though different loops can share the same DATA (cases).
// Empty slice = the loop declares no experiment (so it has no metrics of its
// own). Shared across the trajectory + casebook handlers (same package).
func loopExperiments(appDir, loop string) []string {
	if loop == "" {
		return nil
	}
	specPath, _ := ResolveSpecPath(appDir)
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	var doc struct {
		Loops []struct {
			Name   string `yaml:"name"`
			Engine struct {
				Experiment string `yaml:"experiment"`
			} `yaml:"engine"`
			Steps []struct {
				Experiment string `yaml:"experiment"`
			} `yaml:"steps"`
		} `yaml:"loops"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		return nil
	}
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, l := range doc.Loops {
		if l.Name != loop {
			continue
		}
		add(l.Engine.Experiment)
		for _, s := range l.Steps {
			add(s.Experiment)
		}
	}
	return out
}

// Folders (relative to the app dir) we scan for per-case files, in priority
// order — the first folder that yields cases wins as the "roster" so a seed
// casebook isn't doubled up with inbox copies of the same cases.
var casebookCaseDirs = []string{
	"data/cases",
	"data/seed",
	"data/eval-casebook",
	"sample_data",
	".lumid/inbox", // canonical runtime inbox (alongside legacy data/inbox below)
	"data/inbox",
}

// Single-file casebooks (one row per line / one array) live at these paths.
var casebookFlatFiles = []string{
	"data/queries.jsonl",
	"system/queries.jsonl",
	"data/cases.jsonl",
}

// caseLabelFields — scalar fields we lift into a case's `fields` preview when
// present (mbb-ai cases carry these). Kept short so the UI can render a chip
// row, not a form.
var casePreviewFields = []string{
	"title", "topic", "industry", "case_type", "difficulty",
	"case_id", "version", "primary", "question", "q_id", "label",
}

type casebookScorePoint struct {
	Ts    string  `json:"ts"`
	Score float64 `json:"score"`
}

type casebookCase struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Fields       map[string]any     `json:"fields,omitempty"`
	LatestScore  *float64           `json:"latest_score,omitempty"`
	ScoreHistory []casebookScorePoint `json:"score_history,omitempty"`
}

type casebookVersionPoint struct {
	Ts     string `json:"ts"`
	Note   string `json:"note,omitempty"`
	NCases int    `json:"n_cases"`
}

type casebookMetricPoint struct {
	Ts string  `json:"ts"`
	V  float64 `json:"v"`
}
type casebookMetricEvolution struct {
	Metric string                `json:"metric"`
	Points []casebookMetricPoint `json:"points"`
}

// MeCasebook — GET /me/apps/:app/casebook?loop=<loop>
func MeCasebook(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Query("loop")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// 1. Per-case scores + metric evolution, mined from experiments first so the
	//    case roster can be enriched with latest_score / score_history. Metrics
	//    are strictly bound to the selected loop's experiments (data is shared,
	//    metrics are not); with no loop given we fall back to all (back-compat).
	expAllow := map[string]bool{}
	for _, x := range loopExperiments(appDir, loop) {
		expAllow[x] = true
	}
	scores, metricEvo, scoredVia := casebookScoresFromExperiments(appDir, expAllow, loop != "")

	// 2. The case roster (per-case files, then a flat single-file casebook).
	cases := casebookRoster(appDir, scores)

	// 3. Declared dataset versions (xpcloud.yaml/manifest.json) + version
	//    history derived from how the case-count grew across cycles.
	versionHistory := casebookVersionHistory(appDir, loop)

	// Defensive: never nil — the UI iterates these directly.
	if cases == nil {
		cases = []casebookCase{}
	}
	if metricEvo == nil {
		metricEvo = []casebookMetricEvolution{}
	}
	if versionHistory == nil {
		versionHistory = []casebookVersionPoint{}
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app":               app,
			"loop":              loop,
			"cases":             cases,
			"version_history":   versionHistory,
			"metrics_evolution": metricEvo,
			// How the scores were attributed: "loop_experiment" when the loop
			// declared its own experiment, "app_fallback" when it declared none
			// and we fell back to the app's experiment results (so the UI can
			// show "scored via the app's experiments" provenance), or "" when no
			// scores were found at all.
			"scored_via": scoredVia,
		},
	})
}

// casebookScoresFromExperiments walks data/experiments/<id>/results.jsonl and
// returns (a) per-case score history keyed by dims.case_id, and (b) the
// per-metric evolution series (one point per cycle_ts, the cross-case mean).
// Rows look like:
//   {"ts":"…Z","variant_id":"current","metrics":{"question_score":0.65,…},
//    "cycle_ts":"20260612T112000Z","dims":{"case_id":"Case_001…","q_id":"Q2"}}
// allowed/strict bind metrics to the selected workflow: when strict, only the
// loop's declared experiments contribute scores (different loops can share the
// DATA but never each other's metrics).
//
// scoredVia (third return) reports the attribution provenance so the caller can
// surface it: "loop_experiment" when the strict loop binding produced scores,
// "app_fallback" when the loop declared NO experiment and we fell back to the
// app's experiment results (non-strict), or "" when no scores were found at all.
//
// Fallback (WS-4b): a loop that declares no experiment used to return silent-
// empty (`strict && len(allowed)==0`). That hid scores for loops like mbb-ai's
// `case_cycle`, whose cases ARE scored by the app's experiments but which never
// declared one. Instead of empty, we now drop strictness and attribute the
// app's experiment results to the loop, tagged "app_fallback".
func casebookScoresFromExperiments(appDir string, allowed map[string]bool, strict bool) (map[string][]casebookScorePoint, []casebookMetricEvolution, string) {
	scores := map[string][]casebookScorePoint{}
	// metric -> cycle_ts -> values (averaged per cycle for the trajectory)
	metricByCycle := map[string]map[string][]float64{}
	metricOrder := []string{}

	scoredVia := ""
	if !strict {
		scoredVia = "all_experiments"
	} else if len(allowed) > 0 {
		scoredVia = "loop_experiment"
	} else {
		// This loop declares no experiment. Rather than return empty, fall back
		// to the app's experiment results (non-strict) so its cases still carry
		// scores — tagged so the UI can note the looser provenance.
		strict = false
		scoredVia = "app_fallback"
	}
	expRoot, _ := ResolveRuntimeReadPath(appDir, "data/experiments")
	exps, err := os.ReadDir(expRoot)
	if err != nil {
		return scores, nil, ""
	}
	for _, e := range exps {
		if !e.IsDir() {
			continue
		}
		if strict && !allowed[e.Name()] {
			continue // not this workflow's experiment
		}
		// The experiment's primary metric (for per-case latest_score). Falls
		// back to a sensible scan of the metrics dict when state.json is absent.
		primaryMetric := ""
		if b, err := os.ReadFile(filepath.Join(expRoot, e.Name(), "state.json")); err == nil {
			var st map[string]any
			if json.Unmarshal(b, &st) == nil {
				if m, ok := st["metric"].(string); ok {
					primaryMetric = m
				}
			}
		}

		f, err := os.Open(filepath.Join(expRoot, e.Name(), "results.jsonl"))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			metrics, _ := row["metrics"].(map[string]any)
			if metrics == nil {
				continue
			}
			ts := asStr(row["cycle_ts"])
			if ts == "" {
				ts = asStr(row["ts"])
			}

			// Pick the row's score: the experiment's primary metric if present,
			// else the per-question score, else the first numeric metric.
			score, scoreKey := pickScore(metrics, primaryMetric)

			// Per-case history (keyed by dims.case_id).
			if dims, ok := row["dims"].(map[string]any); ok {
				if caseID := asStr(dims["case_id"]); caseID != "" && scoreKey != "" {
					scores[caseID] = append(scores[caseID], casebookScorePoint{Ts: ts, Score: score})
				}
			}

			// Metric evolution: every numeric metric, averaged per cycle_ts.
			if ts != "" {
				for k, v := range metrics {
					fv, ok := toFloat(v)
					if !ok {
						continue
					}
					if _, seen := metricByCycle[k]; !seen {
						metricByCycle[k] = map[string][]float64{}
						metricOrder = append(metricOrder, k)
					}
					metricByCycle[k][ts] = append(metricByCycle[k][ts], fv)
				}
			}
		}
		f.Close()
	}

	// Sort each case's history oldest→newest (sparkline + latest pick rely on it).
	for k := range scores {
		pts := scores[k]
		sort.Slice(pts, func(i, j int) bool { return pts[i].Ts < pts[j].Ts })
		scores[k] = pts
	}

	// Collapse metric-by-cycle into ordered trajectories (mean per cycle).
	sort.Strings(metricOrder)
	evo := []casebookMetricEvolution{}
	for _, m := range metricOrder {
		cycles := metricByCycle[m]
		tsKeys := make([]string, 0, len(cycles))
		for ts := range cycles {
			tsKeys = append(tsKeys, ts)
		}
		sort.Strings(tsKeys)
		pts := make([]casebookMetricPoint, 0, len(tsKeys))
		for _, ts := range tsKeys {
			vals := cycles[ts]
			if len(vals) == 0 {
				continue
			}
			sum := 0.0
			for _, v := range vals {
				sum += v
			}
			pts = append(pts, casebookMetricPoint{Ts: ts, V: roundN(sum/float64(len(vals)), 4)})
		}
		if len(pts) >= 2 { // a trajectory needs at least two points
			evo = append(evo, casebookMetricEvolution{Metric: strings.ReplaceAll(m, "_", " "), Points: pts})
		}
	}
	// Nothing was actually attributed — clear the provenance note so the UI
	// doesn't claim a fallback that produced no scores.
	if len(scores) == 0 {
		scoredVia = ""
	}
	return scores, evo, scoredVia
}

// pickScore returns (value, keyUsed) for the score to attribute to a result
// row: the experiment's declared primary metric, else question_score, else the
// first numeric metric found (stable by key order).
func pickScore(metrics map[string]any, primary string) (float64, string) {
	if primary != "" {
		if v, ok := toFloat(metrics[primary]); ok {
			return v, primary
		}
	}
	for _, k := range []string{"question_score", "avg_question_score", "score", "accuracy", "alignment_score"} {
		if v, ok := toFloat(metrics[k]); ok {
			return v, k
		}
	}
	keys := make([]string, 0, len(metrics))
	for k := range metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if v, ok := toFloat(metrics[k]); ok {
			return v, k
		}
	}
	return 0, ""
}

// casebookRoster builds the case list from per-case files (first non-empty
// folder in casebookCaseDirs), enriched with score history from `scores`. Each
// case's id is its case_id (when the file declares one) else the filename stem,
// matched against `scores` keys (which are dims.case_id == the file stem for
// mbb-ai). When no per-case files exist, falls back to a flat jsonl casebook.
func casebookRoster(appDir string, scores map[string][]casebookScorePoint) []casebookCase {
	out := []casebookCase{}
	used := map[string]bool{}

	for _, rel := range casebookCaseDirs {
		dirAbs := filepath.Join(appDir, rel)
		ents, err := os.ReadDir(dirAbs)
		if err != nil {
			continue
		}
		found := []casebookCase{}
		for _, e := range ents {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if strings.ToLower(filepath.Ext(e.Name())) != ".json" {
				continue
			}
			stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
			// id is the file stem (matches experiments' dims.case_id); prefer a
			// declared case_id when the file carries one.
			cc := casebookCase{ID: stem, Label: stem}
			if b, err := os.ReadFile(filepath.Join(dirAbs, e.Name())); err == nil && int64(len(b)) < 512*1024 {
				var raw map[string]any
				if json.Unmarshal(b, &raw) == nil {
					cc.Fields = caseFieldsPreview(raw)
					if lbl := caseLabel(raw); lbl != "" {
						cc.Label = lbl
					}
				}
			}
			attachScores(&cc, scores)
			found = append(found, cc)
			used[cc.ID] = true
		}
		if len(found) > 0 {
			sort.Slice(found, func(i, j int) bool { return found[i].ID < found[j].ID })
			out = append(out, found...)
			break // first non-empty roster folder wins
		}
	}

	// Flat single-file casebook fallback (queries.jsonl style): one case per row.
	if len(out) == 0 {
		for _, rel := range casebookFlatFiles {
			f, err := os.Open(filepath.Join(appDir, rel))
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64*1024), 1024*1024)
			i := 0
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				var raw map[string]any
				if json.Unmarshal([]byte(line), &raw) != nil {
					continue
				}
				i++
				id := asStr(raw["id"])
				if id == "" {
					id = asStr(raw["case_id"])
				}
				if id == "" {
					id = "row_" + itoa(int64(i))
				}
				cc := casebookCase{ID: id, Label: id, Fields: caseFieldsPreview(raw)}
				if lbl := caseLabel(raw); lbl != "" {
					cc.Label = lbl
				}
				attachScores(&cc, scores)
				out = append(out, cc)
			}
			f.Close()
			if len(out) > 0 {
				break
			}
		}
	}

	// Finally: cases that exist ONLY as scored experiment rows (a case was
	// retired from disk but its scores remain) — surface them so the casebook's
	// scored set is complete.
	for caseID, hist := range scores {
		if used[caseID] || len(hist) == 0 {
			continue
		}
		cc := casebookCase{ID: caseID, Label: caseID}
		attachScores(&cc, scores)
		out = append(out, cc)
	}

	return out
}

// attachScores copies a case's score history + latest score from the mined map.
func attachScores(cc *casebookCase, scores map[string][]casebookScorePoint) {
	hist := scores[cc.ID]
	if len(hist) == 0 {
		return
	}
	cc.ScoreHistory = hist
	last := hist[len(hist)-1].Score
	cc.LatestScore = &last
}

// caseFieldsPreview lifts a few scalar fields for the UI chip row. Nested
// {source:{title}} / {case_arch:{primary}} (mbb-ai shape) are flattened.
func caseFieldsPreview(raw map[string]any) map[string]any {
	out := map[string]any{}
	add := func(k string, v any) {
		if v == nil {
			return
		}
		switch v.(type) {
		case string, float64, bool:
			if s, ok := v.(string); ok && len(s) > 160 {
				v = s[:160]
			}
			out[k] = v
		}
	}
	for _, k := range casePreviewFields {
		add(k, raw[k])
	}
	if src, ok := raw["source"].(map[string]any); ok {
		add("title", src["title"])
		add("year", src["year"])
	}
	if arch, ok := raw["case_arch"].(map[string]any); ok {
		add("primary", arch["primary"])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// caseLabel picks the most human field for the case's display label.
func caseLabel(raw map[string]any) string {
	if src, ok := raw["source"].(map[string]any); ok {
		if t := asStr(src["title"]); t != "" {
			return t
		}
	}
	for _, k := range []string{"title", "topic", "question", "label", "name"} {
		if s := asStr(raw[k]); s != "" {
			if len(s) > 120 {
				s = s[:120] + "…"
			}
			return s
		}
	}
	return ""
}

// casebookVersionHistory describes how the eval-set itself evolved. We derive
// it from the loop's cycle dirs: each cycle that scored cases is a point in the
// casebook's life, annotated with the case-count seen that cycle. Plus the
// declared dataset versions from xpcloud.yaml/manifest.json as the lead note.
func casebookVersionHistory(appDir, loop string) []casebookVersionPoint {
	out := []casebookVersionPoint{}

	// Declared dataset version(s) → a single lead "declared" point (ts = "").
	if ds := declaredDatasets(appDir); len(ds) > 0 {
		notes := make([]string, 0, len(ds))
		for _, d := range ds {
			notes = append(notes, d)
		}
		out = append(out, casebookVersionPoint{Ts: "", Note: "declared: " + strings.Join(notes, ", ")})
	}

	// Per-cycle case-count from the regression sidecar (regression.json carries
	// `cases[]`). Walk the loop's cycle dirs (and the app's data/regression dirs)
	// oldest→newest; a change in n_cases is the casebook evolving.
	type cnt struct {
		ts string
		n  int
	}
	counts := []cnt{}
	regRoot := filepath.Join(appDir, "data", "regression")
	if ents, err := os.ReadDir(regRoot); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(regRoot, e.Name(), "regression.json"))
			if err != nil {
				continue
			}
			var reg map[string]any
			if json.Unmarshal(b, &reg) != nil {
				continue
			}
			n := 0
			if arr, ok := reg["cases"].([]any); ok {
				n = len(arr)
			}
			counts = append(counts, cnt{ts: e.Name(), n: n})
		}
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].ts < counts[j].ts })
	prev := -1
	for _, ct := range counts {
		if ct.n == prev {
			continue // only record points where the case-count moved
		}
		note := ""
		if prev >= 0 && ct.n > prev {
			note = "cases added"
		} else if prev >= 0 && ct.n < prev {
			note = "cases removed"
		} else {
			note = "casebook scored"
		}
		out = append(out, casebookVersionPoint{Ts: ct.ts, Note: note, NCases: ct.n})
		prev = ct.n
	}
	_ = loop // loop is accepted for API symmetry; regression sidecars are app-wide
	return out
}

// declaredDatasets reads datasets[] ids from xpcloud.yaml (preferred) or
// manifest.json. Best-effort: returns labels like "cases_v1 v1.0.0".
func declaredDatasets(appDir string) []string {
	// manifest.json is structured JSON — parse it directly.
	manifestPath, _ := ResolveManifestPath(appDir)
	if b, err := os.ReadFile(manifestPath); err == nil {
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			if arr, ok := m["datasets"].([]any); ok {
				out := []string{}
				for _, it := range arr {
					if d, ok := it.(map[string]any); ok {
						id := asStr(d["id"])
						ver := asStr(d["version"])
						if id != "" {
							if ver != "" {
								id += " v" + ver
							}
							out = append(out, id)
						}
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	// xpcloud.yaml fallback — a light line scan (no YAML dep in this package):
	// collect `- id: <x>` entries under a `datasets:` block.
	specPath, _ := ResolveSpecPath(appDir)
	if b, err := os.ReadFile(specPath); err == nil {
		out := []string{}
		inDS := false
		for _, raw := range strings.Split(string(b), "\n") {
			line := strings.TrimRight(raw, "\r")
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
				// a new top-level key — entering/leaving the datasets block
				inDS = strings.HasPrefix(trimmed, "datasets:")
				continue
			}
			if inDS && strings.HasPrefix(trimmed, "- id:") {
				id := strings.TrimSpace(strings.TrimPrefix(trimmed, "- id:"))
				if id != "" {
					out = append(out, id)
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// ── small local helpers (kept handler-local to avoid clashing with the
//    shared asString2/formatFloat in me_cycle.go) ──────────────────────────

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
}
func roundN(f float64, places int) float64 {
	p := 1.0
	for i := 0; i < places; i++ {
		p *= 10
	}
	return float64(int64(f*p+0.5*sign(f))) / p
}
func sign(f float64) float64 {
	if f < 0 {
		return -1
	}
	return 1
}
