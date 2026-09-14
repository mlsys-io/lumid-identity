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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

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
	// Cases/Description are WRITTEN into the spec by patch_experiment and were
	// never parsed back, so every read-then-rewrite verb (add_experiment_arm)
	// silently dropped them. For an experiment scoped by `cases` with no
	// `dataset_id` that is not even silent: the scheduler refuses a patch with
	// no scope, so adding an arm failed outright.
	Cases       []string `yaml:"cases" json:"cases,omitempty"`
	Description string   `yaml:"description" json:"description,omitempty"`
	// Dispatch — app-authored routing for "run this arm":
	//   loop: which attached loop a dispatch should use (defaults to the
	//         first attached loop; matters when several loops feed one
	//         experiment and only the batch one is self-sufficient);
	//   ask:  when present, the arm needs a SUBJECT the button cannot know
	//         (e.g. which strategy) — the UI hands dispatch to the chat rail
	//         with this question instead of firing a run that measures
	//         nothing. The surface shows; the chat acts.
	Dispatch map[string]any `yaml:"dispatch" json:"dispatch,omitempty"`
}

type expManifest struct {
	Experiments []expDecl `yaml:"experiments"`
	Loops       []struct {
		Name   string `yaml:"name"`
		Engine struct {
			Experiment expRef `yaml:"experiment"`
		} `yaml:"engine"`
		Steps []struct {
			Experiment expRef `yaml:"experiment"`
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
// expRef is one experiment id, or a list of them.
//
// A single loop can legitimately feed several experiments — quant-research's
// `backtest` loop measures both backtest_evidence (every resolved claim) and
// backtest_performance (only the three-axes-real subset). Decoding into a bare
// string made the list form unmarshal to empty, so the second experiment showed
// `loops: null`: never attached, never evaluated, permanently n=0 while looking
// merely idle.
type expRef []string

func (e *expRef) UnmarshalYAML(value *yaml.Node) error {
	var one string
	if err := value.Decode(&one); err == nil {
		if one != "" {
			*e = []string{one}
		}
		return nil
	}
	var many []string
	if err := value.Decode(&many); err != nil {
		return nil // malformed: attach nothing rather than fail the whole spec
	}
	*e = many
	return nil
}

func expLoops(m expManifest) map[string][]string {
	out := map[string][]string{}
	for _, l := range m.Loops {
		ids := map[string]bool{}
		for _, id := range l.Engine.Experiment {
			if id != "" {
				ids[id] = true
			}
		}
		for _, st := range l.Steps {
			for _, id := range st.Experiment {
				if id != "" {
					ids[id] = true
				}
			}
		}
		for id := range ids {
			out[id] = append(out[id], l.Name)
		}
	}
	return out
}

// readExpState returns one experiment's evaluated state.
//
// Disk first, then the self-reported copy in MySQL. The ledger is written on
// the SCHEDULER's volume and identity mounts no tenant volume, so for a tenant
// install the disk read finds identity's own materialised copy of the published
// bundle — declaration, never results. Disk still WINS when it has something,
// because an operator-shared app runs in the daemon's own HOME and that ledger
// is the freshest copy.
//
// userSub/app may be empty (callers that only have a directory); the fallback
// is simply skipped then.
func readExpState(appDir, id string) map[string]any {
	return readExpStateFor("", "", appDir, id)
}

func readExpStateFor(userSub, app, appDir, id string) map[string]any {
	st := map[string]any{}
	p, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "experiments", id, "state.json"))
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &st)
		// The DISK path carried no staleness marker at all, so exactly the
		// installs identity CAN read served a number with no way to tell how old
		// it was. Both sides now say when they were computed.
		if _, has := st["state_updated_at"]; !has {
			if u, ok := st["updated_at"].(string); ok && u != "" {
				st["state_updated_at"] = u
			}
		}
	}
	diskN, _ := st["n_results"].(float64)
	if userSub == "" || app == "" {
		return st // caller has only a directory; there is no DB row to prefer
	}
	stored := storedExpState(userSub, app, id)
	if stored == nil {
		return st
	}
	// NEWER WINS, not "disk wins if it has anything".
	//
	// The old rule returned the on-disk blob whenever it carried n_results > 0,
	// so a stale materialised copy beat a fresh DB row — which is the wrong way
	// round for the case that actually occurs: evaluate() runs on the SCHEDULER's
	// volume and bridges its result here, so the DB is the side that moves.
	// Measured 2026-09-09 for a3f48236: judge_panel_parity held 52 rows against
	// n=17 served, and kol_alpha 12 against 2.
	//
	// Compare the two blobs' OWN `updated_at` — both are written by evaluate(),
	// so it is one clock on both sides. The DB row's transport timestamp is not
	// comparable to it and is not used here.
	diskWhen, _ := st["updated_at"].(string)
	dbWhen, _ := stored["updated_at"].(string)
	if diskWhen != "" && dbWhen != "" {
		if diskWhen > dbWhen { // RFC3339 sorts lexically
			return st
		}
		return stored
	}
	// One side (or neither) is undated: fall back to "more results wins", which
	// is the old rule's intent without its assumption that disk is authoritative.
	dbN, _ := stored["n_results"].(float64)
	if diskN > dbN {
		return st
	}
	if dbN > 0 || diskN == 0 {
		return stored
	}
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
	rows, _ := readExpRowsCounted(appDir, id, capN)
	return rows
}

// readExpRowsCounted is readExpRows plus the TRUE number of rows in the ledger.
//
// The cap was applied after parsing the whole file and reported nowhere, so a
// long experiment served `n_results: 3000` (computed by evaluate() over every
// row) beside a 500-point series — two views of one experiment disagreeing by
// construction, with nothing on screen saying the second was a window. The
// per-case drill and the chat tool were clipped the same way.
//
// It also saved nothing: every line was still scanned and unmarshalled before
// being thrown away. Now the scan counts, and only the tail is unmarshalled.
func readExpRowsCounted(appDir, id string, capN int) ([]expRow, int) {
	p, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "experiments", id, "results.jsonl"))
	f, err := os.Open(p)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	// Pass 1: keep only the last capN LINES. Cheap — no JSON parsing — and it
	// is what bounds the work, which slicing after the fact never did.
	ring := make([]string, 0, capN+1)
	total := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		total++
		if capN > 0 {
			ring = append(ring, line)
			if len(ring) > capN {
				ring = ring[1:]
			}
		} else {
			ring = append(ring, line)
		}
	}
	// Pass 2: parse only what survived.
	rows := make([]expRow, 0, len(ring))
	for _, line := range ring {
		var r expRow
		if json.Unmarshal([]byte(line), &r) == nil {
			r.normalize()
			if r.VariantID != "" {
				rows = append(rows, r)
			}
		}
	}
	return rows, total
}

// loadAppExperiments — declarations merged with ledger state. Shared with
// the chat tools (list_experiments).
func loadAppExperiments(appDir string) []gin.H {
	return loadAppExperimentsFor("", "", appDir)
}

// loadAppExperimentsFor is the same, with the identity needed to fall back to
// the self-reported state when the ledger is on a volume identity cannot read.
// Callers that only have a directory (chat tools resolving an operator app) use
// loadAppExperiments and simply get the disk view.
func loadAppExperimentsFor(userSub, app, appDir string) []gin.H {
	m := readExpManifest(appDir)
	loops := expLoops(m)
	out := make([]gin.H, 0, len(m.Experiments))
	for _, d := range m.Experiments {
		if d.ID == "" {
			continue
		}
		st := readExpStateFor(userSub, app, appDir, d.ID)
		row := gin.H{
			"id": d.ID, "hypothesis": d.Hypothesis, "kind": d.Kind,
			"dataset_id": d.DatasetID, "metric": d.Metric,
			"benchmark_id": d.Benchmark, "baseline": d.Baseline,
			"success_criteria": d.Criteria, "min_samples": d.MinSamples,
			"status": strOr(d.Status, "active"),
			"loops":  loops[d.ID],
			// Carried for the same reason `arms` is: a verb that reads this row
			// and rewrites the whole experiments[] entry must be able to put
			// back everything it did not mean to change.
			"dispatch": d.Dispatch, "cases": d.Cases, "description": d.Description,
			// The DECLARED arms. expDecl has parsed these since it was written
			// and the row dropped them, so the only arms any client could see
			// were the ones already OBSERVED in state.variants — i.e. a
			// never-run arm was invisible, and nothing could offer to run it.
			// This is the backend half of per-arm dispatch.
			"arms":         d.Arms,
			"n_results":    0,
			"criteria_met": false,
		}
		if len(d.Dispatch) > 0 {
			row["dispatch"] = d.Dispatch
		}
		for _, k := range []string{
			"n_results", "variants", "best_variant", "baseline_value",
			"delta", "delta_pp", "criteria_met", "criteria_reason",
			"verdict", "updated_at", "metric", "higher_is_better",
			// Instrument/definition honesty, written by experiments.evaluate():
			// `comparable:false` means the ranking was withheld because the arms
			// were measured under different instruments — the client must not
			// render a winner in that case.
			"comparable", "instruments", "compare_within",
			"dataset_version", "dataset_versions_seen",
			// The metric keys the rows ACTUALLY carry, and why n is zero when
			// it is. Without these, `n_results: 0` reads identically whether
			// the loop has never run or the declared name matches nothing it
			// emits -- the shape that hid `real_tape_rate` for 19 runs. The
			// client needs them to offer real keys at define-time instead of
			// asking for a name typed from memory.
			"metric_keys_seen", "n_zero_reason",
			// When the state was computed — see storedExpState.
			"state_updated_at",
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
	return loadExperimentDetailFor("", "", appDir, id)
}

func loadExperimentDetailFor(userSub, app, appDir, id string) (gin.H, bool) {
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
	st := readExpStateFor(userSub, app, appDir, id)
	rows, rowsTotal := readExpRowsCounted(appDir, id, expResultsTailCap)
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
		// The ledger is served as a TAIL. Say so, and say how big the real
		// thing is: state.n_results is computed by evaluate() over every row,
		// so without this a long experiment shows `n_results: 3000` beside a
		// 500-point series and nothing explains the disagreement.
		"results_total":     rowsTotal,
		"results_truncated": rowsTotal > len(rows),
		"results_cap":       expResultsTailCap,
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
			// loadAppExperimentsFor, not loadAppExperiments: the identity-less
			// variant passes "" for userSub, which skips readExpStateFor's
			// Postgres fallback entirely. Identity mounts no tenant volume, so
			// the ledger is unreadable here and the fallback is the ONLY source
			// of n_results/variants/verdict -- this endpoint reported
			// `n_results: 0` for every tenant experiment while the DB held real
			// state, which is why /studio/experiments is numberless. Same fix
			// already applied to the chat tool (me_agent.go, list_experiments).
			exps := loadAppExperimentsFor(userID, e.Name(), filepath.Join(root, e.Name()))
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
	exps := loadAppExperimentsFor(userID, app, appDir)
	// What the PUBLISHED app declares that this install does not. The tab lists
	// the local bundle and had no way to say "there is another one you do not
	// have" — an experiment that lands upstream after you installed is
	// invisible until someone runs app_update and notices.
	localIDs := make([]string, 0, len(exps))
	for _, e := range exps {
		if id, _ := e["id"].(string); id != "" {
			localIDs = append(localIDs, id)
		}
	}
	resp := gin.H{"experiments": exps, "count": len(exps)}
	if d := experimentDivergenceFor(userID, app, localIDs); d != nil {
		resp["divergence"] = d
	}
	ok(c, "ok", resp)
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
	detail, found := loadExperimentDetailFor(userID, app, appDir, id)
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
	resp := gin.H{"case_id": caseID, "rows": caseRows, "latest_by_question": latestByQ}
	if len(caseRows) == 0 {
		// The per-case drill reads results.jsonl off disk with no DB fallback —
		// the aggregate state comes from the bridge, the ROWS do not. So an
		// empty answer here means "unreadable", not "this case was never
		// scored", and the two look the same.
		if why := unavailableReason(appDir, "per-case experiment rows"); why != "" {
			resp["unavailable"] = why
		}
	}
	ok(c, "ok", resp)
}

// ── arm resolution for dispatch ──────────────────────────────────────────────

// resolveExperimentArm looks up ONE declared arm of ONE experiment in the app's
// own spec, and reports which loop that experiment is attached to.
//
// Resolving against the manifest — rather than trusting the caller — is what
// keeps a dispatch honest. An arm id that does not exist must be refused BY
// NAME: the alternative is a cycle that runs the baseline and is then recorded
// under a label nobody declared, which is indistinguishable in the ledger from
// a real result. (The same failure the run-a-variant break produced for months,
// where unapplied variants landed as "current".)
//
// Returns (hypothesis, arm config minus its id/description, loop name).
func resolveExperimentArm(appDir, experimentID, armID string) (string, map[string]any, string, error) {
	m := readExpManifest(appDir)
	var decl *expDecl
	for i := range m.Experiments {
		if m.Experiments[i].ID == experimentID {
			decl = &m.Experiments[i]
			break
		}
	}
	if decl == nil {
		known := make([]string, 0, len(m.Experiments))
		for _, d := range m.Experiments {
			known = append(known, d.ID)
		}
		if len(known) == 0 {
			return "", nil, "", fmt.Errorf("this app declares no experiments")
		}
		return "", nil, "", fmt.Errorf("no experiment %q — declared: %s",
			experimentID, strings.Join(known, ", "))
	}
	var arm map[string]any
	names := make([]string, 0, len(decl.Arms))
	for _, a := range decl.Arms {
		id, _ := a["id"].(string)
		if id == "" {
			continue
		}
		names = append(names, id)
		if id == armID {
			arm = a
		}
	}
	if arm == nil {
		return "", nil, "", fmt.Errorf("experiment %q has no arm %q — declared: %s",
			experimentID, armID, strings.Join(names, ", "))
	}
	cfg := map[string]any{}
	for k, v := range arm {
		if k == "id" || k == "description" {
			continue
		}
		cfg[k] = v
	}
	// Which loop runs it. The declaration's dispatch.loop wins when it names
	// an ATTACHED loop — several loops can feed one experiment and only one
	// of them may be self-sufficient for a dispatch (mbb-consultant's
	// judge_panel_parity is fed by both `interview`, which needs a case, and
	// `case_eval`, whose defaults walk a bounded case subset on their own).
	// Falls back to the first attached loop, as before.
	loopName := ""
	attached := expLoops(m)[experimentID]
	if want, _ := decl.Dispatch["loop"].(string); want != "" {
		for _, l := range attached {
			if l == want {
				loopName = want
				break
			}
		}
	}
	if loopName == "" && len(attached) > 0 {
		loopName = attached[0]
	}
	return decl.Hypothesis, cfg, loopName, nil
}

// repeatVariant returns n copies of one variant — the enqueue contract is one
// entry per run, and each becomes its own queued unit so the drain's
// back-pressure (budget per tick, serial within an app) still applies.
func repeatVariant(v map[string]any, n int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, v)
	}
	return out
}

// splitCases turns "Case_001, Case_002" into a list, dropping blanks.
func splitCases(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ── cross-node experiment state ──────────────────────────────────────────────

type appExperimentBody struct {
	UserSub      string         `json:"user_sub"`
	App          string         `json:"app"`
	ExperimentID string         `json:"experiment_id"`
	State        map[string]any `json:"state"`
}

// InternalAppExperimentRecord — POST /api/v1/internal/app-experiments
//
// The cycle self-reports an experiment's evaluated state so identity can serve
// it. The ledger lives on the SCHEDULER's volume; identity mounts no tenant
// volume and therefore reads its own materialised copy of the published
// bundle, which carries the declaration and never the results. Without this the
// Experiments panel shows declared arms whose results can never appear —
// measured 2026-09-04, a real row on disk against n=0 over the API.
//
// Idempotent on (user_sub, app, experiment_id): each cycle overwrites with the
// freshly evaluated state, which is what evaluate() already does to state.json.
func InternalAppExperimentRecord(c *gin.Context) {
	var b appExperimentBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if b.UserSub == "" || b.App == "" || b.ExperimentID == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub, app, experiment_id required")
		return
	}
	sj := "{}"
	n := 0
	if b.State != nil {
		if raw, err := json.Marshal(b.State); err == nil {
			sj = string(raw)
		}
		if v, ok := b.State["n_results"].(float64); ok {
			n = int(v)
		}
	}
	row := models.MeAppExperiment{
		UserSub: b.UserSub, App: b.App, ExperimentID: b.ExperimentID,
		State: sj, NResults: n,
	}
	res := common.DB.Where("user_sub = ? AND app = ? AND experiment_id = ?",
		b.UserSub, b.App, b.ExperimentID).Assign(row).FirstOrCreate(&models.MeAppExperiment{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+res.Error.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "recorded",
		"data": gin.H{"app": b.App, "experiment_id": b.ExperimentID, "n_results": n}})
}

// storedExpState returns the self-reported state for one experiment, or nil.
//
// DISK WINS when it has rows: an operator-shared app runs in the daemon's own
// HOME, so identity can read that ledger directly and it is the freshest copy.
// The DB is the fallback for everything identity cannot see — which is every
// tenant install.
func storedExpState(userSub, app, experimentID string) map[string]any {
	var row models.MeAppExperiment
	q := common.DB.Where("user_sub = ? AND app = ? AND experiment_id = ?",
		userSub, app, experimentID).First(&row)
	if q.Error != nil || row.State == "" {
		return nil
	}
	var st map[string]any
	if json.Unmarshal([]byte(row.State), &st) != nil {
		return nil
	}
	// WHEN this was computed, not just what it says. The bridge only fires from
	// refresh_for_cycle, i.e. once per loop RUN, so a quiet experiment serves a
	// number that is arbitrarily old with nothing to say so. Measured 2026-09-09
	// for a3f48236: judge_panel_parity held 52 rows on the scheduler volume
	// against n=17 here, and kol_alpha 12 against 2 — both last pushed
	// 2026-09-05. The panel and the chat both quoted the stale figure as
	// current. Serving the timestamp lets a reader (and `list_experiments`)
	// tell "no results" from "no results SINCE".
	if st != nil && !row.UpdatedAt.IsZero() {
		st["state_updated_at"] = row.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return st
}
