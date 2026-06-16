package handler

// Variant trajectory tree — the data behind the Studio "trajectory" view.
//
//   GET /me/apps/:app/trajectory?loop=<loop>&experiment=<id>
//
// Each node is a config point an autoresearch loop explored. The whole thing
// is a tree: a baseline root, each cycle's variants branching off the running
// champion, the champion forming the trunk.
//
// Data lives at <appDir>/data/experiments/<experiment_id>/{state.json,
// results.jsonl}. Each results row is one variant trial:
//   {"ts":"…Z","variant_id":"44160e4d","metrics":{… maybe empty},
//    "variant":{… scalar config},"cycle_ts":"…"(sometimes),"dims":{…}}
// state.json carries {metric, higher_is_better, baseline_value, …}.
//
// Tree construction (see the per-section comments below):
//   1. pick the experiment (most results rows, or metric-matching) when
//      ?experiment= is absent;
//   2. group rows into cycles (cycle_ts, else day bucket of ts), chronological;
//   3. champion-so-far = best-scoring variant across all rows up to & including
//      a cycle; a variant's parent = the previous cycle's champion (baseline for
//      the first); is_champion on each cycle's best; depth = cycleIdx+1;
//   4. unscored variants (empty metrics — common) are included scored:false and
//      can never be champion;
//   5. baseline node at depth 0;
//   6. run_ts maps each variant to a cycle DIR under data/cycles/<loop>/ for the
//      pipeline drill-in (cycle_ts match, else latest dir <= variant ts);
//   7. per-cycle `learned` = sum of auto_publish.memories[*].pushed from the
//      champion's cycle.json.
//
// With NO experiments dir the view degrades to a LINEAR run chain built from
// the loop's cycle dirs (capped at cycleScanCap). Read-only, best-effort: any
// missing/odd shape yields defaults, never a 500.

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

const cycleScanCap = 120

type trajNode struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"` // baseline | variant | run
	VariantID  string         `json:"variant_id,omitempty"`
	CycleTs    string         `json:"cycle_ts,omitempty"`
	RunTs      string         `json:"run_ts,omitempty"`
	Depth      int            `json:"depth"`
	ParentID   string         `json:"parent_id,omitempty"`
	Label      string         `json:"label"`
	Config     map[string]any `json:"config,omitempty"`
	Score      *float64       `json:"score,omitempty"`
	Scored     bool           `json:"scored"`
	DeltaVsBaseline *float64  `json:"delta_vs_baseline,omitempty"`
	IsChampion bool           `json:"is_champion,omitempty"`
	DurationS  *float64       `json:"duration_s,omitempty"`
}

type trajCycle struct {
	Ts             string   `json:"ts"`
	NVariants      int      `json:"n_variants"`
	ChampionID     string   `json:"champion_id,omitempty"`
	ChampionScore  *float64 `json:"champion_score,omitempty"`
	Learned        int      `json:"learned"`
	BestDelta      *float64 `json:"best_delta,omitempty"`
	DurationS      *float64 `json:"duration_s,omitempty"`
}

// one variant trial after grouping (a single best-scored representative per
// variant_id within a cycle).
type trajVariant struct {
	variantID string
	cycleTs   string // the cycle bucket key
	ts        string // earliest row ts (for run_ts mapping)
	config    map[string]any
	score     float64
	scored    bool
}

// MeTrajectory — GET /me/apps/:app/trajectory?loop=<loop>&experiment=<id>
func MeTrajectory(c *gin.Context) {
	userID, ok2 := currentUserID(c)
	if !ok2 {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Query("loop")
	expWant := c.Query("experiment")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	if expWant != "" && !slugRe.MatchString(expWant) {
		fail(c, http.StatusBadRequest, 1400, "invalid experiment")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// 1. Pick the experiment dir.
	expID, expDir := pickExperiment(appDir, expWant)

	// Cycle dirs under data/cycles/<loop>/ (capped, oldest→newest) — used both
	// for run_ts mapping and the no-experiment linear fallback.
	cycleDirs := scanCycleDirs(appDir, loop)

	data := gin.H{
		"app":            app,
		"loop":           loop,
		"experiment_id":  expID,
		"cycle_scan_cap": cycleScanCap,
	}

	// per-request cache so variants sharing a cycle dir don't re-walk it.
	durCache := map[string]float64{}

	if expDir == "" {
		// 9. No experiments dir → linear run chain from cycle dirs.
		nodes, cycles := linearRunChain(appDir, loop, cycleDirs, durCache)
		data["has_variants"] = false
		data["nodes"] = nodes
		data["cycles"] = cycles
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": data})
		return
	}

	// 2. state.json → metric / higher_is_better / baseline.
	metric, higher, baseline, hasBaseline := readExperimentState(expDir)
	data["metric"] = metric
	data["higher_is_better"] = higher
	if hasBaseline {
		data["baseline"] = baseline
	} else {
		data["baseline"] = nil
	}

	// 3. results.jsonl → variants grouped into cycles.
	cycleKeys, byCycle := readVariantsGrouped(expDir, metric)

	data["has_variants"] = len(cycleKeys) > 0

	nodes := []trajNode{}
	cycles := []trajCycle{}

	// 6. baseline node.
	nodes = append(nodes, trajNode{
		ID: "baseline", Kind: "baseline", Depth: 0, Label: "baseline",
		Scored: hasBaseline,
		Score:  ifPtr(hasBaseline, baseline),
	})

	// 4. Champion lineage. champion-so-far across all rows up to & including the
	// current cycle; a variant's parent = the PREVIOUS cycle's champion (baseline
	// for the first cycle).
	betterThan := func(a, b float64) bool {
		if higher {
			return a > b
		}
		return a < b
	}
	prevChampionID := "baseline"
	for ci, ck := range cycleKeys {
		vs := byCycle[ck]
		// best scored variant of THIS cycle (the cycle champion).
		cycleChampIdx := -1
		for i := range vs {
			if !vs[i].scored {
				continue
			}
			if cycleChampIdx < 0 || betterThan(vs[i].score, vs[cycleChampIdx].score) {
				cycleChampIdx = i
			}
		}
		cyc := trajCycle{Ts: ck, NVariants: len(vs)}
		for i := range vs {
			v := vs[i]
			n := trajNode{
				ID:        "v:" + v.variantID,
				Kind:      "variant",
				VariantID: v.variantID,
				CycleTs:   v.cycleTs,
				Depth:     ci + 1,
				ParentID:  prevChampionID,
				Label:     variantLabel(v.config),
				Config:    v.config,
				Scored:    v.scored,
				RunTs:     mapRunTs(cycleDirs, v.cycleTs, v.ts),
			}
			// Distinct id when the same variant_id recurs across cycles (mbb-ai's
			// "current") so nodes don't collide.
			if len(cycleKeys) > 1 {
				n.ID = "v:" + v.variantID + "@" + ck
			}
			if v.scored {
				sc := v.score
				n.Score = &sc
				if hasBaseline {
					d := roundN(sc-baseline, 4)
					n.DeltaVsBaseline = &d
				}
			}
			// execution time — wall-clock file span of the run's cycle dir.
			if n.RunTs != "" {
				if dur := durationAtRunTs(appDir, loop, n.RunTs, durCache); dur > 0 {
					n.DurationS = &dur
				}
			}
			if i == cycleChampIdx {
				n.IsChampion = true
				cyc.ChampionID = n.ID
				sc := v.score
				cyc.ChampionScore = &sc
				if hasBaseline {
					d := roundN(sc-baseline, 4)
					cyc.BestDelta = &d
				}
				if n.DurationS != nil {
					dv := *n.DurationS
					cyc.DurationS = &dv
				}
				prevChampionID = n.ID
				// 8. learned — memories pushed by this cycle's champion run.
				cyc.Learned = learnedAtRunTs(appDir, loop, n.RunTs)
			}
			nodes = append(nodes, n)
		}
		cycles = append(cycles, cyc)
	}

	data["nodes"] = nodes
	data["cycles"] = cycles
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": data})
}

// pickExperiment resolves the experiment dir. When `want` is set and exists,
// use it. Otherwise prefer the dir whose results.jsonl has the most rows; tie /
// no rows → the one whose state metric is non-empty. Returns ("","") if none.
func pickExperiment(appDir, want string) (string, string) {
	expRoot := filepath.Join(appDir, "data", "experiments")
	if want != "" {
		d := filepath.Join(expRoot, want)
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return want, d
		}
	}
	ents, err := os.ReadDir(expRoot)
	if err != nil {
		return "", ""
	}
	bestID, bestDir, bestRows := "", "", -1
	for _, e := range ents {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		d := filepath.Join(expRoot, e.Name())
		rows := countLines(filepath.Join(d, "results.jsonl"))
		// metric-bearing state nudges ties (rows+1 so a scored exp beats an empty).
		m, _, _, _ := readExperimentState(d)
		if m != "" {
			rows++
		}
		if rows > bestRows {
			bestRows, bestID, bestDir = rows, e.Name(), d
		}
	}
	return bestID, bestDir
}

// readExperimentState pulls metric / higher_is_better / baseline_value.
func readExperimentState(expDir string) (metric string, higher bool, baseline float64, hasBaseline bool) {
	higher = true // sensible default
	b, err := os.ReadFile(filepath.Join(expDir, "state.json"))
	if err != nil {
		return
	}
	var st map[string]any
	if json.Unmarshal(b, &st) != nil {
		return
	}
	metric = asStr(st["metric"])
	if v, ok2 := st["higher_is_better"].(bool); ok2 {
		higher = v
	}
	if v, ok2 := toFloat(st["baseline_value"]); ok2 {
		baseline = roundN(v, 6)
		hasBaseline = true
	}
	return
}

// readVariantsGrouped reads results.jsonl and groups variant trials into cycles
// (cycle_ts when present, else ts[:10] day bucket). Within a cycle, rows sharing
// a variant_id collapse to one representative carrying the best usable score
// (mbb-ai writes many per-question rows + an aggregate row per cycle). Returns
// the cycle keys oldest→newest and the per-cycle variant slices.
func readVariantsGrouped(expDir, metric string) ([]string, map[string][]trajVariant) {
	byCycle := map[string]map[string]*trajVariant{} // cycleKey -> variantID -> agg
	cycleSeen := map[string]bool{}
	cycleOrder := []string{}

	f, err := os.Open(filepath.Join(expDir, "results.jsonl"))
	if err != nil {
		return nil, map[string][]trajVariant{}
	}
	defer f.Close()
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
		vid := asStr(row["variant_id"])
		if vid == "" {
			vid = "v"
		}
		rowTs := asStr(row["ts"])
		ck := asStr(row["cycle_ts"])
		if ck == "" {
			// day bucket — keep it human/sortable.
			if len(rowTs) >= 10 {
				ck = rowTs[:10]
			} else {
				ck = rowTs
			}
		}
		if !cycleSeen[ck] {
			cycleSeen[ck] = true
			cycleOrder = append(cycleOrder, ck)
			byCycle[ck] = map[string]*trajVariant{}
		}
		agg := byCycle[ck][vid]
		if agg == nil {
			agg = &trajVariant{variantID: vid, cycleTs: asStr(row["cycle_ts"]), ts: rowTs}
			byCycle[ck][vid] = agg
		}
		// earliest ts for stable run_ts mapping
		if rowTs != "" && (agg.ts == "" || rowTs < agg.ts) {
			agg.ts = rowTs
		}
		// config: first non-empty variant{} wins (scalar fields only).
		if agg.config == nil {
			if cfg, okc := row["variant"].(map[string]any); okc {
				agg.config = scalarConfig(cfg)
			}
		}
		// score: prefer a row that carries the experiment's primary metric;
		// otherwise the first scored row. metrics often empty → stays unscored.
		if metrics, okm := row["metrics"].(map[string]any); okm && len(metrics) > 0 {
			sc, key := pickScore(metrics, metric)
			if key != "" {
				if !agg.scored || (metric != "" && key == metric) {
					agg.score = sc
					agg.scored = true
				}
			}
		}
	}

	sort.Strings(cycleOrder)
	out := map[string][]trajVariant{}
	for _, ck := range cycleOrder {
		vs := make([]trajVariant, 0, len(byCycle[ck]))
		for _, v := range byCycle[ck] {
			vs = append(vs, *v)
		}
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].ts != vs[j].ts {
				return vs[i].ts < vs[j].ts
			}
			return vs[i].variantID < vs[j].variantID
		})
		out[ck] = vs
	}
	return cycleOrder, out
}

// scalarConfig keeps only scalar config fields (string/number/bool) so the UI
// renders a chip row, not nested structures.
func scalarConfig(cfg map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range cfg {
		switch v.(type) {
		case string, float64, bool:
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// variantLabel humanizes a config: "<component> · <model>" when present, else
// the first one-two scalar config values.
func variantLabel(cfg map[string]any) string {
	if cfg == nil {
		return "variant"
	}
	comp := asStr(cfg["component"])
	model := shortModel(asStr(cfg["model"]))
	switch {
	case comp != "" && model != "":
		return comp + " · " + model
	case comp != "":
		return comp
	case model != "":
		return model
	}
	// first 1-2 scalar values (stable by key order).
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		if s := asString2(cfg[k]); s != "" {
			parts = append(parts, s)
		}
		if len(parts) >= 2 {
			break
		}
	}
	if len(parts) == 0 {
		return "variant"
	}
	return truncate(strings.Join(parts, " · "), 60)
}

// shortModel trims a verbose model id (claude-haiku-4-5 → haiku) for the label.
func shortModel(m string) string {
	if m == "" {
		return ""
	}
	for _, fam := range []string{"haiku", "sonnet", "opus"} {
		if strings.Contains(m, fam) {
			return fam
		}
	}
	return m
}

// scanCycleDirs returns the loop's cycle dir names under data/cycles/<loop>/,
// sorted oldest→newest, capped at cycleScanCap (keeping the most recent).
func scanCycleDirs(appDir, loop string) []string {
	if loop == "" {
		return nil
	}
	root := filepath.Join(appDir, "data", "cycles", loop)
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	dirs := []string{}
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	if len(dirs) > cycleScanCap {
		dirs = dirs[len(dirs)-cycleScanCap:]
	}
	return dirs
}

// mapRunTs maps a variant to a cycle DIR id for the pipeline drill-in: an exact
// cycle_ts match if present, else the latest dir whose id is <= the variant ts.
// "" when nothing maps. cycleDirs is sorted oldest→newest.
func mapRunTs(cycleDirs []string, cycleTs, variantTs string) string {
	if len(cycleDirs) == 0 {
		return ""
	}
	if cycleTs != "" {
		for _, d := range cycleDirs {
			if d == cycleTs {
				return d
			}
		}
	}
	// latest dir <= variantTs (cycle-dir ids and the ISO ts are both
	// lexicographically time-ordered enough for "compress to digits" compare).
	if variantTs == "" {
		return ""
	}
	vKey := digitsOnly(variantTs)
	best := ""
	for _, d := range cycleDirs {
		if digitsOnly(d) <= vKey {
			best = d
		}
	}
	return best
}

// durationAtRunTs estimates a cycle's execution time as the wall-clock FILE SPAN
// of its cycle dir: newest file mtime − oldest file mtime, in seconds. The
// command-engine cycle.json carries no duration; the dir-name→mtime delta is
// polluted by the scheduled-vs-actual offset, so we use the file span instead.
// Returns 0 when runTs is empty, the dir is missing, or fewer than 2 files.
// Results are cached per runTs (variants sharing a cycle don't re-walk).
func durationAtRunTs(appDir, loop, runTs string, cache map[string]float64) float64 {
	if loop == "" || runTs == "" {
		return 0
	}
	if cache != nil {
		if v, ok2 := cache[runTs]; ok2 {
			return v
		}
	}
	span := 0.0
	dir := filepath.Join(appDir, "data", "cycles", loop, runTs)
	ents, err := os.ReadDir(dir)
	if err == nil {
		var minT, maxT time.Time
		n := 0
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			st, serr := os.Stat(filepath.Join(dir, e.Name()))
			if serr != nil {
				continue
			}
			mt := st.ModTime()
			if n == 0 || mt.Before(minT) {
				minT = mt
			}
			if n == 0 || mt.After(maxT) {
				maxT = mt
			}
			n++
		}
		if n >= 2 {
			if d := maxT.Sub(minT).Seconds(); d > 0 {
				span = roundN(d, 3)
			}
		}
	}
	if cache != nil {
		cache[runTs] = span
	}
	return span
}

// learnedAtRunTs sums auto_publish.memories[*].pushed from a run's cycle.json.
func learnedAtRunTs(appDir, loop, runTs string) int {
	if loop == "" || runTs == "" {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(appDir, "data", "cycles", loop, runTs, "cycle.json"))
	if err != nil {
		return 0
	}
	var cj map[string]any
	if json.Unmarshal(b, &cj) != nil {
		return 0
	}
	return sumPushed(cj)
}

// sumPushed totals auto_publish.memories[*].pushed in a parsed cycle.json.
func sumPushed(cj map[string]any) int {
	ap, ok2 := cj["auto_publish"].(map[string]any)
	if !ok2 {
		return 0
	}
	mem, ok2 := ap["memories"].(map[string]any)
	if !ok2 {
		return 0
	}
	total := 0
	for _, v := range mem {
		if m, okm := v.(map[string]any); okm {
			if p, okp := toFloat(m["pushed"]); okp {
				total += int(p)
			}
		}
	}
	return total
}

// linearRunChain builds the degraded view for apps with NO experiments dir:
// each cycle dir is one kind:"run" node, parent = the previous cycle's node,
// depth = index, score = the cycle's primary numeric metric (scored if any),
// run_ts = the cycle dir, label = a short date. No baseline node (no baseline
// to anchor to). cycleDirs is oldest→newest.
func linearRunChain(appDir, loop string, cycleDirs []string, durCache map[string]float64) ([]trajNode, []trajCycle) {
	nodes := []trajNode{}
	cycles := []trajCycle{}
	parent := ""
	for i, ts := range cycleDirs {
		score, scored := cycleScore(appDir, loop, ts)
		n := trajNode{
			ID:       "run:" + ts,
			Kind:     "run",
			CycleTs:  ts,
			RunTs:    ts,
			Depth:    i,
			ParentID: parent,
			Label:    shortDate(ts),
			Scored:   scored,
		}
		if scored {
			sc := score
			n.Score = &sc
		}
		if dur := durationAtRunTs(appDir, loop, ts, durCache); dur > 0 {
			n.DurationS = &dur
		}
		nodes = append(nodes, n)
		cyc := trajCycle{Ts: ts, NVariants: 1, ChampionID: n.ID, Learned: learnedAtRunTs(appDir, loop, ts)}
		if scored {
			sc := score
			cyc.ChampionScore = &sc
		}
		if n.DurationS != nil {
			dv := *n.DurationS
			cyc.DurationS = &dv
		}
		cycles = append(cycles, cyc)
		parent = n.ID
	}
	return nodes, cycles
}

// cycleScore reads a cycle.json's primary numeric metric (first non-bookkeeping
// numeric in metrics{}). Returns (value, true) when one is found.
func cycleScore(appDir, loop, ts string) (float64, bool) {
	b, err := os.ReadFile(filepath.Join(appDir, "data", "cycles", loop, ts, "cycle.json"))
	if err != nil {
		return 0, false
	}
	var cj map[string]any
	if json.Unmarshal(b, &cj) != nil {
		return 0, false
	}
	m, ok2 := cj["metrics"].(map[string]any)
	if !ok2 {
		return 0, false
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.HasPrefix(k, "xpio_ingested") || strings.HasPrefix(k, "auto_reflect") {
			continue
		}
		if v, okv := toFloat(m[k]); okv {
			return roundN(v, 4), true
		}
	}
	return 0, false
}

// ── tiny local helpers (no clash with package-shared asStr/toFloat/roundN/
//    pickScore/itoa/truncate/asString2) ──────────────────────────────────────

// ifPtr returns &v when cond, else nil — for omit-when-absent score pointers.
func ifPtr(cond bool, v float64) *float64 {
	if !cond {
		return nil
	}
	return &v
}

// digitsOnly keeps only digits so an ISO ts ("2026-06-12T01:33:42Z") and a
// cycle dir id ("20260612T013342Z") compare consistently.
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// shortDate renders a cycle dir id / day bucket as a compact label.
func shortDate(ts string) string {
	d := digitsOnly(ts)
	if len(d) >= 8 {
		return d[0:4] + "-" + d[4:6] + "-" + d[6:8]
	}
	return ts
}

// countLines counts non-empty lines in a file (best-effort, 0 on error).
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n
}
