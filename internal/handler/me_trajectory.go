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
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const cycleScanCap = 120

// appAgentMemoryTimes loads, across the app's declared memory_agents, the sorted
// epoch-seconds of every banked memory's created_at. Used to derive a per-node
// "agent version" = how many memories the agent had banked at/by a given run.
// Tenant bank first (~/.tenants/<sub>/.xp/kg/...), then the operator bank.
func appAgentMemoryTimes(userID, appDir string) []float64 {
	specPath, _ := ResolveSpecPath(appDir)
	var times []float64
	for _, ag := range readYamlMemoryAgents(specPath) {
		bankPath := ""
		if d, ok := tenantKGBankDir(userID, ag); ok {
			bankPath = filepath.Join(d, "bank.jsonl")
		} else if d, ok := KGBankDir(ag); ok {
			bankPath = filepath.Join(d, "bank.jsonl")
		}
		if bankPath == "" {
			continue
		}
		f, err := os.Open(bankPath)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for sc.Scan() {
			var raw map[string]any
			if json.Unmarshal(sc.Bytes(), &raw) != nil {
				continue
			}
			// created_at is ISO string in some banks, float epoch in others.
			switch v := raw["created_at"].(type) {
			case string:
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					times = append(times, float64(t.Unix()))
				}
			case float64:
				if v > 0 {
					times = append(times, v)
				}
			}
		}
		f.Close()
	}
	sort.Float64s(times)
	return times
}

// declaredDataVersion returns the workflow's declared dataset version ("v<sem>")
// — the first top-level datasets[] entry — or "" when the app mounts no dataset.
func declaredDataVersion(appDir string) string {
	for _, d := range readAppDatasets(appDir) {
		if d.Version != "" {
			return "v" + d.Version
		}
	}
	return ""
}

// dataVersionAtRunTs returns the dataset version this run was evaluated on:
// authoritative from cycle.json assets_used.dataset.version when present, else
// the workflow's declared version (`fallback`).
func dataVersionAtRunTs(appDir, loop, runTs, fallback string) string {
	if runTs != "" {
		cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
		if b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, runTs, "cycle.json")); err == nil {
			var cj struct {
				AssetsUsed struct {
					Dataset struct {
						Version string `json:"version"`
					} `json:"dataset"`
				} `json:"assets_used"`
			}
			if json.Unmarshal(b, &cj) == nil && cj.AssetsUsed.Dataset.Version != "" {
				return "v" + cj.AssetsUsed.Dataset.Version
			}
		}
	}
	return fallback
}

// modelLabel collapses a raw model id to a glanceable family label
// (gemma / claude / minimax / gpt), for the run-tree node chip.
func modelLabel(k string) string {
	k = strings.ToLower(k)
	if i := strings.LastIndexByte(k, '/'); i >= 0 {
		k = k[i+1:] // drop owner prefix (cyankiwi/MiniMax… → minimax…)
	}
	switch {
	case strings.Contains(k, "gemma"):
		return "gemma"
	case strings.Contains(k, "claude"), strings.Contains(k, "sonnet"), strings.Contains(k, "haiku"), strings.Contains(k, "opus"):
		return "claude"
	case strings.Contains(k, "minimax"):
		return "minimax"
	case strings.Contains(k, "gpt"), strings.Contains(k, "openai"):
		return "gpt"
	}
	if i := strings.IndexByte(k, '-'); i > 0 {
		return k[:i]
	}
	return k
}

// parseAnalystModel pulls `analyst_model` from an interview_report markdown
// (a line like "- **analyst_model**: `gemma-4-26B`").
func parseAnalystModel(b []byte) string {
	s := string(b)
	i := strings.Index(s, "analyst_model")
	if i < 0 {
		return ""
	}
	r := s[i:]
	a := strings.IndexByte(r, '`')
	if a < 0 {
		return ""
	}
	r = r[a+1:]
	z := strings.IndexByte(r, '`')
	if z < 0 {
		return ""
	}
	return r[:z]
}

// appRunModels maps a run's cycle_ts prefix → short model label, read from the
// per-case interview reports (outbox/<case>/<ts>/interview_report_*.md). One
// report per distinct run is read. This is the exact per-run model — including
// sweep runs that wrote no cycle dir (so cost.by_model is unavailable).
func appRunModels(appDir string) map[string]string {
	out := map[string]string{}
	for _, root := range []string{filepath.Join(appDir, ".lumid", "outbox"), filepath.Join(appDir, "data", "outbox")} {
		cases, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, cdir := range cases {
			if !cdir.IsDir() {
				continue
			}
			tsDirs, _ := os.ReadDir(filepath.Join(root, cdir.Name()))
			for _, td := range tsDirs {
				if !td.IsDir() {
					continue
				}
				key := td.Name()
				if i := strings.IndexByte(key, '_'); i > 0 {
					key = key[:i] // cycle_ts prefix (drop the _<µs>Z suffix)
				}
				if _, ok := out[key]; ok {
					continue
				}
				ents, _ := os.ReadDir(filepath.Join(root, cdir.Name(), td.Name()))
				for _, e := range ents {
					if strings.HasPrefix(e.Name(), "interview_report") && strings.HasSuffix(e.Name(), ".md") {
						if b, rerr := os.ReadFile(filepath.Join(root, cdir.Name(), td.Name(), e.Name())); rerr == nil {
							if m := parseAnalystModel(b); m != "" {
								out[key] = modelLabel(m)
							}
						}
						break
					}
				}
			}
		}
	}
	return out
}

// modelFromCycleJson reads cost.by_model from a run's cycle.json (runs that wrote
// a cycle dir). Best-effort fallback when no interview report exists.
func modelFromCycleJson(appDir, loop, runTs string) string {
	if runTs == "" {
		return ""
	}
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, runTs, "cycle.json"))
	if err != nil {
		return ""
	}
	var cj struct {
		Cost struct {
			ByModel map[string]json.RawMessage `json:"by_model"`
		} `json:"cost"`
	}
	if json.Unmarshal(b, &cj) != nil {
		return ""
	}
	for k := range cj.Cost.ByModel {
		return modelLabel(k)
	}
	return ""
}

// modelForNode prefers the exact interview-report model (by cycle_ts), else the
// cycle.json cost.by_model at the mapped run dir.
func modelForNode(appDir, loop, cycleTs, runTs string, runModels map[string]string) string {
	if cycleTs != "" {
		if m := runModels[strings.TrimSuffix(cycleTs, "Z")]; m != "" {
			return m
		}
	}
	return modelFromCycleJson(appDir, loop, runTs)
}

// branchKeyForNode computes a run's CONFIGURATION SIGNATURE — the set of axes
// whose change forks a new branch in the run tree:
//   - model (gemma / claude / …)
//   - dataset version it ran on
//   - the prompt set (content SHAs) from cycle.json assets_used, when recorded
//
// Switching ANY of these = a branch; an unchanged signature = continue the same
// branch; returning to a prior signature continues THAT branch. Deliberately
// EXCLUDED: the agent's knowledge-bank version (it grows every run — that's
// evolution ALONG a branch, not a branch axis) and the workflow (each workflow
// is its own trajectory). Best-effort: missing provenance degrades to model+data.
func branchKeyForNode(appDir, loop, cycleTs, runTs string, runModels map[string]string, fallbackData string) string {
	model := modelForNode(appDir, loop, cycleTs, runTs, runModels)
	data := dataVersionAtRunTs(appDir, loop, runTs, fallbackData)
	promptSig := ""
	if runTs != "" {
		cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
		if b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, runTs, "cycle.json")); err == nil {
			var cj struct {
				AssetsUsed struct {
					Prompts map[string]string `json:"prompts"`
					Model   string            `json:"model"`
				} `json:"assets_used"`
			}
			if json.Unmarshal(b, &cj) == nil {
				if model == "" && cj.AssetsUsed.Model != "" {
					model = modelLabel(cj.AssetsUsed.Model)
				}
				if len(cj.AssetsUsed.Prompts) > 0 {
					keys := make([]string, 0, len(cj.AssetsUsed.Prompts))
					for k := range cj.AssetsUsed.Prompts {
						keys = append(keys, k)
					}
					sort.Strings(keys)
					var sb strings.Builder
					for _, k := range keys {
						sha := cj.AssetsUsed.Prompts[k]
						if len(sha) > 8 {
							sha = sha[:8]
						}
						sb.WriteString(k)
						sb.WriteByte('=')
						sb.WriteString(sha)
						sb.WriteByte(';')
					}
					promptSig = sb.String()
				}
			}
		}
	}
	return "m:" + model + "|d:" + data + "|p:" + promptSig
}

// assignNodeVersions stamps every real (non-baseline) node with a sequential
// version "v<N>" in chronological order. The run tree IS the agent's version
// history, so each node is its OWN distinct version. This supersedes the
// bank-memory-count derivation (agentVersionAt), which collapses to a single
// version — e.g. mbb-ai's all-"v36" — whenever the runs don't bank NEW memories
// (the bank was seeded once, well before these runs). Versions are global and
// unique across branches so a node can be referenced unambiguously.
func assignNodeVersions(nodes []trajNode) {
	idx := make([]int, 0, len(nodes))
	for i := range nodes {
		if nodes[i].Kind == "baseline" {
			continue
		}
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ka, kb := versionSortKey(nodes[idx[a]]), versionSortKey(nodes[idx[b]])
		if ka != kb {
			return ka < kb
		}
		return nodes[idx[a]].ID < nodes[idx[b]].ID
	})
	for rank, i := range idx {
		nodes[i].AgentVersion = "v" + strconv.Itoa(rank+1)
	}
}

// versionSortKey orders nodes chronologically for version numbering (run dir id,
// then cycle ts, both reduced to digits so ISO and dir-id forms compare).
func versionSortKey(n trajNode) string {
	if n.RunTs != "" {
		return digitsOnly(n.RunTs)
	}
	if n.CycleTs != "" {
		return digitsOnly(n.CycleTs)
	}
	return ""
}

// agentVersionAt returns the fixed agent version for a node — "v<N>" where N is
// the number of memories banked at/by cycleTs (dir-id form 20060102T150405Z).
// "" when there are no memory agents / nothing banked yet / unparseable ts.
func agentVersionAt(times []float64, cycleTs string) string {
	if len(times) == 0 || cycleTs == "" {
		return ""
	}
	t, err := time.Parse("20060102T150405Z", cycleTs)
	if err != nil {
		return ""
	}
	cut := float64(t.Unix())
	n := sort.Search(len(times), func(i int) bool { return times[i] > cut })
	if n == 0 {
		return ""
	}
	return "v" + strconv.Itoa(n)
}

type trajNode struct {
	ID              string         `json:"id"`
	Kind            string         `json:"kind"` // baseline | variant | run
	VariantID       string         `json:"variant_id,omitempty"`
	CycleTs         string         `json:"cycle_ts,omitempty"`
	RunTs           string         `json:"run_ts,omitempty"`
	Depth           int            `json:"depth"`
	ParentID        string         `json:"parent_id,omitempty"`
	Label           string         `json:"label"`
	Config          map[string]any `json:"config,omitempty"`
	Score           *float64       `json:"score,omitempty"`
	Scored          bool           `json:"scored"`
	DeltaVsBaseline *float64       `json:"delta_vs_baseline,omitempty"`
	IsChampion      bool           `json:"is_champion,omitempty"`
	DurationS       *float64       `json:"duration_s,omitempty"`
	// NeedsDecision: the run has pending advisor suggestions / offers or a
	// held review_queue item awaiting a human decision (drives the canvas
	// "needs-attention" badge).
	NeedsDecision bool `json:"needs_decision,omitempty"`
	// AgentVersion: this node's version in the agent's history — "v<N>", N = the
	// run's 1-based chronological rank in this trajectory (assignNodeVersions).
	// The run tree IS the version history, so every node is a distinct version;
	// versions are global + unique across branches. (Supersedes the old
	// bank-memory-count derivation, which collapsed to one version when runs
	// banked nothing new.)
	AgentVersion string `json:"agent_version,omitempty"`
	// DataVersion: the dataset version this run was evaluated on ("v<semver>").
	// Authoritative from cycle.json assets_used; falls back to the workflow's
	// declared dataset version (the repo is fixed per workflow, version pinned
	// per run). The metric on this node is scored on this data version.
	DataVersion string `json:"data_version,omitempty"`
	// Model: the LLM this run used (short label — "gemma" / "claude" / …), so
	// gemma vs claude runs are distinguishable at a glance. From the run's
	// interview report (analyst_model) or cycle.json cost.by_model. A change of
	// model forks a new branch; the same model continues its own branch.
	Model string `json:"model,omitempty"`
	// Learned: memories this run banked (auto_publish pushed). Carried on the node
	// itself so the UI doesn't have to index cycles[] by depth — depth is no
	// longer the cycle index once runs branch by model.
	Learned int `json:"learned,omitempty"`
}

type trajCycle struct {
	Ts            string   `json:"ts"`
	NVariants     int      `json:"n_variants"`
	ChampionID    string   `json:"champion_id,omitempty"`
	ChampionScore *float64 `json:"champion_score,omitempty"`
	Learned       int      `json:"learned"`
	BestDelta     *float64 `json:"best_delta,omitempty"`
	DurationS     *float64 `json:"duration_s,omitempty"`
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
		// Cross-node: trajectory is runtime data on the PVC identity can't read.
		// Reconstruct from the run store (me_app_runs) — the cross-node channel
		// the cycle self-reports to. App-agnostic. Empty until a run reports.
		nodes, cycles := trajNodesFromRuns(appRunsFor(userID, app, loop), loopMetricName(userID, app, loop))
		assignNodeVersions(nodes)
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
			"has_variants": false, "nodes": nodes, "cycles": cycles,
		}})
		return
	}

	// 1. Pick the experiment dir — strictly the selected loop's declared
	//    experiment (metrics are workflow-bound; data is shared). No loop
	//    given → fall back to most-rows (back-compat).
	loopExps := loopExperiments(appDir, loop)
	expAllow := map[string]bool{}
	for _, x := range loopExps {
		expAllow[x] = true
	}
	expID, expDir := pickExperiment(appDir, expWant, expAllow, loop != "")

	// Cycle dirs under data/cycles/<loop>/ (capped, oldest→newest) — used both
	// for run_ts mapping and the no-experiment linear fallback.
	cycleDirs := scanCycleDirs(appDir, loop)

	// Agent-version source: the sorted banked-memory timestamps across the app's
	// memory_agents. Each node's agent version = how many were banked by its run.
	memTimes := appAgentMemoryTimes(userID, appDir)
	// The workflow's declared dataset version — the per-run fallback when a run
	// didn't record its own (assets_used) data version.
	declaredDataVer := declaredDataVersion(appDir)
	// Per-run model labels (gemma / claude / …), keyed by cycle_ts prefix.
	runModels := appRunModels(appDir)

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
		nodes, cycles := linearRunChain(appDir, loop, cycleDirs, durCache, memTimes, declaredDataVer, runModels)
		if len(nodes) == 0 {
			// resolveAppDir returned identity's MATERIALIZED BUNDLE CACHE —
			// non-empty, so the appDir=="" cross-node fallback above never
			// fired, and this branch walked the cache's (empty) runtime dirs:
			// the workflow page rendered "No run trajectory yet" for a tenant
			// loop with hundreds of DB-recorded runs (observed live
			// 2026-09-05, quant-research.backtest). A cache directory is not
			// run evidence; when the disk yields nothing, reconstruct from
			// the run store exactly as the no-dir path does.
			nodes, cycles = trajNodesFromRuns(appRunsFor(userID, app, loop), loopMetricName(userID, app, loop))
		}
		assignNodeVersions(nodes)
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

	// 3. results.jsonl → per-case rows → consolidated into ROUNDS (a round = a full
	//    pass over the casebook). A per-case loop emits one cycle_ts PER case, so we
	//    break a round when a case REPEATS (a new pass began). Each round = one run
	//    node scored as the MEAN over its cases. Rounds are grouped into cycles (by
	//    their run) and laid out with model/config BRANCHING: consecutive runs of
	//    the same signature chain; a different model/config forks a new branch.
	rows := readCaseRows(expDir, metric)
	data["has_variants"] = len(rows) > 0

	// 3a. round-consolidate per variant_id (case-repeat = a new pass).
	type rnd struct {
		vid, firstTs, firstCycleTs string
		seen                       map[string]bool
		sum                        float64
		n                          int
		config                     map[string]any
	}
	var rounds []*rnd
	cur := map[string]*rnd{}
	for _, r := range rows {
		key := r.caseID
		if key == "" {
			key = r.ts
		}
		g := cur[r.vid]
		if g == nil || g.seen[key] {
			g = &rnd{vid: r.vid, firstTs: r.ts, firstCycleTs: r.cycleTs, seen: map[string]bool{}, config: r.config}
			cur[r.vid] = g
			rounds = append(rounds, g)
		}
		if g.config == nil && r.config != nil {
			g.config = r.config
		}
		g.seen[key] = true
		if r.scored {
			g.sum += r.score
			g.n++
		}
	}

	// 3b. group rounds into cycles by their representative run; a cycle holds the
	//     variant-rounds that ran together (an A/B fan); most apps = one per cycle.
	cycleKeys := []string{}
	byCycle := map[string][]trajVariant{}
	for _, g := range rounds {
		ck := g.firstCycleTs
		if ck == "" {
			ck = g.firstTs
		}
		tv := trajVariant{variantID: g.vid, cycleTs: g.firstCycleTs, ts: g.firstTs, config: g.config}
		if g.n > 0 {
			tv.score = roundN(g.sum/float64(g.n), 6)
			tv.scored = true
		}
		if _, seen := byCycle[ck]; !seen {
			cycleKeys = append(cycleKeys, ck)
		}
		byCycle[ck] = append(byCycle[ck], tv)
	}
	sort.SliceStable(cycleKeys, func(i, j int) bool { return digitsOnly(cycleKeys[i]) < digitsOnly(cycleKeys[j]) })

	nodes := []trajNode{}
	cycles := []trajCycle{}

	// baseline node.
	nodes = append(nodes, trajNode{
		ID: "baseline", Kind: "baseline", Depth: 0, Label: "baseline",
		Scored: hasBaseline,
		Score:  ifPtr(hasBaseline, baseline),
	})

	betterThan := func(a, b float64) bool {
		if higher {
			return a > b
		}
		return a < b
	}
	// 4. Model/config-aware lineage. A cycle whose signature was seen CONTINUES
	//    that branch (parent = its last champion); a NEW signature FORKS off the
	//    chronologically-previous champion (baseline for the first). Same model
	//    continues its branch; switching model/config (or reverting) branches.
	type champRef struct {
		id    string
		depth int
	}
	prevOverall := champRef{"baseline", 0}
	champBySig := map[string]champRef{}
	for _, ck := range cycleKeys {
		vs := byCycle[ck]
		repRunTs := mapRunTs(cycleDirs, vs[0].cycleTs, vs[0].ts)
		sig := branchKeyForNode(appDir, loop, vs[0].cycleTs, repRunTs, runModels, declaredDataVer)
		if cs := configSig(vs[0].config); cs != "" {
			sig += "|" + cs // a real A/B fan in one cycle keeps distinct branches
		}
		par := prevOverall
		if c, ok := champBySig[sig]; ok {
			par = c
		}
		depth := par.depth + 1
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
			runTs := mapRunTs(cycleDirs, v.cycleTs, v.ts)
			n := trajNode{
				ID:        "v:" + v.variantID,
				Kind:      "variant",
				VariantID: v.variantID,
				CycleTs:   v.cycleTs,
				Depth:     depth,
				ParentID:  par.id,
				Label:     variantLabel(v.config),
				Config:    v.config,
				Scored:    v.scored,
				RunTs:     runTs,
			}
			if len(cycleKeys) > 1 || len(vs) > 1 {
				n.ID = "v:" + v.variantID + "@" + ck
			}
			n.AgentVersion = agentVersionAt(memTimes, v.cycleTs)
			n.DataVersion = dataVersionAtRunTs(appDir, loop, runTs, declaredDataVer)
			n.Model = modelForNode(appDir, loop, v.cycleTs, runTs, runModels)
			if v.scored {
				sc := v.score
				n.Score = &sc
				if hasBaseline {
					d := roundN(sc-baseline, 4)
					n.DeltaVsBaseline = &d
				}
			}
			if runTs != "" {
				if dur := durationAtRunTs(appDir, loop, runTs, durCache); dur > 0 {
					n.DurationS = &dur
				}
				n.NeedsDecision = needsDecisionAtRunTs(appDir, loop, runTs)
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
				cyc.Learned = learnedAtRunTs(appDir, loop, runTs)
				n.Learned = cyc.Learned
				champBySig[sig] = champRef{n.ID, depth}
				prevOverall = champRef{n.ID, depth}
			}
			nodes = append(nodes, n)
		}
		cycles = append(cycles, cyc)
	}

	if len(nodes) == 0 {
		// Same cache-shadow as the linear branch: an experiments dir can exist
		// in identity's materialized copy with zero result rows while the DB
		// holds the runs. Disk yields nothing → reconstruct from the run store.
		nodes, cycles = trajNodesFromRuns(appRunsFor(userID, app, loop), loopMetricName(userID, app, loop))
		data["has_variants"] = false
	}
	assignNodeVersions(nodes)
	data["nodes"] = nodes
	data["cycles"] = cycles
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": data})
}

// pickExperiment resolves the experiment dir. When `want` is set and exists,
// use it. Otherwise prefer the dir whose results.jsonl has the most rows; tie /
// no rows → the one whose state metric is non-empty. Returns ("","") if none.
func pickExperiment(appDir, want string, allowed map[string]bool, strict bool) (string, string) {
	if strict && len(allowed) == 0 {
		return "", "" // this workflow declares no experiment → no variant metrics
	}
	expRoot, _ := ResolveRuntimeReadPath(appDir, "data/experiments")
	if want != "" && (!strict || allowed[want]) {
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
		if strict && !allowed[e.Name()] {
			continue // not this workflow's experiment
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

// caseRow is one per-case AGGREGATE result (dims.case_id, NOT a per-question
// sub-score), carrying the experiment's primary metric.
type caseRow struct {
	vid, ts, cycleTs, caseID string
	score                    float64
	scored                   bool
	config                   map[string]any
}

// readCaseRows reads results.jsonl and returns the per-case aggregate rows in
// time order (per-question dims.q_id rows excluded). The caller consolidates
// these by configuration signature into one node per model/config.
func readCaseRows(expDir, metric string) []caseRow {
	f, err := os.Open(filepath.Join(expDir, "results.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var rows []caseRow
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
		dims, _ := row["dims"].(map[string]any)
		if dims != nil {
			if _, isQ := dims["q_id"]; isQ {
				continue // per-question sub-score — not a case result
			}
		}
		r := caseRow{vid: asStr(row["variant_id"]), ts: asStr(row["ts"]), cycleTs: asStr(row["cycle_ts"])}
		if r.vid == "" {
			r.vid = "v"
		}
		if dims != nil {
			r.caseID = asStr(dims["case_id"])
		}
		if cfg, okc := row["variant"].(map[string]any); okc {
			r.config = scalarConfig(cfg)
		}
		if metrics, okm := row["metrics"].(map[string]any); okm && len(metrics) > 0 {
			sc, key := pickScore(metrics, metric)
			if key != "" && (metric == "" || key == metric) {
				r.score, r.scored = sc, true
			}
		}
		rows = append(rows, r)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ts < rows[j].ts })
	return rows
}

// configSig is a stable string fingerprint of a scalar config map (sorted keys),
// used to keep distinct variants of the same model in distinct trajectory nodes.
func configSig(cfg map[string]any) string {
	if len(cfg) == 0 {
		return ""
	}
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(asString2(cfg[k]))
		b.WriteByte(';')
	}
	return b.String()
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
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	root := filepath.Join(cyclesRoot, loop)
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
	// The run's OWN timestamp is its identity — prefer it so every node is unique
	// (cycle_ts is unique per run; collapsing many runs onto one dir breaks
	// compare/promote/log, which key off this value).
	own := cycleTs
	if own == "" {
		own = variantTs
	}
	if len(cycleDirs) == 0 {
		return own
	}
	// Exact cycle-dir match (the run actually wrote a dir) always wins.
	if cycleTs != "" {
		for _, d := range cycleDirs {
			if d == cycleTs {
				return d
			}
		}
	}
	// Otherwise snap to the nearest dir at/just-before the run, but ONLY when it's
	// CLOSE (≤ 15 min) — i.e. an off-by-seconds dir id for the same run. A far
	// older dir would snap MANY distinct runs onto one dir (a collision), so fall
	// back to the run's own ts as a unique id instead.
	kt := parseRunTs(own)
	best := ""
	var bestT time.Time
	for _, d := range cycleDirs {
		dt := parseRunTs(d)
		if dt.IsZero() || kt.IsZero() || dt.After(kt) {
			continue
		}
		if best == "" || dt.After(bestT) {
			best, bestT = d, dt
		}
	}
	if best != "" && !kt.IsZero() && kt.Sub(bestT) <= 15*time.Minute {
		return best
	}
	return own
}

// parseRunTs parses a cycle-dir / cycle_ts id ("20060102T150405Z"). Zero time on
// any other shape (e.g. an ISO row ts), so callers treat it as "unparseable".
func parseRunTs(s string) time.Time {
	t, err := time.Parse("20060102T150405Z", s)
	if err != nil {
		return time.Time{}
	}
	return t
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
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	dir := filepath.Join(cyclesRoot, loop, runTs)
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
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, runTs, "cycle.json"))
	if err != nil {
		return 0
	}
	var cj map[string]any
	if json.Unmarshal(b, &cj) != nil {
		return 0
	}
	return sumPushed(cj)
}

// needsDecisionAtRunTs — true when the run has pending advisor suggestions /
// offers or a held review_queue item awaiting a human decision. Reads the
// run's cycle.json; best-effort (missing/odd → false).
func needsDecisionAtRunTs(appDir, loop, runTs string) bool {
	if loop == "" || runTs == "" {
		return false
	}
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, runTs, "cycle.json"))
	if err != nil {
		return false
	}
	var cj map[string]any
	if json.Unmarshal(b, &cj) != nil {
		return false
	}
	for _, k := range []string{"offers", "review_queue"} {
		if a, ok := cj[k].([]any); ok && len(a) > 0 {
			return true
		}
	}
	return false
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
func linearRunChain(appDir, loop string, cycleDirs []string, durCache map[string]float64, memTimes []float64, declaredDataVer string, runModels map[string]string) ([]trajNode, []trajCycle) {
	nodes := []trajNode{}
	cycles := []trajCycle{}
	// Config-aware lineage (same model as the variant path): a run continues the
	// branch of its CONFIGURATION SIGNATURE (model + data + prompts); a new
	// signature forks off the chronologically-previous run; reverting to a prior
	// signature continues that branch. The first run is the root (no baseline node
	// in the degraded view).
	type ref struct {
		id    string
		depth int
	}
	var prevOverall *ref
	lastBySig := map[string]ref{}
	for _, ts := range cycleDirs {
		sig := branchKeyForNode(appDir, loop, ts, ts, runModels, declaredDataVer)
		var parent string
		depth := 0
		if r, ok := lastBySig[sig]; ok {
			parent, depth = r.id, r.depth+1 // continue this config's branch
		} else if prevOverall != nil {
			parent, depth = prevOverall.id, prevOverall.depth+1 // fork the new config off the last run
		}
		score, scored := cycleScore(appDir, loop, ts)
		n := trajNode{
			ID:       "run:" + ts,
			Kind:     "run",
			CycleTs:  ts,
			RunTs:    ts,
			Depth:    depth,
			ParentID: parent,
			Label:    shortDate(ts),
			Scored:   scored,
			// Mark each run a champion of its (model) branch so the UI collapses
			// long same-config stretches into a "+N cycles" badge instead of
			// rendering one node per cycle (these loops can have 100+ cycles).
			IsChampion:   true,
			AgentVersion: agentVersionAt(memTimes, ts),
			DataVersion:  dataVersionAtRunTs(appDir, loop, ts, declaredDataVer),
			Model:        modelForNode(appDir, loop, ts, ts, runModels),
			Learned:      learnedAtRunTs(appDir, loop, ts),
		}
		if scored {
			sc := score
			n.Score = &sc
		}
		if dur := durationAtRunTs(appDir, loop, ts, durCache); dur > 0 {
			n.DurationS = &dur
		}
		nodes = append(nodes, n)
		cyc := trajCycle{Ts: ts, NVariants: 1, ChampionID: n.ID, Learned: n.Learned}
		if scored {
			sc := score
			cyc.ChampionScore = &sc
		}
		if n.DurationS != nil {
			dv := *n.DurationS
			cyc.DurationS = &dv
		}
		cycles = append(cycles, cyc)
		cur := ref{n.ID, depth}
		lastBySig[sig] = cur
		prevOverall = &cur
	}
	return nodes, cycles
}

// cycleScore reads a cycle.json's primary numeric metric (first non-bookkeeping
// numeric in metrics{}). Returns (value, true) when one is found.
func cycleScore(appDir, loop, ts string) (float64, bool) {
	cyclesRoot, _ := ResolveRuntimeReadPath(appDir, "data/cycles")
	b, err := os.ReadFile(filepath.Join(cyclesRoot, loop, ts, "cycle.json"))
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
