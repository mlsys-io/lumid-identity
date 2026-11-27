package handler

// The simple app spec ("v2", 2026-11-25) → the legacy shape every reader in
// this package already parses (loops/schedule/engine/dispatch/arms/ui.nav).
//
// Research apps are written in ONE short scheme:
//
//	name / title / summary / version / icon
//	data:        [{id, source: "repo:<owner/name>" | "path:<dir>", version}]
//	compute:     {site, gpu}                    # app default
//	workflows:   [{id, title, about, notes, run, steps: {python|dag|skills|workflows},
//	               inputs, data, compute, feedback, parent, node, helper}]
//	nodes:       [{id, title, parent}]
//	experiments: [{id, workflow, question, hypothesis, metric: {name, better},
//	               data, baseline, done_when, min_samples, versions: [{id, about, inputs}]}]
//	pages:       [{id, title, file, hidden}]
//
// This is the Go twin of LumidOS sdk/apps/spec_v2.py — same rules, same
// fixture (testdata/spec_v2_mlsys.yaml, copied from LumidOS tests/fixtures).
// A spec with nothing to translate is returned BYTE-FOR-BYTE unchanged, so
// legacy apps take no risk from this.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var specV2SafeInput = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// readSpecAware is os.ReadFile, plus the v2 translation when the file is an
// app spec (.xpcloud.yaml / xpcloud.yaml). Any other file reads unchanged, so
// it is safe to use wherever a spec MIGHT be read. Never use it where the raw
// bytes matter (the config editor, base_sha checks, text patches).
func readSpecAware(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	switch filepath.Base(path) {
	case SpecDotfile, "xpcloud.yaml":
		return normalizeSpecBytes(b, filepath.Dir(path)), nil
	}
	return b, nil
}

func isV2Workflow(w map[string]any) bool {
	if w == nil {
		return false
	}
	_, hasName := w["name"]
	_, hasID := w["id"]
	if hasName && !hasID {
		return false
	}
	for _, k := range []string{"id", "steps", "run", "about", "inputs", "helper"} {
		if _, ok := w[k]; ok {
			return true
		}
	}
	return false
}

func isV2Experiment(e map[string]any) bool {
	for _, k := range []string{"workflow", "versions", "question", "done_when"} {
		if _, ok := e[k]; ok {
			return true
		}
	}
	return false
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func specStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

// specNeedsV2 is the cheap gate: only specs that use a v2 key get rewritten.
func specNeedsV2(doc map[string]any) bool {
	if _, ok := doc["pages"]; ok {
		return true
	}
	if _, ok := doc["data"]; ok {
		if _, has := doc["datasets"]; !has {
			return true
		}
	}
	if _, ok := doc["title"]; ok {
		if _, has := doc["display_name"]; !has {
			return true
		}
	}
	for _, key := range []string{"workflows", "loops"} {
		for _, w := range asList(doc[key]) {
			if isV2Workflow(asMap(w)) {
				return true
			}
		}
	}
	for _, e := range asList(doc["experiments"]) {
		if m := asMap(e); m != nil && isV2Experiment(m) {
			return true
		}
	}
	for _, d := range asList(doc["datasets"]) {
		if m := asMap(d); m != nil {
			if _, ok := m["source"]; ok {
				return true
			}
		}
	}
	return false
}

// normalizeSpecBytes translates v2 keys; appDir (may be "") lets `notes:` be
// read into the loop description. On any failure it returns b unchanged.
func normalizeSpecBytes(b []byte, appDir string) []byte {
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil || doc == nil {
		return b
	}
	if !specNeedsV2(doc) {
		return b
	}
	out, err := yaml.Marshal(normalizeSpecDoc(doc, appDir))
	if err != nil {
		return b
	}
	return out
}

func readNotes(appDir string, rel any) string {
	r := specStr(rel)
	if appDir == "" || r == "" {
		return ""
	}
	root, err := filepath.Abs(appDir)
	if err != nil {
		return ""
	}
	p, err := filepath.Abs(filepath.Join(root, r))
	if err != nil || !strings.HasPrefix(p, root+string(os.PathSeparator)) {
		return "" // never read outside the bundle
	}
	nb, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	if len(nb) > 20000 {
		nb = nb[:20000]
	}
	return string(nb)
}

func jinjaDefault(v any) string {
	s := specStr(v)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

func engineForWorkflow(w, appCompute map[string]any, exps []string) map[string]any {
	steps := asMap(w["steps"])
	if steps == nil {
		return nil
	}
	compute := map[string]any{}
	for k, v := range appCompute {
		compute[k] = v
	}
	for k, v := range asMap(w["compute"]) {
		compute[k] = v
	}
	inputs := asMap(w["inputs"])
	var eng map[string]any
	if py := specStr(steps["python"]); py != "" {
		eng = map[string]any{"type": "command", "module": py}
		var args []any
		for _, k := range specV2SortedKeys(inputs) {
			if specV2SafeInput.MatchString(k) {
				args = append(args, fmt.Sprintf("--%s={{ args.%s | default('%s') }}", k, k, jinjaDefault(inputs[k])))
			}
		}
		if len(args) > 0 {
			eng["args"] = args
		}
		if s := specStr(compute["site"]); s != "" {
			eng["site"] = s
		}
	} else if dag := specStr(steps["dag"]); dag != "" {
		name := dag
		if strings.HasSuffix(dag, ".yaml") || strings.HasSuffix(dag, ".yml") {
			name = strings.TrimSuffix(filepath.Base(dag), filepath.Ext(dag))
		}
		eng = map[string]any{"type": "lumilake", "workflow": name}
		if len(inputs) > 0 {
			eng["inputs"] = inputs
		}
		if s := specStr(compute["site"]); s != "" {
			eng["site"] = s
		}
		if g := specStr(compute["gpu"]); g != "" {
			eng["hardware"] = map[string]any{"gpu_memory": g}
		}
	} else if stages, ok := chainStages(w); ok {
		// A composite workflow: other workflows of this app, run in order by
		// the LumidOS runner (_run_chain_engine). Each stage keeps its own
		// compute, so no site/hardware here.
		l := make([]any, len(stages))
		for i, st := range stages {
			l[i] = st
		}
		eng = map[string]any{"type": "chain", "stages": l}
	} else {
		return nil
	}
	if len(exps) == 1 {
		eng["experiment"] = exps[0]
	} else if len(exps) > 1 {
		l := make([]any, len(exps))
		for i, e := range exps {
			l[i] = e
		}
		eng["experiment"] = l
	}
	return eng
}

func specV2SortedKeys(m map[string]any) []string {
	// yaml.v3 decodes mappings into Go maps (unordered); sort for stable args.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func loopFromWorkflow(w, appCompute map[string]any, appDir string, expsByWf map[string][]string) map[string]any {
	out := map[string]any{}
	for k, v := range w {
		switch k {
		case "id", "about", "notes", "run", "steps", "inputs", "helper", "data":
		default:
			out[k] = v
		}
	}
	name := specStr(w["id"])
	if name == "" {
		name = specStr(w["name"])
	}
	out["name"] = name
	if t := specStr(w["title"]); t != "" {
		if _, ok := out["display_name"]; !ok {
			out["display_name"] = t
		}
	}
	var parts []string
	if a := strings.TrimSpace(specStr(w["about"])); a != "" {
		parts = append(parts, a)
	}
	if n := strings.TrimSpace(readNotes(appDir, w["notes"])); n != "" {
		parts = append(parts, n)
	}
	if len(parts) > 0 && specStr(out["description"]) == "" {
		out["description"] = strings.Join(parts, "\n\n")
	}
	if specStr(out["description"]) == "" {
		if stages, ok := chainStages(w); ok && len(stages) > 0 {
			out["description"] = chainSummary(stages)
		}
	}
	run, has := w["run"]
	if !has {
		run = w["schedule"]
	}
	if r := specStr(run); r == "" || r == "manual" || r == "@trigger" {
		out["schedule"] = "@trigger"
	} else {
		out["schedule"] = r
	}
	if _, ok := out["engine"].(map[string]any); !ok {
		if eng := engineForWorkflow(w, appCompute, expsByWf[name]); eng != nil {
			out["engine"] = eng
		}
	}
	if steps := asMap(w["steps"]); steps != nil {
		if sk := asList(steps["skills"]); len(sk) > 0 {
			if _, ok := out["skills"]; !ok {
				out["skills"] = sk
			}
		}
	}
	if d, ok := w["data"]; ok && d != nil {
		if _, has := out["datasets"]; !has {
			if l := asList(d); l != nil {
				out["datasets"] = l
			} else {
				out["datasets"] = []any{d}
			}
		}
	}
	if h, _ := w["helper"].(bool); h {
		out["role"] = "helper"
	}
	if _, has := out["metrics"]; !has {
		for _, st := range asList(w["feedback"]) {
			ms := asList(asMap(st)["metrics"])
			if len(ms) > 0 {
				if n := specStr(asMap(ms[0])["name"]); n != "" {
					out["metrics"] = map[string]any{"primary": n}
					break
				}
			}
		}
	}
	return out
}

func experimentFromV2(e map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range e {
		switch k {
		case "workflow", "question", "done_when", "versions", "data":
		default:
			out[k] = v
		}
	}
	if wf := specStr(e["workflow"]); wf != "" {
		if _, ok := out["loop"]; !ok {
			out["loop"] = wf
		}
		disp := map[string]any{}
		for k, v := range asMap(out["dispatch"]) {
			disp[k] = v
		}
		if _, ok := disp["loop"]; !ok {
			disp["loop"] = wf
		}
		out["dispatch"] = disp
	}
	if q := specStr(e["question"]); q != "" && specStr(out["description"]) == "" {
		out["description"] = q
	}
	if d := specStr(e["done_when"]); d != "" && specStr(out["success_criteria"]) == "" {
		out["success_criteria"] = d
	}
	if d := specStr(e["data"]); d != "" && specStr(out["dataset_id"]) == "" {
		out["dataset_id"] = d
	}
	if m := asMap(out["metric"]); m != nil {
		if bt, ok := m["better"]; ok {
			if _, has := m["higher_is_better"]; !has {
				nm := map[string]any{}
				for k, v := range m {
					if k != "better" {
						nm[k] = v
					}
				}
				nm["higher_is_better"] = strings.ToLower(specStr(bt)) != "lower"
				out["metric"] = nm
			}
		}
	}
	if b, ok := out["baseline"].(string); ok {
		out["baseline"] = map[string]any{"arm": b}
	}
	if vs := asList(e["versions"]); vs != nil {
		if _, has := out["arms"]; !has {
			var arms []any
			for _, v := range vs {
				vm := asMap(v)
				if vm == nil {
					continue
				}
				arm := map[string]any{"id": vm["id"]}
				if a := specStr(vm["about"]); a != "" {
					arm["description"] = a
				}
				for k, val := range asMap(vm["inputs"]) {
					if _, ok := arm[k]; !ok {
						arm[k] = val
					}
				}
				for k, val := range vm {
					if k == "id" || k == "about" || k == "inputs" {
						continue
					}
					if _, ok := arm[k]; !ok {
						arm[k] = val
					}
				}
				arms = append(arms, arm)
			}
			out["arms"] = arms
			if _, ok := out["kind"]; !ok {
				out["kind"] = "arms"
			}
		}
	}
	return out
}

func datasetFromV2(d any) any {
	m := asMap(d)
	if m == nil {
		return d
	}
	src, ok := m["source"]
	if !ok {
		return d
	}
	out := map[string]any{}
	for k, v := range m {
		if k != "source" {
			out[k] = v
		}
	}
	s := specStr(src)
	switch {
	case strings.HasPrefix(s, "repo:"):
		if _, ok := out["repo"]; !ok {
			out["repo"] = s[5:]
		}
	case strings.HasPrefix(s, "path:"):
		if _, ok := out["local_path"]; !ok {
			out["local_path"] = s[5:]
		}
	default:
		if _, ok := out["repo"]; !ok {
			out["repo"] = s
		}
	}
	return out
}

func uiFromPages(pages []any, title string, icon any, ui map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range ui {
		out[k] = v
	}
	surfaces := map[string]any{}
	for k, v := range asMap(out["surfaces"]) {
		surfaces[k] = v
	}
	nav := append([]any{}, asList(out["nav"])...)
	have := map[string]bool{}
	for _, n := range nav {
		have[specStr(asMap(n)["surface"])] = true
	}
	for _, p := range pages {
		pm := asMap(p)
		id := specStr(pm["id"])
		if id == "" {
			continue
		}
		if f := specStr(pm["file"]); f != "" {
			if _, ok := surfaces[id]; !ok {
				surfaces[id] = f
			}
		}
		hidden, _ := pm["hidden"].(bool)
		if !hidden && !have[id] {
			label := specStr(pm["title"])
			if label == "" {
				label = id
			}
			nav = append(nav, map[string]any{"surface": id, "label": label})
			have[id] = true
		}
	}
	if len(surfaces) > 0 {
		out["surfaces"] = surfaces
	}
	if len(nav) > 0 {
		out["nav"] = nav
	}
	sb := map[string]any{}
	for k, v := range asMap(out["sidebar"]) {
		sb[k] = v
	}
	if title != "" {
		if _, ok := sb["label"]; !ok {
			sb["label"] = title
		}
	}
	if s := specStr(icon); s != "" {
		if _, ok := sb["icon"]; !ok {
			sb["icon"] = s
		}
	}
	if len(sb) > 0 {
		out["sidebar"] = sb
	}
	return out
}

// normalizeSpecDoc is the pure translation (old keys win where both exist).
func normalizeSpecDoc(doc map[string]any, appDir string) map[string]any {
	out := map[string]any{}
	for k, v := range doc {
		out[k] = v
	}
	if t := specStr(out["title"]); t != "" && specStr(out["display_name"]) == "" {
		out["display_name"] = t
	}
	if d := asList(out["data"]); d != nil {
		if _, has := out["datasets"]; !has {
			l := make([]any, len(d))
			for i, x := range d {
				l[i] = datasetFromV2(x)
			}
			out["datasets"] = l
		}
	} else if ds := asList(out["datasets"]); ds != nil {
		l := make([]any, len(ds))
		for i, x := range ds {
			l[i] = datasetFromV2(x)
		}
		out["datasets"] = l
	}
	appCompute := asMap(out["compute"])

	expsByWf := map[string][]string{}
	if exps := asList(out["experiments"]); exps != nil {
		nl := make([]any, len(exps))
		for i, e := range exps {
			em := asMap(e)
			if em != nil && specStr(em["id"]) != "" && specStr(em["workflow"]) != "" {
				wf := specStr(em["workflow"])
				expsByWf[wf] = append(expsByWf[wf], specStr(em["id"]))
			}
			if em != nil && isV2Experiment(em) {
				nl[i] = experimentFromV2(em)
			} else {
				nl[i] = e
			}
		}
		out["experiments"] = nl
	}

	if wfs := asList(out["workflows"]); wfs != nil {
		anyV2 := false
		for _, w := range wfs {
			if isV2Workflow(asMap(w)) {
				anyV2 = true
				break
			}
		}
		if anyV2 {
			loops := append([]any{}, asList(out["loops"])...)
			seen := map[string]bool{}
			for _, lp := range loops {
				seen[specStr(asMap(lp)["name"])] = true
			}
			var rest []any
			for _, w := range wfs {
				wm := asMap(w)
				if isV2Workflow(wm) {
					lp := loopFromWorkflow(wm, appCompute, appDir, expsByWf)
					n := specStr(lp["name"])
					if n != "" && !seen[n] {
						loops = append(loops, lp)
						seen[n] = true
					}
				} else {
					rest = append(rest, w)
				}
			}
			out["loops"] = loops
			if len(rest) > 0 {
				out["workflows"] = rest
			} else {
				delete(out, "workflows")
			}
		}
	}
	if loops := asList(out["loops"]); loops != nil {
		nl := make([]any, len(loops))
		for i, lp := range loops {
			if lm := asMap(lp); isV2Workflow(lm) {
				nl[i] = loopFromWorkflow(lm, appCompute, appDir, expsByWf)
			} else {
				nl[i] = lp
			}
		}
		out["loops"] = nl
	}
	if pages := asList(out["pages"]); pages != nil {
		out["ui"] = uiFromPages(pages, specStr(out["title"]), out["icon"], asMap(out["ui"]))
	}
	return out
}

// readAppSpecForParse is readAppSpecBytes (tenant overlay → disk → repo) with
// the v2 translation, for readers that PARSE the spec. Editors and base_sha
// checks keep calling readAppSpecBytes for the raw bytes.
func readAppSpecForParse(userID, app, appDir string) []byte {
	return normalizeSpecBytes(readAppSpecBytes(userID, app, appDir), appDir)
}

// fetchRepoSpecForParse is fetchRepoSpecYAML with the v2 translation.
func fetchRepoSpecForParse(userSub, app string) ([]byte, bool) {
	b, ok := fetchRepoSpecYAML(userSub, app)
	if !ok {
		return b, ok
	}
	return normalizeSpecBytes(b, ""), true
}

// chainStages reads a composite workflow's `steps.workflows`, in order. Each
// entry is a bare workflow id or {use: <id>, inputs: {...}}; both become
// {"loop": <id>} plus "inputs" when given. ok is false when the workflow has
// no `steps.workflows` key at all.
func chainStages(w map[string]any) ([]map[string]any, bool) {
	raw, ok := asMap(w["steps"])["workflows"]
	if !ok {
		return nil, false
	}
	var out []map[string]any
	for _, s := range asList(raw) {
		st := map[string]any{}
		if m := asMap(s); m != nil {
			st["loop"] = strings.TrimSpace(specStr(m["use"]))
			if in := asMap(m["inputs"]); len(in) > 0 {
				st["inputs"] = in
			}
		} else {
			st["loop"] = strings.TrimSpace(specStr(s))
		}
		out = append(out, st)
	}
	return out, true
}

// chainSummary is the one-line description of a composite workflow, shown
// where a workflow has no about/notes: "Chain: backtest → forward_test".
func chainSummary(stages []map[string]any) string {
	ids := make([]string, len(stages))
	for i, st := range stages {
		ids[i] = specStr(st["loop"])
	}
	return "Chain: " + strings.Join(ids, " → ")
}

// specV2ChainError checks every composite workflow (`steps.workflows`) in a
// parsed spec against the app's own workflow ids. It returns the first problem
// in words, or nil. Specs without a chain always pass, so this is safe to call
// on any spec before saving it. The runner re-checks at run time (a spec can
// arrive by app_push without passing through here).
func specV2ChainError(doc map[string]any) error {
	ids := map[string]bool{}
	var order []string
	chains := map[string][]string{}
	var problems []error
	for _, key := range []string{"workflows", "loops"} {
		for _, w := range asList(doc[key]) {
			wm := asMap(w)
			id := specStr(wm["id"])
			if id == "" {
				id = specStr(wm["name"])
			}
			if id == "" {
				continue
			}
			ids[id] = true
			stages, ok := chainStages(wm)
			if !ok {
				// Already translated (loops[].engine), e.g. read via readSpecAware.
				if eng := asMap(wm["engine"]); specStr(eng["type"]) == "chain" {
					for _, st := range asList(eng["stages"]) {
						stages = append(stages, map[string]any{"loop": strings.TrimSpace(specStr(asMap(st)["loop"]))})
					}
					ok = true
				}
			}
			if !ok {
				continue
			}
			if _, dup := chains[id]; dup {
				continue
			}
			steps := asMap(wm["steps"])
			for _, other := range []string{"python", "dag", "skills"} {
				if _, has := steps[other]; has {
					problems = append(problems, fmt.Errorf("workflow %q: steps.workflows cannot be combined with steps.%s — a chain only runs other workflows", id, other))
				}
			}
			if len(stages) == 0 {
				problems = append(problems, fmt.Errorf("workflow %q: steps.workflows lists no workflows to run", id))
			}
			order = append(order, id)
			l := make([]string, len(stages))
			for i, st := range stages {
				l[i] = specStr(st["loop"])
			}
			chains[id] = l
		}
	}
	if len(problems) > 0 {
		return problems[0]
	}
	for _, id := range order {
		for i, st := range chains[id] {
			switch {
			case st == "":
				return fmt.Errorf("workflow %q: stage %d names no workflow (write an id, or {use: <id>})", id, i+1)
			case st == id:
				return fmt.Errorf("workflow %q: stage %d runs the workflow itself", id, i+1)
			case !ids[st]:
				return fmt.Errorf("workflow %q: stage %d (%s) is not a workflow in this app", id, i+1, st)
			}
		}
	}
	// A cycle through other composites (a → b → a): depth-first over chains
	// only, since a plain workflow ends every path.
	const (
		unseen = iota
		active
		done
	)
	state := map[string]int{}
	var path []string
	var visit func(id string) error
	visit = func(id string) error {
		state[id] = active
		path = append(path, id)
		for _, st := range chains[id] {
			if _, isChain := chains[st]; !isChain {
				continue
			}
			switch state[st] {
			case active:
				start := 0
				for i, p := range path {
					if p == st {
						start = i
						break
					}
				}
				loop := append(append([]string{}, path[start:]...), st)
				return fmt.Errorf("workflow %q: its stages loop back to it (%s)", st, strings.Join(loop, " → "))
			case unseen:
				if err := visit(st); err != nil {
					return err
				}
			}
		}
		path = path[:len(path)-1]
		state[id] = done
		return nil
	}
	for _, id := range order {
		if state[id] == unseen {
			if err := visit(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// specV2ChainErrorBytes is specV2ChainError on raw YAML. Unparseable YAML is
// not its concern (callers check that first) and passes.
func specV2ChainErrorBytes(b []byte) error {
	var doc map[string]any
	if yaml.Unmarshal(b, &doc) != nil || doc == nil {
		return nil
	}
	return specV2ChainError(doc)
}
