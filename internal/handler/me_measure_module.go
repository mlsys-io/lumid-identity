package handler

// App compute modules (round 10, 2026-11-28).
//
// An app declares small CPU-only compute — a small ML model, a data-processing
// step — in its spec, and lum.id's central measurement service runs it with
// hard limits:
//
//	modules:
//	- id: prompt_stats
//	  title: Prompt length statistics
//	  about: Token-length histogram and percentiles of a request trace.
//	  image: ghcr.io/<org>/<repo>@sha256:<64 hex>   # pinned; a tag alone is refused
//	  run: python -m mymod.job                     # ONE JSON object on stdin → ONE on stdout
//	  inputs: {trace: "rows of {prompt_tokens, output_tokens}"}
//	  limits: {cpu: 1, memory: 2Gi, timeout_s: 120}
//	  share: everyone                              # everyone | you (default you)
//	  public: false                                # true: any lum.id user's app may call it
//
// The instrument name is "<app>.<id>" for the caller's own install of app, and
// "<owner>/<app>.<id>" for a public module of someone else's published app.
// Either way the module runs AS THE CALLER (their fleet credential, their
// budget), never with the publisher's rights.
//
// What identity enforces: the pinned digest, the clamped limits (cpu ≤ 2,
// memory ≤ 4Gi, timeout ≤ 600 s — written into the FlowMesh task, whose worker
// applies them as cgroup limits and a wall-clock kill), inputs ≤ 256 KiB,
// output ≤ 1 MiB (the wrapper stops reading past it; identity re-checks at
// settle), no GPU request, network none, visibility. The content key is the
// image digest, the run command and the canonical inputs — not the name — so
// the same computation reached by two names is measured once.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const (
	moduleMaxCPU       = 2
	moduleMaxMemoryMi  = 4096
	moduleMinMemoryMi  = 64
	moduleMaxTimeoutS  = 600
	moduleDefCPU       = 1
	moduleDefMemoryMi  = 1024
	moduleDefTimeoutS  = 120
	moduleMaxOutBytes  = 1 << 20
	moduleMaxCodeBytes = 256 << 10 // FlowMesh's python code limit
	// The task's own wall clock outlives the wrapper's, so a module that runs
	// over its limit is reported by the wrapper, in words, not by a kill.
	moduleTimeoutGraceS = 30
)

var (
	moduleIDRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,47}$`)
	moduleImageRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	moduleAppRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	moduleOwnerRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	moduleMemoryRe = regexp.MustCompile(`^\s*([0-9]+)\s*([KkMmGgTt][Ii]?[Bb]?)?\s*$`)
)

type moduleLimits struct {
	CPU      int `json:"cpu"`
	MemoryMi int `json:"memory_mi"`
	TimeoutS int `json:"timeout_s"`
}

func (l moduleLimits) memory() string { return strconv.Itoa(l.MemoryMi) + "Mi" }

// appModule is one validated `modules:` entry.
type appModule struct {
	ID     string
	Title  string
	About  string
	Image  string
	Run    string
	Inputs map[string]string
	Limits moduleLimits
	Share  string // everyone | you
	Public bool
	// Notes: what the platform changed (a clamped limit), in words.
	Notes []string
}

func (m appModule) digest() string { return m.Image[strings.Index(m.Image, "@")+1:] }

// parseModuleMemory reads "2Gi", "512Mi", "1G" (binary units, as FlowMesh
// reads them) or a bare byte count, in MiB rounded up.
func parseModuleMemory(v any) (int, error) {
	var bytes float64
	switch t := v.(type) {
	case int:
		bytes = float64(t)
	case int64:
		bytes = float64(t)
	case float64:
		bytes = t
	case string:
		m := moduleMemoryRe.FindStringSubmatch(t)
		if m == nil {
			return 0, fmt.Errorf("limits.memory %q is not a size (write e.g. 512Mi or 2Gi)", t)
		}
		n, _ := strconv.ParseFloat(m[1], 64)
		mult := 1.0
		switch strings.ToLower(m[2]) {
		case "k", "kb", "ki", "kib":
			mult = 1 << 10
		case "m", "mb", "mi", "mib":
			mult = 1 << 20
		case "g", "gb", "gi", "gib":
			mult = 1 << 30
		case "t", "tb", "ti", "tib":
			mult = 1 << 40
		}
		bytes = n * mult
	default:
		return 0, fmt.Errorf("limits.memory must be a size like 2Gi")
	}
	if bytes <= 0 {
		return 0, errors.New("limits.memory must be more than zero")
	}
	return int(math.Ceil(bytes / (1 << 20))), nil
}

func moduleNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

// clampModuleLimits applies the defaults and the platform's ceilings. A limit
// over the ceiling is clamped (and said so in Notes); one that is not a
// positive number is refused.
func clampModuleLimits(raw map[string]any) (moduleLimits, []string, error) {
	l := moduleLimits{CPU: moduleDefCPU, MemoryMi: moduleDefMemoryMi, TimeoutS: moduleDefTimeoutS}
	var notes []string
	if v, has := raw["cpu"]; has {
		f, isNum := moduleNumber(v)
		if !isNum || f <= 0 {
			return l, nil, errors.New("limits.cpu must be a positive number of cores")
		}
		l.CPU = int(math.Ceil(f))
		if l.CPU > moduleMaxCPU {
			notes = append(notes, fmt.Sprintf("asked for %v CPUs; a module gets at most %d", v, moduleMaxCPU))
			l.CPU = moduleMaxCPU
		}
	}
	if v, has := raw["memory"]; has {
		mi, err := parseModuleMemory(v)
		if err != nil {
			return l, nil, err
		}
		if mi > moduleMaxMemoryMi {
			notes = append(notes, fmt.Sprintf("asked for %v memory; a module gets at most 4Gi", v))
			mi = moduleMaxMemoryMi
		}
		l.MemoryMi = max(mi, moduleMinMemoryMi)
	}
	if v, has := raw["timeout_s"]; has {
		f, isNum := moduleNumber(v)
		if !isNum || f <= 0 {
			return l, nil, errors.New("limits.timeout_s must be a positive number of seconds")
		}
		l.TimeoutS = int(math.Ceil(f))
		if l.TimeoutS > moduleMaxTimeoutS {
			notes = append(notes, fmt.Sprintf("asked for %v s; a module runs at most %d s", v, moduleMaxTimeoutS))
			l.TimeoutS = moduleMaxTimeoutS
		}
	}
	for k := range raw {
		if k != "cpu" && k != "memory" && k != "timeout_s" {
			return l, nil, fmt.Errorf("limits.%s is not a module limit (cpu, memory, timeout_s; modules never get a GPU)", k)
		}
	}
	return l, notes, nil
}

// parseModuleEntry validates one `modules:` entry. Errors are in words and
// name the module.
func parseModuleEntry(e map[string]any) (appModule, error) {
	id := strings.TrimSpace(specStr(e["id"]))
	if !moduleIDRe.MatchString(id) {
		return appModule{}, fmt.Errorf("module %q: id must be a short slug (lowercase letters, digits, _ or -)", id)
	}
	m := appModule{ID: id, Title: specStr(e["title"]), About: specStr(e["about"]),
		Image: strings.TrimSpace(specStr(e["image"])), Run: strings.TrimSpace(specStr(e["run"])),
		Share: strings.TrimSpace(specStr(e["share"])), Inputs: map[string]string{}}
	if m.Image == "" {
		return m, fmt.Errorf("module %s: image is required, pinned by digest (…@sha256:<64 hex>)", id)
	}
	if !moduleImageRe.MatchString(m.Image) {
		return m, fmt.Errorf("module %s: image %q is not pinned by digest; write it as <repo>@sha256:<64 hex> "+
			"(a tag can change under everyone who reuses its results)", id, m.Image)
	}
	if m.Run == "" {
		return m, fmt.Errorf("module %s: run is required (the command that reads ONE JSON object on stdin "+
			"and writes ONE on stdout)", id)
	}
	if len(m.Run) > 512 || strings.ContainsAny(m.Run, "\n\r\x00") {
		return m, fmt.Errorf("module %s: run must be one command line of at most 512 characters", id)
	}
	switch m.Share {
	case "":
		m.Share = "you"
	case "you", "everyone":
	default:
		return m, fmt.Errorf("module %s: share is everyone or you, not %q", id, m.Share)
	}
	if v, has := e["public"]; has && v != nil {
		b, isBool := v.(bool)
		if !isBool {
			return m, fmt.Errorf("module %s: public is true or false", id)
		}
		m.Public = b
	}
	if raw, has := e["inputs"]; has && raw != nil {
		in, isMap := raw.(map[string]any)
		if !isMap {
			return m, fmt.Errorf("module %s: inputs is a mapping of input name to words", id)
		}
		for k, v := range in {
			m.Inputs[k] = specStr(v)
		}
	}
	raw := map[string]any{}
	if v, has := e["limits"]; has && v != nil {
		lm, isMap := v.(map[string]any)
		if !isMap {
			return m, fmt.Errorf("module %s: limits is a mapping {cpu, memory, timeout_s}", id)
		}
		raw = lm
	}
	l, notes, err := clampModuleLimits(raw)
	if err != nil {
		return m, fmt.Errorf("module %s: %v", id, err)
	}
	m.Limits, m.Notes = l, notes
	return m, nil
}

// specModuleEntries is the spec's raw `modules:` list (entries that are not
// mappings are kept as nil so their position can be named).
func specModuleEntries(doc map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range asList(doc["modules"]) {
		out = append(out, asMap(e))
	}
	return out
}

// specModulesError is the save-time check: every module valid, ids unique,
// and every workflow's steps.module naming a declared one.
func specModulesError(doc map[string]any) error {
	if raw, has := doc["modules"]; has && raw != nil && asList(raw) == nil {
		return errors.New("modules must be a list")
	}
	ids := map[string]bool{}
	for i, e := range specModuleEntries(doc) {
		if e == nil {
			return fmt.Errorf("modules[%d] must be a mapping", i)
		}
		m, err := parseModuleEntry(e)
		if err != nil {
			return err
		}
		if ids[m.ID] {
			return fmt.Errorf("module %s is declared twice", m.ID)
		}
		ids[m.ID] = true
	}
	for _, key := range []string{"workflows", "loops"} {
		for _, w := range asList(doc[key]) {
			wm := asMap(w)
			steps := asMap(wm["steps"])
			raw, has := steps["module"]
			if !has {
				continue
			}
			wid := specStr(wm["id"])
			if wid == "" {
				wid = specStr(wm["name"])
			}
			mod := strings.TrimSpace(specStr(raw))
			if strings.Contains(mod, "/") {
				// An owner-qualified public module: resolved at run time.
				continue
			}
			if !ids[mod] {
				return fmt.Errorf("workflow %q: steps.module %q is not a module of this app", wid, mod)
			}
			for _, other := range []string{"python", "dag", "skills", "workflows"} {
				if _, also := steps[other]; also {
					return fmt.Errorf("workflow %q: steps.module cannot be combined with steps.%s", wid, other)
				}
			}
			if in, has := steps["inputs"]; has && in != nil && asMap(in) == nil {
				return fmt.Errorf("workflow %q: steps.inputs is a mapping", wid)
			}
		}
	}
	return nil
}

// specModules parses a spec's modules; the second value lists the entries
// that failed, by id (or position), with the reason.
func specModules(specYAML []byte) ([]appModule, map[string]string) {
	var doc map[string]any
	bad := map[string]string{}
	if yaml.Unmarshal(specYAML, &doc) != nil || doc == nil {
		return nil, bad
	}
	var out []appModule
	for i, e := range specModuleEntries(doc) {
		m, err := parseModuleEntry(e)
		if err != nil {
			k := specStr(e["id"])
			if k == "" {
				k = "#" + strconv.Itoa(i+1)
			}
			bad[k] = err.Error()
			continue
		}
		out = append(out, m)
	}
	return out, bad
}

// moduleSpecSource reads the spec a module is declared in: the caller's own
// install of app (owner ""), or owner's published app. A var so tests need no
// xpcloud.
var moduleSpecSource = func(sub, owner, app string) ([]byte, bool) {
	if owner == "" {
		if row := storedAppSpec(sub, app); row != nil {
			return []byte(row.SpecYAML), true
		}
		return fetchRepoSpecYAML(sub, app)
	}
	for _, path := range []string{".xpcloud.yaml", "xpcloud.yaml"} {
		if b, ok := fetchRepoBlobAt(sub, owner+"/"+app, path); ok {
			return b, true
		}
	}
	return nil, false
}

// parseModuleName splits "<app>.<id>" or "<owner>/<app>.<id>". ok=false when
// the name has no module shape (it is then simply an unknown instrument).
func parseModuleName(name string) (owner, app, id string, ok bool) {
	rest := name
	if i := strings.Index(rest, "/"); i >= 0 {
		owner, rest = rest[:i], rest[i+1:]
		if !moduleOwnerRe.MatchString(owner) {
			return "", "", "", false
		}
	}
	dot := strings.LastIndex(rest, ".")
	if dot <= 0 {
		return "", "", "", false
	}
	app, id = rest[:dot], rest[dot+1:]
	if !moduleAppRe.MatchString(app) || !moduleIDRe.MatchString(id) {
		return "", "", "", false
	}
	return owner, app, id, true
}

// moduleRefusal is a refusal in words with the HTTP code it is answered with.
type moduleRefusal struct {
	code int
	why  string
}

// resolveModule finds the module a name refers to, as seen by sub calling
// from callerApp. isModule=false: not a module name at all.
func resolveModule(sub, name, callerApp string) (m appModule, app string, isModule bool, refusal *moduleRefusal) {
	owner, app, id, isModule := parseModuleName(name)
	if !isModule {
		return appModule{}, "", false, nil
	}
	if owner == sub {
		owner = ""
	}
	spec, found := moduleSpecSource(sub, owner, app)
	if !found {
		if owner == "" {
			return appModule{}, app, true, &moduleRefusal{http.StatusNotFound,
				fmt.Sprintf("module %s: you have no app %q installed (a public module of another app is "+
					"named <owner>/<app>.<module>)", name, app)}
		}
		return appModule{}, app, true, &moduleRefusal{http.StatusNotFound,
			fmt.Sprintf("module %s: %s publishes no app %q", name, owner, app)}
	}
	mods, bad := specModules(spec)
	if why, isBad := bad[id]; isBad {
		return appModule{}, app, true, &moduleRefusal{http.StatusBadRequest, why}
	}
	for _, x := range mods {
		if x.ID != id {
			continue
		}
		if owner != "" && !x.Public {
			return appModule{}, app, true, &moduleRefusal{http.StatusForbidden,
				fmt.Sprintf("module %s is not public: only installs of %s may call it", name, app)}
		}
		if owner == "" && !x.Public && callerApp != "" && callerApp != app {
			return appModule{}, app, true, &moduleRefusal{http.StatusForbidden,
				fmt.Sprintf("module %s is not visible to the %s app: only %s may call it "+
					"(its author can set public: true)", name, callerApp, app)}
		}
		return x, app, true, nil
	}
	ids := make([]string, 0, len(mods))
	for _, x := range mods {
		ids = append(ids, x.ID)
	}
	sort.Strings(ids)
	have := "none"
	if len(ids) > 0 {
		have = strings.Join(ids, ", ")
	}
	return appModule{}, app, true, &moduleRefusal{http.StatusNotFound,
		fmt.Sprintf("module %s: app %s declares no module %q (its modules: %s)", name, app, id, have)}
}

// moduleInstrument is the measurement instrument a resolved module is.
func moduleInstrument(name string, m appModule) measureInstrument {
	share := "tenant"
	if m.Share == "everyone" {
		share = "global"
	}
	about := m.About
	if about == "" {
		about = m.Title
	}
	return measureInstrument{Name: fleetClip(name, 160), About: about, Share: share, Inputs: m.Inputs,
		executor: "module", keyAs: "module",
		plan:     func(in map[string]any) (measurePlan, error) { return modulePlan(name, m, in) },
		versions: func() []string { return []string{m.digest()} }}
}

// modulePlan: ONE FlowMesh python stage on the pinned image, running the
// fixed wrapper around the module's `run`.
func modulePlan(name string, m appModule, inputs map[string]any) (measurePlan, error) {
	inJSON, err := canonicalJSON(inputs)
	if err != nil {
		return measurePlan{}, err
	}
	material := map[string]any{"run": m.Run, "inputs": inputs}
	key := measureKey("module", m.digest(), material)
	code := moduleWrapperCode(m.Run, inJSON, m.Limits.TimeoutS)
	if len(code) > moduleMaxCodeBytes {
		return measurePlan{}, fmt.Errorf("the inputs are too large for a module (%d KiB once packed into the job; "+
			"the limit is about %d KiB) — pass a dataset reference instead of the rows",
			len(code)>>10, (moduleMaxCodeBytes-len(moduleWrapperCode(m.Run, "{}", m.Limits.TimeoutS)))>>10)
	}
	graph := map[string]any{
		"apiVersion": "flowmesh/v1", "kind": "Workflow",
		"metadata": map[string]any{"name": "measure-" + key[:12], "annotations": map[string]any{
			"description": "module " + name + ", measured via /me/measure"}},
		"spec": map[string]any{"stages": []any{map[string]any{"name": "module", "spec": map[string]any{
			"taskType": "python", "entrypoint": "main", "image": m.Image,
			"timeoutSeconds": m.Limits.TimeoutS + moduleTimeoutGraceS, "network": "none", "code": code,
			"resources": map[string]any{"hardware": map[string]any{
				"cpu": m.Limits.CPU, "memory": m.Limits.memory()}}}}}},
	}
	wf, err := canonicalJSON(graph)
	if err != nil {
		return measurePlan{}, err
	}
	return measurePlan{version: m.digest(), label: m.ID, material: material, workflow: wf, site: "auto",
		name: fleetClip("measure module "+name, 128)}, nil
}

// pyRawLiteral renders s as an exact Python literal: a raw triple-quoted
// string when that is safe (no ”' inside, no trailing backslash or quote), else a
// regular quoted one.
func pyRawLiteral(s string) string {
	if !strings.Contains(s, "'''") && !strings.HasSuffix(s, `\`) && !strings.HasSuffix(s, "'") &&
		!strings.Contains(s, `\'`) {
		return "r'''" + s + "'''"
	}
	return pyStr(s)
}

// moduleWrapperCode is the fixed stage code: run the module with the inputs on
// stdin, read at most 1 MiB of stdout, parse ONE JSON object, return it. Every
// failure is an exception whose message says what went wrong, in words.
func moduleWrapperCode(run, inputsJSON string, timeoutS int) string {
	return "RUN = " + pyStr(run) + "\n" +
		"INPUTS = " + pyRawLiteral(inputsJSON) + "\n" +
		"TIMEOUT_S = " + strconv.Itoa(timeoutS) + "\n" +
		"MAX_OUT = " + strconv.Itoa(moduleMaxOutBytes) + "\n" + moduleWrapperBody
}

const moduleWrapperBody = `

class ModuleError(Exception):
    pass


def _no_constants(name):
    raise ValueError(name + " is not JSON")


def main():
    import json, shlex, shutil, subprocess, sys, tempfile, threading

    argv = shlex.split(RUN)
    if argv and argv[0] in ("python", "python3") and shutil.which(argv[0]) is None:
        argv[0] = sys.executable
    err = tempfile.TemporaryFile()
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
    except OSError as e:
        raise ModuleError("the module's run command could not start: %s" % e) from None

    def feed():
        try:
            p.stdin.write(INPUTS.encode("utf-8"))
        except OSError:
            pass  # it stopped reading; its exit status says why
        finally:
            try:
                p.stdin.close()
            except OSError:
                pass

    stopped = []

    def stop(why):
        stopped.append(why)
        try:
            p.kill()
        except OSError:
            pass

    threading.Thread(target=feed, daemon=True).start()
    timer = threading.Timer(TIMEOUT_S, stop, ("timeout",))
    timer.daemon = True
    timer.start()
    out = bytearray()
    while True:
        chunk = p.stdout.read(65536)
        if not chunk:
            break
        out += chunk
        if len(out) > MAX_OUT:
            stop("size")
            break
    code = p.wait()
    timer.cancel()
    err.seek(0)
    tail = err.read()[-2000:].decode("utf-8", "replace").strip()
    if "timeout" in stopped:
        raise ModuleError("the module did not finish within its limit of %d s" % TIMEOUT_S)
    if "size" in stopped:
        raise ModuleError("the module wrote more than 1 MiB on stdout; a module's output is at most 1 MiB")
    if code != 0:
        if code == -9 or code == 137:
            raise ModuleError("the module was killed (most often by its memory limit)" + (": " + tail if tail else ""))
        raise ModuleError("the module exited with code %d" % code + (": " + tail if tail else ""))
    text = out.decode("utf-8", "replace").strip()
    if not text:
        raise ModuleError("the module wrote nothing on stdout; it must write ONE JSON object")
    try:
        value = json.loads(text, parse_constant=_no_constants)
    except ValueError as e:
        raise ModuleError("the module's stdout is not ONE JSON object (%s): %r" % (e, text[:200])) from None
    if not isinstance(value, dict):
        raise ModuleError("the module must write ONE JSON object on stdout, not a %s" % type(value).__name__)
    return {"output": value}
`

// moduleSettleValue unwraps a settled module stage's value and re-checks the
// output limit. why != "" is a failure in words.
func moduleSettleValue(value map[string]any) (map[string]any, string) {
	out, isMap := value["output"].(map[string]any)
	if !isMap {
		return nil, "the module stage returned no output object"
	}
	s, err := canonicalJSON(out)
	if err != nil {
		return nil, "the module's output could not be stored: " + err.Error()
	}
	if len(s) > moduleMaxOutBytes {
		return nil, fmt.Sprintf("the module's output is %d KiB; a module's output is at most 1 MiB", len(s)>>10)
	}
	return out, ""
}

// moduleFailureWords drops the task runner's prefix from a module's own error.
func moduleFailureWords(msg string) string {
	for _, p := range []string{"python task failed: ModuleError: ", "ModuleError: "} {
		if i := strings.Index(msg, p); i >= 0 {
			return strings.TrimSpace(msg[i+len(p):])
		}
	}
	return msg
}

// moduleListing: the modules visible to app, for GET /me/measure/instruments.
// Only the caller's own install's modules are listed; a public module of
// another app is called by its owner-qualified name.
func moduleListing(sub, app string) []gin.H {
	if app == "" || !moduleAppRe.MatchString(app) {
		return nil
	}
	spec, found := moduleSpecSource(sub, "", app)
	if !found {
		return nil
	}
	mods, bad := specModules(spec)
	out := []gin.H{}
	for _, m := range mods {
		share := "tenant"
		if m.Share == "everyone" {
			share = "global"
		}
		item := gin.H{"name": app + "." + m.ID, "kind": "module", "title": m.Title, "about": m.About,
			"inputs": m.Inputs, "share": share, "public": m.Public, "image": m.Image, "run": m.Run,
			"versions": []string{m.digest()},
			"limits": gin.H{"cpu": m.Limits.CPU, "memory": m.Limits.memory(), "timeout_s": m.Limits.TimeoutS,
				"gpu": false, "network": "none", "max_output": "1 MiB", "max_inputs": "256 KiB"}}
		if len(m.Notes) > 0 {
			item["notes"] = m.Notes
		}
		out = append(out, item)
	}
	keys := make([]string, 0, len(bad))
	for k := range bad {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// Listed so the author sees why it cannot run.
		out = append(out, gin.H{"name": app + "." + k, "kind": "module", "refused": bad[k]})
	}
	return out
}
