package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const testModuleImage = "ghcr.io/acme/prompt-mod@sha256:" +
	"4444444444444444444444444444444444444444444444444444444444444444"

const testModuleSpec = `name: trace-lab
modules:
- id: prompt_stats
  title: Prompt length statistics
  about: Token-length histogram of a request trace.
  image: ` + testModuleImage + `
  run: python -m mymod.job
  inputs: {trace: "rows of {prompt_tokens}", bins: "number of bins"}
  limits: {cpu: 8, memory: 16Gi, timeout_s: 3600}
  share: everyone
- id: private_one
  image: ` + testModuleImage + `
  run: python -m mymod.other
- id: open_one
  image: ` + testModuleImage + `
  run: python -m mymod.open
  public: true
- id: tagged
  image: ghcr.io/acme/prompt-mod:latest
  run: python -m mymod.job
workflows:
- id: stats
  steps: {module: prompt_stats, inputs: {bins: 10}}
  inputs: {trace: "[]"}
`

func moduleEntry(t *testing.T, y string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(y), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestModuleEntryPinsTheImageAndClampsLimits(t *testing.T) {
	m, err := parseModuleEntry(moduleEntry(t, "id: a\nimage: "+testModuleImage+
		"\nrun: python -m x\nlimits: {cpu: 8, memory: 16Gi, timeout_s: 3600}\nshare: everyone"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Limits != (moduleLimits{CPU: 2, MemoryMi: 4096, TimeoutS: 600}) || len(m.Notes) != 3 || m.Share != "everyone" {
		t.Fatalf("clamped = %+v notes %v", m.Limits, m.Notes)
	}
	d, err := parseModuleEntry(moduleEntry(t, "id: a\nimage: "+testModuleImage+"\nrun: x\nlimits: {cpu: 0.5, memory: 512Mi}"))
	if err != nil || d.Limits != (moduleLimits{CPU: 1, MemoryMi: 512, TimeoutS: 120}) || d.Share != "you" || d.Public {
		t.Fatalf("defaults = %+v %v", d, err)
	}
	for name, y := range map[string]string{
		"tag only":        "id: a\nimage: ghcr.io/acme/x:v1\nrun: x",
		"short digest":    "id: a\nimage: ghcr.io/acme/x@sha256:abcd\nrun: x",
		"no image":        "id: a\nrun: x",
		"no run":          "id: a\nimage: " + testModuleImage,
		"bad id":          "id: A B\nimage: " + testModuleImage + "\nrun: x",
		"gpu limit":       "id: a\nimage: " + testModuleImage + "\nrun: x\nlimits: {gpu: 1}",
		"memory nonsense": "id: a\nimage: " + testModuleImage + "\nrun: x\nlimits: {memory: lots}",
		"negative cpu":    "id: a\nimage: " + testModuleImage + "\nrun: x\nlimits: {cpu: -1}",
		"share":           "id: a\nimage: " + testModuleImage + "\nrun: x\nshare: world",
		"public string":   "id: a\nimage: " + testModuleImage + "\nrun: x\npublic: \"yes\"",
	} {
		if _, err := parseModuleEntry(moduleEntry(t, y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = parseModuleEntry(moduleEntry(t, "id: a\nimage: ghcr.io/acme/x:v1\nrun: x"))
	if !strings.Contains(err.Error(), "not pinned by digest") {
		t.Errorf("tag refusal = %v", err)
	}
}

func TestModuleNames(t *testing.T) {
	for name, want := range map[string][3]string{
		"trace-lab.prompt_stats":           {"", "trace-lab", "prompt_stats"},
		"70f192ce-97f3/trace-lab.open_one": {"70f192ce-97f3", "trace-lab", "open_one"},
	} {
		o, a, id, ok := parseModuleName(name)
		if !ok || [3]string{o, a, id} != want {
			t.Errorf("%s = %q %q %q %v", name, o, a, id, ok)
		}
	}
	for _, name := range []string{"mlsys-simulator", "lqt-backtest", ".x", "a.", "a/b/c.d", "a.B C"} {
		if _, _, _, ok := parseModuleName(name); ok {
			t.Errorf("%s parsed as a module name", name)
		}
	}
}

func TestModulePlanIsOneLimitedStageKeyedByContent(t *testing.T) {
	mods, bad := specModules([]byte(testModuleSpec))
	if len(mods) != 3 || bad["tagged"] == "" {
		t.Fatalf("modules = %d, bad = %v", len(mods), bad)
	}
	m := mods[0]
	in := decodeInputs(t, `{"trace":[{"prompt_tokens":3}],"bins":10}`)
	p, err := modulePlan("trace-lab.prompt_stats", m, in)
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]any
	if err := json.Unmarshal([]byte(p.workflow), &g); err != nil {
		t.Fatal(err)
	}
	stages := g["spec"].(map[string]any)["stages"].([]any)
	if len(stages) != 1 {
		t.Fatalf("stages = %d", len(stages))
	}
	spec := stages[0].(map[string]any)["spec"].(map[string]any)
	hw := spec["resources"].(map[string]any)["hardware"].(map[string]any)
	if spec["taskType"] != "python" || spec["image"] != testModuleImage || spec["network"] != "none" ||
		spec["entrypoint"] != "main" || spec["timeoutSeconds"] != 630.0 || hw["cpu"] != 2.0 || hw["memory"] != "4096Mi" {
		t.Fatalf("stage = %v", spec)
	}
	if _, gpu := hw["gpu"]; gpu {
		t.Fatal("a module stage requested a GPU")
	}
	for k := range spec {
		switch k {
		case "taskType", "entrypoint", "image", "timeoutSeconds", "network", "code", "resources":
		default:
			t.Errorf("field %q is not one the FlowMesh python spec takes", k)
		}
	}
	if !strings.Contains(spec["code"].(string), `RUN = "python -m mymod.job"`) || p.site != "auto" {
		t.Errorf("code/site = %v / %s", spec["code"], p.site)
	}
	// The key is the content: same digest + run + inputs under another name
	// and another key order is the same row; other inputs or run are not.
	inst := moduleInstrument("trace-lab.prompt_stats", m)
	other := moduleInstrument("someone/trace-lab.prompt_stats", m)
	p2, _ := other.plan(decodeInputs(t, `{"bins":10,"trace":[{"prompt_tokens":3}]}`))
	if measureKey(inst.keyName(), p.version, p.keyed()) != measureKey(other.keyName(), p2.version, p2.keyed()) {
		t.Error("the same computation under two names got two keys")
	}
	p3, _ := modulePlan("x", m, decodeInputs(t, `{"bins":11,"trace":[{"prompt_tokens":3}]}`))
	m2 := m
	m2.Run = "python -m mymod.other"
	p4, _ := modulePlan("x", m2, in)
	k := measureKey("module", p.version, p.keyed())
	if measureKey("module", p3.version, p3.keyed()) == k || measureKey("module", p4.version, p4.keyed()) == k {
		t.Error("other inputs or another run command shared a key")
	}
	if inst.Share != "global" || moduleInstrument("x", mods[1]).Share != "tenant" {
		t.Errorf("share = %s / %s", inst.Share, moduleInstrument("x", mods[1]).Share)
	}
	// Inputs that cannot fit the job's code are refused in words.
	big := map[string]any{"trace": strings.Repeat("x", moduleMaxCodeBytes)}
	if _, err := modulePlan("x", m, big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized inputs = %v", err)
	}
}

func TestSpecModulesSaveCheckAndEngine(t *testing.T) {
	var doc map[string]any
	_ = yaml.Unmarshal([]byte(testModuleSpec), &doc)
	if err := specV2ChainError(doc); err == nil || !strings.Contains(err.Error(), "tagged") {
		t.Fatalf("a tag-only module saved: %v", err)
	}
	good := strings.Replace(testModuleSpec, "ghcr.io/acme/prompt-mod:latest", testModuleImage, 1)
	_ = yaml.Unmarshal([]byte(good), &doc)
	if err := specV2ChainError(doc); err != nil {
		t.Fatalf("valid modules refused: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown module": func(s string) string { return strings.Replace(s, "{module: prompt_stats", "{module: nope", 1) },
		"combined": func(s string) string {
			return strings.Replace(s, "{module: prompt_stats,", "{module: prompt_stats, python: x,", 1)
		},
		"duplicate": func(s string) string { return strings.Replace(s, "id: private_one", "id: prompt_stats", 1) },
	} {
		_ = yaml.Unmarshal([]byte(mutate(good)), &doc)
		if err := specV2ChainError(doc); err == nil {
			t.Errorf("%s: saved", name)
		}
	}
	out := normalizeSpecBytes([]byte(good), "")
	var norm struct {
		Loops []struct {
			Name   string         `yaml:"name"`
			Engine map[string]any `yaml:"engine"`
		} `yaml:"loops"`
		Modules []any `yaml:"modules"`
	}
	if err := yaml.Unmarshal(out, &norm); err != nil || len(norm.Loops) != 1 || len(norm.Modules) != 4 {
		t.Fatalf("normalized = %s (%v)", out, err)
	}
	eng := norm.Loops[0].Engine
	in, _ := eng["inputs"].(map[string]any)
	if eng["type"] != "module" || eng["module"] != "prompt_stats" || in["bins"] != 10 || in["trace"] != "[]" {
		t.Fatalf("engine = %v", eng)
	}
}

func TestResolveModuleVisibility(t *testing.T) {
	good := strings.Replace(testModuleSpec, "ghcr.io/acme/prompt-mod:latest", testModuleImage, 1)
	prev := moduleSpecSource
	t.Cleanup(func() { moduleSpecSource = prev })
	moduleSpecSource = func(sub, owner, app string) ([]byte, bool) {
		if app != "trace-lab" || (owner != "" && owner != "pub-owner") {
			return nil, false
		}
		return []byte(good), true
	}
	cases := []struct {
		name, app string
		code      int // 0 = resolves
		words     string
	}{
		{"trace-lab.prompt_stats", "trace-lab", 0, ""},
		{"trace-lab.prompt_stats", "", 0, ""},
		{"trace-lab.private_one", "other-app", http.StatusForbidden, "not visible to the other-app app"},
		{"trace-lab.open_one", "other-app", 0, ""},
		{"trace-lab.nope", "trace-lab", http.StatusNotFound, "declares no module"},
		{"missing-app.x", "", http.StatusNotFound, "no app"},
		{"pub-owner/trace-lab.open_one", "mine", 0, ""},
		{"pub-owner/trace-lab.private_one", "mine", http.StatusForbidden, "not public"},
		{"me/trace-lab.private_one", "trace-lab", 0, ""}, // owner == caller is their own install
	}
	for _, tc := range cases {
		_, _, isModule, ref := resolveModule("me", tc.name, tc.app)
		if !isModule {
			t.Errorf("%s: not a module", tc.name)
			continue
		}
		switch {
		case tc.code == 0 && ref != nil:
			t.Errorf("%s from %q refused: %s", tc.name, tc.app, ref.why)
		case tc.code != 0 && (ref == nil || ref.code != tc.code || !strings.Contains(ref.why, tc.words)):
			t.Errorf("%s from %q = %+v; want %d %q", tc.name, tc.app, ref, tc.code, tc.words)
		}
	}
	if _, _, isModule, _ := resolveModule("me", "mlsys-simulator", ""); isModule {
		t.Error("a registry instrument read as a module")
	}
}

func TestModuleSettleValue(t *testing.T) {
	out, why := moduleSettleValue(map[string]any{"output": map[string]any{"p50": 3}})
	if why != "" || out["p50"] != 3 {
		t.Fatalf("settle = %v %q", out, why)
	}
	if _, why := moduleSettleValue(map[string]any{"output": map[string]any{"x": strings.Repeat("y", moduleMaxOutBytes)}}); !strings.Contains(why, "at most 1 MiB") {
		t.Errorf("oversized = %q", why)
	}
	if _, why := moduleSettleValue(map[string]any{"nothing": 1}); why == "" {
		t.Error("no output accepted")
	}
	if got := moduleFailureWords("python task failed: ModuleError: the module exited with code 2: boom"); got != "the module exited with code 2: boom" {
		t.Errorf("words = %q", got)
	}
}

// The wrapper is real Python: run it here against small stand-in modules.
func TestModuleWrapperRunsTheCommand(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	echo := write("echo.py", "import json,sys\nd=json.load(sys.stdin)\nprint(json.dumps({'n': len(d['rows']), 'q': d['q']}))\n")
	cases := []struct {
		name, script, inputs string
		timeout              int
		want                 string // substring of the result line, or of the error
	}{
		{"ok", echo, `{"q":"it's \"quoted\"","rows":[1,2,3]}`, 30, `{"output": {"n": 3, "q": "it's \"quoted\""}}`},
		{"not json", write("text.py", "print('hello')\n"), `{}`, 30, "not ONE JSON object"},
		{"a list", write("list.py", "print('[1,2]')\n"), `{}`, 30, "not a list"},
		{"nan", write("nan.py", "print('{\"x\": NaN}')\n"), `{}`, 30, "not ONE JSON object"},
		{"exit", write("exit.py", "import sys\nsys.stderr.write('boom')\nsys.exit(2)\n"), `{}`, 30, "exited with code 2: boom"},
		{"silent", write("silent.py", "pass\n"), `{}`, 30, "wrote nothing"},
		{"slow", write("slow.py", "import time\ntime.sleep(30)\n"), `{}`, 1, "within its limit of 1 s"},
		{"big", write("big.py", "import sys\nsys.stdout.write('x' * (2 << 20))\n"), `{}`, 30, "more than 1 MiB"},
	}
	for _, tc := range cases {
		code := moduleWrapperCode("python3 "+tc.script, tc.inputs, tc.timeout) +
			"\nif __name__ == '__main__':\n    import json\n    try:\n        print(json.dumps(main()))\n" +
			"    except ModuleError as e:\n        print('ERR', e)\n"
		prog := write(tc.name+"_wrap.py", code)
		out, err := exec.Command(py, prog).CombinedOutput()
		if err != nil || !strings.Contains(string(out), tc.want) {
			t.Errorf("%s: %s (%v); want %q", tc.name, out, err, tc.want)
		}
	}
	// pyRawLiteral falls back to a quoted literal when a raw one is unsafe.
	for _, s := range []string{`{"a":"'''"}`, `{"a":"x\\'"}`, `{}`} {
		prog := write("lit.py", "import sys\nsys.stdout.write("+pyRawLiteral(s)+")\n")
		if out, err := exec.Command(py, prog).Output(); err != nil || string(out) != s {
			t.Errorf("literal %s -> %q (%v)", s, out, err)
		}
	}
}

// ── The full flow against a fake FlowMesh (needs TEST_MYSQL_DSN) ────────

type fakeModuleFM struct {
	mu     sync.Mutex
	state  string // PENDING | DONE | FAILED
	posted string
	posts  int
}

func (f *fakeModuleFM) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows":
		f.posts++
		f.posted = string(body)
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-mod001","status":"PENDING"}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/workflows/wfl-mod001":
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-mod001","status":"` + f.state + `","task_ids":["tsk-mod"]}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/tasks":
		errField := `null`
		if f.state == "FAILED" {
			errField = `"python task failed: ModuleError: the module exited with code 2: bad trace"`
		}
		_, _ = w.Write([]byte(`[{"task_id":"tsk-mod","status":"` + f.state + `","error":` + errField +
			`,"task":{"metadata":{"name":"g:module"}},"usages":[{"runtime_sec":3,"hardware":{"gpu":{"devices":[]}}}]}]`))
	case r.Method == "GET" && p == "/fm/home/api/v1/results/tsk-mod":
		_, _ = w.Write([]byte(`{"task_type":"python","value":{"output":{"p50":12,"hist":[1,2]}}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func moduleTestSetup(t *testing.T) (*fakeModuleFM, string, string) {
	t.Helper()
	_, owner, other := fleetTestSetup(t)
	f := &fakeModuleFM{state: "PENDING"}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	t.Setenv("FLEET_BASE_URL", srv.URL)
	t.Setenv("MEASURE_SITES", "home")
	osub, xsub := subOf(t, owner), subOf(t, other)
	measureCleanup(t, osub, xsub)
	// The stored spec as written, tag-only module included: it is refused when
	// called, not when listed.
	for _, s := range []string{osub, xsub} {
		common.DB.Where("user_sub = ? AND app = ?", s, "trace-lab").Delete(&models.MeAppSpec{})
		common.DB.Create(&models.MeAppSpec{UserSub: s, App: "trace-lab", SpecYAML: testModuleSpec, UIFiles: "{}",
			UpdatedAt: time.Now()})
	}
	t.Cleanup(func() { common.DB.Where("user_sub IN ?", []string{osub, xsub}).Delete(&models.MeAppSpec{}) })
	return f, owner, other
}

const moduleBody = `{"instrument":"trace-lab.prompt_stats","app":"trace-lab","workflow":"stats",` +
	`"inputs":{"trace":[{"prompt_tokens":3}],"bins":10}}`

func TestModuleMeasuresOnceAndIsReusedWithinItsShare(t *testing.T) {
	f, owner, other := moduleTestSetup(t)
	code, first := measureCall(t, "POST", "/api/v1/me/measure", moduleBody, owner)
	if code != http.StatusAccepted || first["status"] != "running" || f.posts != 1 {
		t.Fatalf("submit = %d %v", code, first)
	}
	if !strings.Contains(f.posted, `"network":"none"`) || !strings.Contains(f.posted, `"memory":"4096Mi"`) ||
		!strings.Contains(f.posted, `"cpu":2`) || !strings.Contains(f.posted, `"image":"`+testModuleImage+`"`) {
		t.Fatalf("posted graph = %s", f.posted)
	}
	f.state = "DONE"
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner)
	res, _ := got["result"].(map[string]any)
	value, _ := res["value"].(map[string]any)
	if code != 200 || got["status"] != "succeeded" || value["p50"] != 12.0 || res["share"] != "everyone" ||
		res["measured_on"] != "trace-lab.prompt_stats" {
		t.Fatalf("settled = %d %v", code, got)
	}
	// share: everyone — another user's identical call is answered from it.
	code, again := measureCall(t, "POST", "/api/v1/me/measure", moduleBody, other)
	res2, _ := again["result"].(map[string]any)
	if code != 200 || again["status"] != "succeeded" || res2["reused"] != true || f.posts != 1 {
		t.Fatalf("reuse = %d %v (posts %d)", code, again, f.posts)
	}
	// Not visible from another app; private modules refuse in words.
	code, refused := measureCall(t, "POST", "/api/v1/me/measure",
		strings.Replace(strings.Replace(moduleBody, "prompt_stats", "private_one", 1), `"app":"trace-lab"`, `"app":"other"`, 1), owner)
	if code != http.StatusForbidden || !strings.Contains(refused["_message"].(string), "not visible") {
		t.Fatalf("private from another app = %d %v", code, refused)
	}
	code, refused = measureCall(t, "POST", "/api/v1/me/measure", strings.Replace(moduleBody, "prompt_stats", "tagged", 1), owner)
	if code != http.StatusBadRequest || !strings.Contains(refused["_message"].(string), "not pinned") {
		t.Fatalf("tag-only = %d %v", code, refused)
	}
	// The listing for the app shows its modules with their clamped limits.
	code, list := measureCall(t, "GET", "/api/v1/me/measure/instruments?app=trace-lab", "", owner)
	found := false
	for _, it := range list["instruments"].([]any) {
		m := it.(map[string]any)
		if m["name"] == "trace-lab.prompt_stats" {
			found = true
			lim := m["limits"].(map[string]any)
			if m["kind"] != "module" || lim["cpu"] != 2.0 || lim["memory"] != "4096Mi" || lim["timeout_s"] != 600.0 ||
				m["share"] != "global" {
				t.Errorf("listed = %v", m)
			}
		}
	}
	if code != 200 || !found {
		t.Fatalf("listing = %d %v", code, list)
	}
}

func TestModuleFailureSaysWhyInWords(t *testing.T) {
	f, owner, _ := moduleTestSetup(t)
	_, first := measureCall(t, "POST", "/api/v1/me/measure", moduleBody, owner)
	f.state = "FAILED"
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner)
	if code != 200 || got["status"] != "failed" || got["error"] != "the module exited with code 2: bad trace" {
		t.Fatalf("failed = %d %v", code, got)
	}
}
