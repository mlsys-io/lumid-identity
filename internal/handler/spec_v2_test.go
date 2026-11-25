package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"lumid_identity/models"
)

// Same fixture as LumidOS tests/test_spec_v2.py — the two normalizers agree.
func loadV2Fixture(t *testing.T) (map[string]any, string) {
	t.Helper()
	src, err := os.ReadFile("testdata/spec_v2_mlsys.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "notes", "simulate.md"), []byte("HOW TO CALL: run it.\n"), 0o644)
	spec := filepath.Join(dir, ".xpcloud.yaml")
	_ = os.WriteFile(spec, src, 0o644)
	b, err := readSpecAware(spec)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, spec
}

func loopNamed(doc map[string]any, name string) map[string]any {
	for _, lp := range asList(doc["loops"]) {
		if m := asMap(lp); specStr(m["name"]) == name {
			return m
		}
	}
	return nil
}

func TestSpecV2TopLevelAndLoops(t *testing.T) {
	doc, _ := loadV2Fixture(t)
	if doc["display_name"] != "MLSys Research" {
		t.Fatalf("display_name = %v", doc["display_name"])
	}
	if _, ok := doc["workflows"]; ok {
		t.Fatal("workflows should fold into loops")
	}
	var names []string
	for _, lp := range asList(doc["loops"]) {
		names = append(names, specStr(asMap(lp)["name"]))
	}
	if len(names) != 4 || names[0] != "simulate" || names[3] != "coach" {
		t.Fatalf("loops = %v", names)
	}
	sim := loopNamed(doc, "simulate")
	eng := asMap(sim["engine"])
	if sim["schedule"] != "@trigger" || eng["type"] != "command" || eng["module"] != "simulate" || eng["site"] != "office" {
		t.Fatalf("simulate = %#v", sim)
	}
	if eng["experiment"] != "sla_concurrency" {
		t.Fatalf("experiment = %v", eng["experiment"])
	}
	if sim["description"] != "Simulate one serving design.\n\nHOW TO CALL: run it." {
		t.Fatalf("description = %q", sim["description"])
	}
	found := false
	for _, a := range asList(eng["args"]) {
		if a == "--task={{ args.task | default('9.2') }}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("args = %v", eng["args"])
	}
	sb := loopNamed(doc, "sandbox")
	if sb["parent"] != "simulate" || sb["node"] != "real_gpu" || asMap(sb["engine"])["site"] != "home" {
		t.Fatalf("sandbox = %#v", sb)
	}
	if loopNamed(doc, "coach")["role"] != "helper" {
		t.Fatal("coach should be a helper")
	}
	score := asMap(loopNamed(doc, "score")["engine"])
	if score["type"] != "lumilake" || score["workflow"] != "score" || asMap(score["hardware"])["gpu_memory"] != "16Gi" {
		t.Fatalf("score engine = %#v", score)
	}
}

func TestSpecV2ExperimentAndPages(t *testing.T) {
	doc, _ := loadV2Fixture(t)
	e := asMap(asList(doc["experiments"])[0])
	if asMap(e["dispatch"])["loop"] != "simulate" || e["loop"] != "simulate" || e["dataset_id"] != "protocol_v1" {
		t.Fatalf("experiment = %#v", e)
	}
	if asMap(e["metric"])["higher_is_better"] != true || asMap(e["baseline"])["arm"] != "c32" || e["kind"] != "arms" {
		t.Fatalf("experiment = %#v", e)
	}
	arm := asMap(asList(e["arms"])[1])
	if arm["id"] != "c16" || arm["task"] != "9.2" || arm["overrides"] != "serving.max_concurrency=16" || arm["description"] != "max_concurrency 16" {
		t.Fatalf("arm = %#v", arm)
	}
	ui := asMap(doc["ui"])
	nav := asList(ui["nav"])
	if len(nav) != 1 || asMap(nav[0])["surface"] != "designs" || asMap(ui["surfaces"])["design"] != "ui/design.yaml" {
		t.Fatalf("ui = %#v", ui)
	}
}

// The real readers see the v2 app: loops with parent/node, and the measurement
// table resolves the primary metric from feedback.
func TestSpecV2ThroughReaders(t *testing.T) {
	_, spec := loadV2Fixture(t)
	loops, err := readYamlLoops(spec)
	if err != nil || len(loops) != 4 {
		t.Fatalf("readYamlLoops: %v %d", err, len(loops))
	}
	if loops[1].Parent != "simulate" || loops[1].Node != "real_gpu" || loops[3].Role != "helper" || len(loops[0].Feedback) != 1 {
		t.Fatalf("loops = %+v", loops)
	}
	raw, _ := os.ReadFile(spec)
	if got, _ := readYamlLoopsBytes(raw); len(got) != 4 {
		t.Fatalf("readYamlLoopsBytes on raw v2 = %d loops", len(got))
	}
}

func TestSpecV2LegacyUntouched(t *testing.T) {
	legacy := []byte("# comment kept\nloops:\n- name: x\n  schedule: '@trigger'\nexperiments:\n- id: e\n  dispatch: {loop: x}\n")
	if got := normalizeSpecBytes(legacy, ""); string(got) != string(legacy) {
		t.Fatalf("legacy spec rewritten:\n%s", got)
	}
}

func TestSpecV2NotesStayInBundle(t *testing.T) {
	doc := map[string]any{"workflows": []any{map[string]any{"id": "w", "about": "a", "notes": "../../etc/passwd", "steps": map[string]any{"python": "w"}}}}
	out := normalizeSpecDoc(doc, t.TempDir())
	if d := asMap(asList(out["loops"])[0])["description"]; d != "a" {
		t.Fatalf("description = %v", d)
	}
}

func TestWorkflowDefFileRe(t *testing.T) {
	for _, ok := range []string{"workflows/score.yaml", "notes/simulate.md", "commands/sandbox.py"} {
		if !workflowDefFileRe.MatchString(ok) || !appFileIntentPathOK(ok) {
			t.Fatalf("%s should be allowed", ok)
		}
	}
	for _, bad := range []string{"commands/../x.py", "commands/a-b.py", "secrets/x.yaml", "workflows/x.json", ".xpcloud.yaml"} {
		if workflowDefFileRe.MatchString(bad) {
			t.Fatalf("%s should be refused", bad)
		}
	}
	if !appFileIsCode("commands/sandbox.py") || appFileIsCode("workflows/x.yaml") {
		t.Fatal("appFileIsCode")
	}
}

// A Python step is code the scheduler runs: only an admin's batch may carry it,
// and the queued payload says so (the picker refuses commands/*.py without it).
func TestAppFileCodeNeedsAdmin(t *testing.T) {
	db := setupIntentDB(t)
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	db.Exec("DELETE FROM users WHERE id IN ('spec-v2-user','spec-v2-admin')")
	db.Create(&models.User{ID: "spec-v2-user", Email: "spec-v2-user@example.test", Role: "user"})
	db.Create(&models.User{ID: "spec-v2-admin", Email: "spec-v2-admin@example.test", Role: "admin"})
	defer db.Exec("DELETE FROM users WHERE id IN ('spec-v2-user','spec-v2-admin')")

	code := []map[string]any{writeOp("commands/sandbox.py", "def main():\n    return {}\n", "")}
	if _, err := queueAppFileBatch("spec-v2-user", "mlsys-research", code); err != errAppFileCode {
		t.Fatalf("non-admin code write: err = %v, want errAppFileCode", err)
	}
	id, err := queueAppFileBatch("spec-v2-admin", "mlsys-research", code)
	if err != nil {
		t.Fatalf("admin code write: %v", err)
	}
	var q models.MeAppIntent
	db.First(&q, "id = ?", id)
	if !strings.Contains(q.Payload, `"allow_code":true`) {
		t.Fatalf("payload lacks allow_code: %s", q.Payload)
	}
	// A DAG or notes file needs no flag.
	id, _ = queueAppFileBatch("spec-v2-user", "mlsys-research", []map[string]any{writeOp("workflows/score.yaml", "a: 1\n", "")})
	db.First(&q, "id = ?", id)
	if strings.Contains(q.Payload, "allow_code") {
		t.Fatalf("non-code batch carries allow_code: %s", q.Payload)
	}
	db.Where("1 = 1").Delete(&models.MeAppIntent{})
}
