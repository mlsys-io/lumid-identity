package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// A simple-scheme spec shaped like MLSys Research: a variant (sandbox) of
// simulate sits in a node; a variant of the variant; an experiment; a chain.
const wfDeleteSpec = `# MLSys Research — operator notes live here
name: mlsys-research-e2e
title: MLSys Research
version: 0.4.0

workflows:                # the graph's first layer
  - id: simulate
    title: Simulate
    steps: {python: simulate}
  - id: sandbox           # a VARIANT of simulate
    parent: simulate
    node: real_gpu
    steps: {python: sandbox}
  - id: sla_tuned
    parent: sandbox       # variant of the variant
    steps: {python: sandbox}
  - id: pipeline
    steps:
      workflows:
        - simulate
        - use: sla_tuned
          inputs: {days: 7}

nodes:
  - {id: real_gpu, title: On a real GPU, parent: simulate}
  - {id: tuned, title: Tuned, parent: sandbox}   # keep this comment

experiments:
  # the study the e2e scenario creates
  - id: sla_concurrency
    workflow: sandbox
    question: How far can concurrency go?
  - id: other
    workflow: simulate
`

func wfParse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("rewritten spec does not parse: %v\n%s", err, b)
	}
	return doc
}

func wfIDs(doc map[string]any, list, key string) []string {
	var out []string
	for _, e := range asList(doc[list]) {
		out = append(out, specStr(asMap(e)[key]))
	}
	return out
}

func wfEntry(doc map[string]any, list, id string) map[string]any {
	for _, e := range asList(doc[list]) {
		if m := asMap(e); specStr(m["id"]) == id || specStr(m["name"]) == id {
			return m
		}
	}
	return nil
}

func TestPlanWorkflowDelete(t *testing.T) {
	// The pipeline chain names sla_tuned; most cases drop the chain first.
	noChain := strings.Replace(wfDeleteSpec, `  - id: pipeline
    steps:
      workflows:
        - simulate
        - use: sla_tuned
          inputs: {days: 7}
`, "", 1)

	cases := []struct {
		name       string
		spec       string
		wf         string
		force      bool
		wantStatus int
		wantMsg    string // substring of the refusal
		check      func(t *testing.T, p *workflowDeletePlan, doc map[string]any)
	}{
		{
			name: "simple scheme: delete a leaf workflow", spec: noChain, wf: "sla_tuned",
			wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if got := wfIDs(doc, "workflows", "id"); !reflect.DeepEqual(got, []string{"simulate", "sandbox"}) {
					t.Errorf("workflows = %v", got)
				}
				if p.Remaining != 2 || !reflect.DeepEqual(p.Lists, []string{"workflows"}) {
					t.Errorf("plan = %+v", p)
				}
				if len(p.ReparentedNodes)+len(p.ReparentedWorkflows)+len(p.DroppedExperiments) != 0 {
					t.Errorf("a leaf delete changed other entries: %+v", p)
				}
				if p.onlyRemovesLegacyLoop() {
					t.Error("a workflows: delete must not go as a remove_loop intent")
				}
			},
		},
		{
			name: "re-parent nodes and child workflows to the deleted one's parent", spec: noChain,
			wf: "sandbox", force: true, wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if got := specStr(wfEntry(doc, "workflows", "sla_tuned")["parent"]); got != "simulate" {
					t.Errorf("sla_tuned.parent = %q, want simulate", got)
				}
				if got := specStr(wfEntry(doc, "nodes", "tuned")["parent"]); got != "simulate" {
					t.Errorf("node tuned.parent = %q, want simulate", got)
				}
				if got := specStr(wfEntry(doc, "nodes", "real_gpu")["parent"]); got != "simulate" {
					t.Errorf("unrelated node changed: %q", got)
				}
				if len(asList(doc["nodes"])) != 2 {
					t.Errorf("a node was deleted: %v", doc["nodes"])
				}
				if !reflect.DeepEqual(p.ReparentedNodes, []string{"tuned"}) ||
					!reflect.DeepEqual(p.ReparentedWorkflows, []string{"sla_tuned"}) {
					t.Errorf("plan = %+v", p)
				}
			},
		},
		{
			name: "re-parent with no grandparent drops the parent key", spec: noChain,
			wf: "simulate", force: true, wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if _, has := wfEntry(doc, "workflows", "sandbox")["parent"]; has {
					t.Errorf("sandbox kept parent: %v", wfEntry(doc, "workflows", "sandbox"))
				}
				if _, has := wfEntry(doc, "nodes", "real_gpu")["parent"]; has {
					t.Errorf("real_gpu kept parent: %v", wfEntry(doc, "nodes", "real_gpu"))
				}
				if got := specStr(wfEntry(doc, "workflows", "sla_tuned")["parent"]); got != "sandbox" {
					t.Errorf("grandchild re-parented: %q", got)
				}
				if got := specStr(wfEntry(doc, "workflows", "sandbox")["node"]); got != "real_gpu" {
					t.Errorf("sandbox lost its node: %q", got)
				}
			},
		},
		{
			name: "experiment refusal", spec: noChain, wf: "sandbox",
			wantStatus: 409, wantMsg: "Experiment 'sla_concurrency' runs on this workflow; archive or move it first",
		},
		{
			name: "experiment refusal names every experiment", spec: noChain + "  - id: second\n    workflow: sandbox\n",
			wf: "sandbox", wantStatus: 409, wantMsg: "Experiments 'sla_concurrency', 'second' run on this workflow",
		},
		{
			name: "force drops the experiments with it", spec: noChain, wf: "sandbox", force: true,
			wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if got := wfIDs(doc, "experiments", "id"); !reflect.DeepEqual(got, []string{"other"}) {
					t.Errorf("experiments = %v", got)
				}
				if !reflect.DeepEqual(p.DroppedExperiments, []string{"sla_concurrency"}) {
					t.Errorf("dropped = %v", p.DroppedExperiments)
				}
			},
		},
		{
			name: "chain refusal ({use: id} stage)", spec: wfDeleteSpec, wf: "sla_tuned", force: true,
			wantStatus: 409, wantMsg: "Chain 'pipeline' runs this workflow as a stage",
		},
		{
			name: "chain refusal (bare id stage), even with force", spec: wfDeleteSpec, wf: "simulate", force: true,
			wantStatus: 409, wantMsg: "Chain 'pipeline'",
		},
		{
			name: "deleting the chain itself is fine", spec: wfDeleteSpec, wf: "pipeline", wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if p.Remaining != 3 {
					t.Errorf("remaining = %d", p.Remaining)
				}
			},
		},
		{
			name: "translated chain engine also refuses",
			spec: "loops:\n  - name: a\n  - name: c\n    engine: {type: chain, stages: [{loop: a}]}\n",
			wf:   "a", wantStatus: 409, wantMsg: "Chain 'c'",
		},
		{
			name: "last workflow refusal (simple scheme)", spec: "workflows:\n  - id: only\n    steps: {python: x}\n",
			wf: "only", wantStatus: 409, wantMsg: "can't remove the last workflow",
		},
		{
			name: "last workflow counts both lists",
			spec: "workflows:\n  - id: a\nloops:\n  - name: b\n", wf: "a", wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if p.Remaining != 1 || len(asList(doc["workflows"])) != 0 {
					t.Errorf("plan = %+v doc = %v", p, doc)
				}
			},
		},
		{
			name: "unknown workflow", spec: noChain, wf: "nope", wantStatus: 404,
			wantMsg: "workflow 'nope' not found in app",
		},
		{
			name: "a nested step name is not a workflow",
			spec: "loops:\n  - name: a\n    steps: [{name: b}]\n  - name: c\n", wf: "b", wantStatus: 404,
		},
		{
			name: "legacy loops: still works",
			spec: "name: legacy\n# my loops\nloops:\n  - name: a   # first\n    schedule: '@daily'\n  - name: b\n    schedule: '@trigger'\n",
			wf:   "a", wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				if got := wfIDs(doc, "loops", "name"); !reflect.DeepEqual(got, []string{"b"}) {
					t.Errorf("loops = %v", got)
				}
				if !p.onlyRemovesLegacyLoop() {
					t.Errorf("a plain loops: delete should stay a remove_loop intent: %+v", p)
				}
				if !strings.Contains(string(p.Out), "# my loops") {
					t.Errorf("legacy comment lost:\n%s", p.Out)
				}
			},
		},
		{
			name: "comments and key order survive the rewrite", spec: noChain, wf: "sandbox", force: true,
			wantStatus: 200,
			check: func(t *testing.T, p *workflowDeletePlan, doc map[string]any) {
				out := string(p.Out)
				for _, c := range []string{
					"# MLSys Research — operator notes live here",
					"# the graph's first layer",
					"# variant of the variant",
					"# keep this comment",
				} {
					if !strings.Contains(out, c) {
						t.Errorf("comment %q lost:\n%s", c, out)
					}
				}
				if strings.Contains(out, "a VARIANT of simulate") {
					t.Errorf("the deleted entry's comment should go with it:\n%s", out)
				}
				order := []string{"name:", "title:", "version:", "workflows:", "nodes:", "experiments:"}
				last := -1
				for _, k := range order {
					i := strings.Index(out, "\n"+k) // out opens with a comment line
					if i <= last {
						t.Errorf("key %s out of order:\n%s", k, out)
					}
					last = i
				}
				// Flow style is kept, too.
				if !strings.Contains(out, "steps: {python: simulate}") {
					t.Errorf("flow mapping reformatted:\n%s", out)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, status, code, msg := planWorkflowDelete([]byte(c.spec), "app", c.wf, c.force)
			if status != c.wantStatus {
				t.Fatalf("status = %d (%d %q), want %d", status, code, msg, c.wantStatus)
			}
			if c.wantMsg != "" && !strings.Contains(msg, c.wantMsg) {
				t.Errorf("message = %q, want it to contain %q", msg, c.wantMsg)
			}
			if status == http.StatusConflict && code != 1409 {
				t.Errorf("code = %d", code)
			}
			if c.check != nil {
				c.check(t, p, wfParse(t, p.Out))
			}
		})
	}
}

func TestPlanWorkflowDeleteBadSpec(t *testing.T) {
	if _, status, _, _ := planWorkflowDelete([]byte("workflows: [\n"), "app", "a", false); status != 500 {
		t.Errorf("unparseable spec: %d", status)
	}
	if _, status, _, _ := planWorkflowDelete([]byte(""), "app", "a", false); status != 404 {
		t.Errorf("empty spec: %d", status)
	}
	if _, status, _, _ := planWorkflowDelete([]byte("- a\n"), "app", "a", false); status != 404 {
		t.Errorf("non-mapping spec: %d", status)
	}
}

func TestTruthyParam(t *testing.T) {
	for v, want := range map[string]bool{"1": true, "true": true, "YES": true, "": false, "0": false, "no": false} {
		if truthyParam(v) != want {
			t.Errorf("truthyParam(%q) != %v", v, want)
		}
	}
}

// The direct path (tenant tree mounted): the rewrite lands in the dotfile, a
// legacy xpcloud.yaml is not left behind, cycles are archived, and the
// manifest mirror is kept in step.
func TestRemoveLoopFromAppDirect(t *testing.T) {
	cases := []struct {
		name, specFile, spec, manifest, wf string
		force                              bool
		wantStatus, wantRemaining          int
	}{
		{name: "simple scheme in the dotfile", specFile: ".xpcloud.yaml", spec: wfDeleteSpec,
			wf: "pipeline", wantStatus: 200, wantRemaining: 3},
		{name: "simple scheme refusal leaves the file alone", specFile: ".xpcloud.yaml", spec: wfDeleteSpec,
			wf: "sla_tuned", wantStatus: 409},
		{name: "legacy loops in a legacy xpcloud.yaml", specFile: "xpcloud.yaml",
			spec:     "name: legacy\n# keep me\nloops:\n  - name: a\n  - name: b\n",
			manifest: `{"name":"legacy","loops":[{"name":"a"},{"name":"b"}]}`,
			wf:       "a", wantStatus: 200, wantRemaining: 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("LUMID_OPERATOR_HOME", home)
			user, app := "u-test", "mlsys-research-e2e"
			appDir := filepath.Join(tenantAppsDir(user), app)
			cycles := filepath.Join(appDir, "data", "cycles", c.wf, "20261128T000000")
			if err := os.MkdirAll(cycles, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(appDir, c.specFile), []byte(c.spec), 0o644); err != nil {
				t.Fatal(err)
			}
			if c.manifest != "" {
				_ = os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(c.manifest), 0o644)
			}

			r := removeLoopFromApp(user, app, c.wf, c.force)
			if r.Status != c.wantStatus {
				t.Fatalf("status = %d (%s), want %d", r.Status, r.Msg, c.wantStatus)
			}
			if r.IntentID != "" {
				t.Fatalf("direct path queued an intent: %+v", r)
			}
			if c.wantStatus != 200 {
				b, _ := os.ReadFile(filepath.Join(appDir, c.specFile))
				if string(b) != c.spec {
					t.Error("a refused delete rewrote the spec")
				}
				if _, err := os.Stat(cycles); err != nil {
					t.Error("a refused delete moved the cycles")
				}
				return
			}
			if r.Remaining != c.wantRemaining {
				t.Errorf("remaining = %d, want %d", r.Remaining, c.wantRemaining)
			}
			out, err := os.ReadFile(SpecWritePath(appDir))
			if err != nil {
				t.Fatalf("dotfile not written: %v", err)
			}
			if c.specFile != SpecDotfile {
				if _, err := os.Stat(filepath.Join(appDir, c.specFile)); err == nil {
					t.Error("legacy spec left behind next to the dotfile")
				}
			}
			if wfEntry(wfParse(t, out), "workflows", c.wf) != nil || wfEntry(wfParse(t, out), "loops", c.wf) != nil {
				t.Errorf("workflow still in the spec:\n%s", out)
			}
			if !strings.Contains(string(out), "#") {
				t.Errorf("comments lost:\n%s", out)
			}
			if _, err := os.Stat(cycles); err == nil {
				t.Error("cycle history not moved out of the live tree")
			}
			trash, _ := filepath.Glob(filepath.Join(tenantRoot(user), ".xp", ".trash", app, c.wf+"-*"))
			if len(trash) != 1 {
				t.Errorf("cycle history not archived: %v", trash)
			}
			if c.manifest != "" {
				manPath, _ := ResolveManifestPath(appDir)
				mb, _ := os.ReadFile(manPath)
				var mj map[string]any
				_ = json.Unmarshal(mb, &mj)
				if got := asList(mj["loops"]); len(got) != 1 {
					t.Errorf("manifest mirror loops = %v", got)
				}
			}
		})
	}
}

// wfDeleteSeedInstall seeds an install the scheduler echoed (install done)
// whose current spec is an applied app_file_write, so readAppSpecBytes finds it.
func wfDeleteSeedInstall(t *testing.T, user, app, spec string) {
	t.Helper()
	now := time.Now()
	past := now.Add(-time.Hour)
	content, _ := json.Marshal(spec)
	rows := []models.MeAppIntent{
		{ID: "wfdel-install-" + app, Action: "install", UserSub: user, Status: "done",
			Payload: `{"slug":"owner/` + app + `"}`, CreatedAt: past, CompletedAt: &past},
		{ID: "wfdel-spec-" + app, Action: appFileWriteAction, UserSub: user, Status: "done",
			Payload:   `{"app":"` + app + `","path":".xpcloud.yaml","op":"write","content":` + string(content) + `,"base_sha":""}`,
			CreatedAt: now, CompletedAt: &now},
	}
	if err := common.DB.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// With a scheduler that runs the simple-scheme remove_loop
// (LUMID_SCHEDULER_REMOVES_WORKFLOWS=1), every delete is a remove_loop
// intent carrying force, so the scheduler archives the workflow's runs and
// mirrors the manifest; identity's pre-checks still refuse at once, in words.
func TestRemoveLoopFromAppViaRemoveLoop(t *testing.T) {
	t.Setenv("LUMID_SCHEDULER_REMOVES_WORKFLOWS", "1")
	db := setupIntentDB(t)
	if err := db.AutoMigrate(&models.MeAppSpec{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	user := "u-wfdel-rl"
	t.Cleanup(func() { common.DB.Where("user_sub = ?", user).Delete(&models.MeAppSpec{}) })
	pending := func(action string) []models.MeAppIntent {
		var rows []models.MeAppIntent
		db.Where("user_sub = ? AND action = ? AND status = ?", user, action, "pending").
			Order("created_at").Find(&rows)
		return rows
	}
	payloadOf := func(row models.MeAppIntent) map[string]any {
		var pl map[string]any
		if err := json.Unmarshal([]byte(row.Payload), &pl); err != nil {
			t.Fatalf("payload: %v", err)
		}
		return pl
	}
	wfDeleteSeedInstall(t, user, "simple", wfDeleteSpec)
	wfDeleteSeedInstall(t, user, "legacy", "name: legacy\nloops:\n  - name: a\n  - name: b\n")

	// Refusals answer synchronously, in identity's words, and queue nothing.
	for _, c := range []struct {
		wf    string
		force bool
		code  int
		msg   string
	}{
		{"sandbox", false, 409, "Experiment 'sla_concurrency' runs on this workflow; archive or move it first"},
		{"sla_tuned", true, 409, "Chain 'pipeline' runs this workflow as a stage"},
		{"nope", false, 404, "workflow 'nope' not found in simple"},
	} {
		if r := removeLoopFromApp(user, "simple", c.wf, c.force); r.Status != c.code ||
			r.IntentID != "" || !strings.Contains(r.Msg, c.msg) {
			t.Errorf("%s: %+v", c.wf, r)
		}
	}
	if n := len(pending(appFileWriteAction)) + len(pending("remove_loop")); n != 0 {
		t.Fatalf("a refusal queued %d intents", n)
	}

	// Simple scheme: a remove_loop, never a spec write.
	r := removeLoopFromApp(user, "simple", "pipeline", false)
	if r.Status != 200 || r.IntentID == "" || r.SpecWrite || r.Remaining != 3 {
		t.Fatalf("simple delete: %+v", r)
	}
	rl := pending("remove_loop")
	if len(rl) != 1 || rl[0].ID != r.IntentID {
		t.Fatalf("want one remove_loop intent, got %+v", rl)
	}
	if pl := payloadOf(rl[0]); !reflect.DeepEqual(pl, map[string]any{"app": "simple", "loop": "pipeline"}) {
		t.Errorf("payload = %v (force only when asked)", pl)
	}

	// force rides along; the plan's details are reported as expected.
	r = removeLoopFromApp(user, "simple", "sandbox", true)
	if r.Status != 200 || r.IntentID == "" || r.SpecWrite {
		t.Fatalf("forced delete: %+v", r)
	}
	if !reflect.DeepEqual(r.Plan.DroppedExperiments, []string{"sla_concurrency"}) {
		t.Errorf("plan = %+v", r.Plan)
	}
	rl = pending("remove_loop")
	if len(rl) != 2 || rl[1].ID != r.IntentID {
		t.Fatalf("want a second remove_loop intent, got %+v", rl)
	}
	if pl := payloadOf(rl[1]); pl["loop"] != "sandbox" || pl["force"] != true {
		t.Errorf("forced payload = %v", pl)
	}

	// Legacy: unchanged, a remove_loop.
	r = removeLoopFromApp(user, "legacy", "a", false)
	if r.Status != 200 || r.IntentID == "" || r.SpecWrite || r.Remaining != 1 {
		t.Fatalf("legacy delete: %+v", r)
	}
	if n := len(pending(appFileWriteAction)); n != 0 {
		t.Errorf("%d spec writes queued; deletes must all be remove_loop", n)
	}
}

// The UKS path (identity mounts no tenant volume) against a scheduler older
// than the simple-scheme remove_loop (LUMID_SCHEDULER_REMOVES_WORKFLOWS
// unset): a simple-scheme delete is queued as an app_file_write of the
// rewritten spec, base_sha = the bytes it was planned on; a plain legacy delete
// stays a remove_loop intent; a refusal queues nothing.
func TestRemoveLoopFromAppViaIntent(t *testing.T) {
	t.Setenv("LUMID_SCHEDULER_REMOVES_WORKFLOWS", "")
	db := setupIntentDB(t)
	if err := db.AutoMigrate(&models.MeAppSpec{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	user := "u-wfdel"
	t.Cleanup(func() { common.DB.Where("user_sub = ?", user).Delete(&models.MeAppSpec{}) })
	now := time.Now()
	past := now.Add(-time.Hour)
	seed := func(app, spec string) {
		t.Helper()
		content, _ := json.Marshal(spec)
		rows := []models.MeAppIntent{
			{ID: "wfdel-install-" + app, Action: "install", UserSub: user, Status: "done",
				Payload: `{"slug":"owner/` + app + `"}`, CreatedAt: past, CompletedAt: &past},
			{ID: "wfdel-spec-" + app, Action: appFileWriteAction, UserSub: user, Status: "done",
				Payload:   `{"app":"` + app + `","path":".xpcloud.yaml","op":"write","content":` + string(content) + `,"base_sha":""}`,
				CreatedAt: now, CompletedAt: &now},
		}
		if err := db.Create(&rows).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	pending := func(action string) []models.MeAppIntent {
		var rows []models.MeAppIntent
		db.Where("user_sub = ? AND action = ? AND status = ?", user, action, "pending").Find(&rows)
		return rows
	}

	seed("simple", wfDeleteSpec)
	legacy := "name: legacy\nloops:\n  - name: a\n  - name: b\n"
	seed("legacy", legacy)

	// Refused: an experiment runs on sandbox. Nothing is queued.
	if r := removeLoopFromApp(user, "simple", "sandbox", false); r.Status != 409 || r.IntentID != "" {
		t.Fatalf("experiment refusal: %+v", r)
	}
	if r := removeLoopFromApp(user, "simple", "sla_tuned", true); r.Status != 409 {
		t.Fatalf("chain refusal: %+v", r)
	}
	if n := len(pending(appFileWriteAction)) + len(pending("remove_loop")); n != 0 {
		t.Fatalf("a refusal queued %d intents", n)
	}

	// Simple scheme: queued as a spec write against the bytes it read.
	r := removeLoopFromApp(user, "simple", "pipeline", false)
	if r.Status != 200 || r.IntentID == "" || r.Remaining != 3 {
		t.Fatalf("simple delete: %+v", r)
	}
	writes := pending(appFileWriteAction)
	if len(writes) != 1 || writes[0].ID != r.IntentID {
		t.Fatalf("want one queued spec write, got %+v", writes)
	}
	var pl map[string]any
	_ = json.Unmarshal([]byte(writes[0].Payload), &pl)
	if pl["path"] != ".xpcloud.yaml" || pl["base_sha"] != contentSHA([]byte(wfDeleteSpec)) {
		t.Errorf("payload path/base_sha wrong: %v %v", pl["path"], pl["base_sha"])
	}
	content, _ := pl["content"].(string)
	if wfEntry(wfParse(t, []byte(content)), "workflows", "pipeline") != nil ||
		!strings.Contains(content, "# MLSys Research — operator notes live here") {
		t.Errorf("queued spec wrong:\n%s", content)
	}
	if len(pending("remove_loop")) != 0 {
		t.Error("a simple-scheme delete must not queue remove_loop (the scheduler only reads loops:)")
	}

	// Legacy: the scheduler's remove_loop (it archives the history).
	r = removeLoopFromApp(user, "legacy", "a", false)
	if r.Status != 200 || r.IntentID == "" {
		t.Fatalf("legacy delete: %+v", r)
	}
	if rl := pending("remove_loop"); len(rl) != 1 || rl[0].ID != r.IntentID {
		t.Fatalf("want one remove_loop intent, got %+v", rl)
	}
	if r := removeLoopFromApp(user, "legacy", "zz", false); r.Status != 404 {
		t.Errorf("unknown legacy loop: %+v", r)
	}
}
