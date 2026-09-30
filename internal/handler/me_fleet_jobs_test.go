package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

// ── pure ────────────────────────────────────────────────────────────────────

func TestParseFleetJobID(t *testing.T) {
	good := map[string]fleetJobID{
		"home:fm:wfl-3f2a":          {"home", "fm", "wfl-3f2a"},
		"cloud:ll:req-abcdef123456": {"cloud", "ll", "req-abcdef123456"},
		"office:fm:5b1e.9-x_y":      {"office", "fm", "5b1e.9-x_y"},
	}
	for s, want := range good {
		got, valid := parseFleetJobID(s)
		if !valid || got != want {
			t.Errorf("%q = %#v,%v want %#v", s, got, valid, want)
		}
		if got.String() != s {
			t.Errorf("%q does not round-trip: %q", s, got.String())
		}
	}
	for _, s := range []string{
		"", "home", "home:fm", "home:xx:wfl-1", "Home:fm:wfl-1",
		"home:ll:not-a-req", "home:fm:../../etc", "home:fm:a/b", "home:fm:",
	} {
		if _, valid := parseFleetJobID(s); valid {
			t.Errorf("%q parsed as a job id", s)
		}
	}
}

func TestFleetStatusVocabulary(t *testing.T) {
	cases := map[string]struct {
		status   string
		terminal bool
	}{
		"PENDING": {"queued", false}, "DISPATCHED": {"running", false},
		"CANCELLING": {"running", false}, "DONE": {"succeeded", true},
		"FAILED": {"failed", true}, "CANCELLED": {"canceled", true},
		"pending": {"queued", false}, "optimizing": {"running", false},
		"completed": {"succeeded", true}, "error": {"failed", true},
		"cancelled": {"canceled", true},
		// Never terminal on a word nobody mapped: a poller told "done" stops.
		"PAUSED": {"running", false}, "": {"running", false},
	}
	for native, want := range cases {
		s, term := fleetStatus(native)
		if s != want.status || term != want.terminal {
			t.Errorf("%q = %s,%v want %s,%v", native, s, term, want.status, want.terminal)
		}
	}
}

func TestDetectFleetFormat(t *testing.T) {
	cases := map[string]string{
		"name: x\ninputs: {}\nops:\n  - id: a\n":                         "lumilake",
		"apiVersion: flowmesh/v1\nkind: Workflow\nspec:\n  stages: []\n": "flowmesh",
		"spec:\n  taskType: python\n":                                    "flowmesh",
		"just: a map\n":                                                  "",
		"not yaml: [":                                                    "",
	}
	for wf, want := range cases {
		if got := detectFleetFormat(wf); got != want {
			t.Errorf("%q = %q want %q", wf, got, want)
		}
	}
}

// ── integration: MySQL + a fake federator ───────────────────────────────────

type fakeUpstream struct {
	mu    sync.Mutex
	calls []string
	auth  []string
	body  []string
}

func (f *fakeUpstream) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.body = append(f.body, string(b))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	p := r.URL.Path
	switch {
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows":
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-abc123","status":"PENDING","tasks":[{"task_id":"tsk-1"}]}`))
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows/validate":
		_, _ = w.Write([]byte(`{"valid":true}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/workflows/wfl-abc123":
		// The shape FlowMesh v0.1.10 returns: task ids, not task objects.
		_, _ = w.Write([]byte(`{"workflow_id":"wfl-abc123","task_ids":["tsk-0","tsk-1"],"status":"DONE",` +
			`"dispatched_tasks":[],"completed_tasks":["tsk-0","tsk-1"],"failed_tasks":[],"cancelled_tasks":[]}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/tasks" && r.URL.Query().Get("workflow_id") == "wfl-abc123":
		_, _ = w.Write([]byte(`[{"task_id":"tsk-0","task":{"metadata":{"name":"two-stage:prep"}}},` +
			`{"task_id":"tsk-1","task":{"metadata":{"name":"two-stage:score"}}}]`))
	case r.Method == "GET" && p == "/fm/home/api/v1/results/tsk-0":
		_, _ = w.Write([]byte(`{"task_type":"echo","items":[{"output":"x"}]}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/results/tsk-1":
		_, _ = w.Write([]byte(`{"task_type":"python","value":{"ok":1},"metrics":{"score":0.75}}`))
	case r.Method == "GET" && p == "/fm/home/api/v1/workflows/wfl-abc123/logs":
		_, _ = w.Write([]byte(`[{"message":"hello"}]`))
	case r.Method == "POST" && p == "/fm/home/api/v1/workflows/wfl-abc123/cancel":
		_, _ = w.Write([]byte(`{"ok":true}`))
	case r.Method == "POST" && p == "/ll/office/api/v1/jobs":
		_, _ = w.Write([]byte(`{"ok":true,"data":{"job_id":"req-zzzzzz999999","status":"pending"}}`))
	case r.Method == "GET" && p == "/ll/office/api/v1/jobs/req-zzzzzz999999":
		_, _ = w.Write([]byte(`{"ok":true,"data":{"status":"running"}}`))
	case r.Method == "GET" && p == "/ll/office/api/v1/jobs/req-zzzzzz999999/progress":
		_, _ = w.Write([]byte(`{"ok":true,"data":{"progress":{"execution":0.5}}}`))
	case r.Method == "GET" && p == "/ll/office/api/v1/jobs/req-zzzzzz999999/result":
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"ok":false,"detail":"not ready"}`))
	case r.Method == "GET" && p == "/ll/office/api/v1/jobs/req-zzzzzz999999/workflows":
		_, _ = w.Write([]byte(`{"ok":true,"data":{"workflows":[{"workflow_id":"wfl-x1","status":"DONE"}]}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"no route in fake"}`))
	}
}

func fleetTestSetup(t *testing.T) (*fakeUpstream, string, string) {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping fleet-jobs integration test")
	}
	db := setupClaudePoolTestDB(t)
	if config.G == nil {
		config.G = &config.Config{}
		t.Cleanup(func() { config.G = nil })
	}
	if common.Keys.Active() == nil {
		cfg := &config.Config{}
		cfg.Signing.KeyDir = t.TempDir()
		if err := common.LoadKeys(cfg); err != nil {
			t.Fatalf("keys: %v", err)
		}
	}
	t.Setenv("IDENTITY_GRANT_KEY", strings.Repeat("ab", 32))
	t.Setenv(computeStatusTokenEnv, "svc-read-token")
	fake := &fakeUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	t.Setenv("FLEET_BASE_URL", srv.URL)

	owner := claudePoolTestUser(t, db, "fleet")
	other := claudePoolTestUser(t, db, "fleetx")
	t.Cleanup(func() {
		db.Where("user_sub IN ?", []string{owner, other}).Delete(&models.MeFleetJob{})
		db.Where("user_sub IN ?", []string{owner, other}).Delete(&models.AppSecret{})
		db.Where("user_id IN ?", []string{owner, other}).Delete(&models.Token{})
	})
	return fake, fleetTestPAT(t, owner), fleetTestPAT(t, other)
}

func fleetTestPAT(t *testing.T, sub string) string {
	t.Helper()
	tok, _, err := mintPATForUser(sub, "fleet-test", []string{"*"}, nil, "native")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func fleetRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/me/fleet/jobs", MeFleetJobRun)
	r.GET("/api/v1/me/fleet/jobs", MeFleetJobList)
	r.GET("/api/v1/me/fleet/jobs/:id", MeFleetJobGet)
	r.POST("/api/v1/me/fleet/jobs/:id/cancel", MeFleetJobCancel)
	return r
}

func fleetServe(t *testing.T, h http.Handler, method, path, body, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func fleetCallAPI(t *testing.T, method, path, body, tok string) (int, map[string]any) {
	t.Helper()
	w := fleetServe(t, fleetRouter(), method, path, body, tok)
	var env map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	// Every response, success or failure, is the ret_code envelope the SPA
	// and SDK parse.
	if _, has := env["ret_code"]; !has {
		t.Errorf("%s %s: response is not the ret_code envelope: %s", method, path, w.Body.String())
	}
	data, _ := env["data"].(map[string]any)
	if data == nil {
		data = env
	}
	return w.Code, data
}

const fmGraph = "apiVersion: flowmesh/v1\\nkind: Workflow\\nspec:\\n  stages: []\\n"

func TestFleetFlowMeshRunGetResultLogsCancel(t *testing.T) {
	fake, owner, other := fleetTestSetup(t)

	code, job := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs",
		`{"workflow":"`+fmGraph+`","labels":{"study":"s1","experiment":"e1"}}`, owner)
	if code != http.StatusAccepted {
		t.Fatalf("run = %d %v", code, job)
	}
	if job["id"] != "home:fm:wfl-abc123" || job["status"] != "queued" || job["format"] != "flowmesh" {
		t.Fatalf("run body = %v", job)
	}
	// Ran as the caller: a bridge JWT, never the Lumilake service token.
	if a := fake.auth[0]; !strings.HasPrefix(a, "Bearer ey") {
		t.Errorf("FlowMesh write went upstream with %q, want a bridge JWT", a)
	}

	code, st := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123", "", owner)
	if code != 200 || st["status"] != "succeeded" || st["native_status"] != "DONE" || st["terminal"] != true {
		t.Fatalf("status = %d %v", code, st)
	}

	code, res := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123?view=result", "", owner)
	metrics, _ := res["metrics"].(map[string]any)
	outputs, _ := res["outputs"].([]any)
	if code != 200 || metrics["score"] != 0.75 || len(outputs) != 2 {
		t.Fatalf("result = %d %v", code, res)
	}
	if last, _ := outputs[1].(map[string]any); last["task_id"] != "tsk-1" || last["name"] != "score" {
		t.Errorf("python output = %v, want task tsk-1 named score", outputs[1])
	}

	code, logs := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123?view=logs", "", owner)
	if code != 200 || logs["logs"] == nil {
		t.Fatalf("logs = %d %v", code, logs)
	}

	// Another user: 404, not 403 — no oracle for job ids.
	if code, _ := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123", "", other); code != 404 {
		t.Errorf("other user read = %d, want 404", code)
	}
	if code, _ := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123/cancel", "", other); code != 404 {
		t.Errorf("other user cancel = %d, want 404", code)
	}

	code, list := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs?study=s1", "", owner)
	jobs, _ := list["jobs"].([]any)
	if code != 200 || len(jobs) != 1 {
		t.Fatalf("list = %d %v", code, list)
	}
	if j := jobs[0].(map[string]any); j["status"] != "succeeded" {
		t.Errorf("list did not pick up the refreshed status: %v", j)
	}
	if _, others := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs", "", other); len(others["jobs"].([]any)) != 0 {
		t.Errorf("another user's list shows this job")
	}

	code, cancel := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs/home:fm:wfl-abc123/cancel", "", owner)
	if code != 200 || cancel["cancel_requested"] != true {
		t.Fatalf("cancel = %d %v", code, cancel)
	}
}

func TestFleetFlowMeshDryRunRecordsNothing(t *testing.T) {
	fake, owner, _ := fleetTestSetup(t)
	code, out := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs",
		`{"workflow":"`+fmGraph+`","dry_run":true}`, owner)
	if code != 200 || out["valid"] != true {
		t.Fatalf("dry run = %d %v", code, out)
	}
	if fake.calls[0] != "POST /fm/home/api/v1/workflows/validate" {
		t.Errorf("dry run called %v", fake.calls)
	}
	if _, list := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs", "", owner); len(list["jobs"].([]any)) != 0 {
		t.Error("a dry run was recorded as a job")
	}
}

func TestFleetLumilakeRunStatusResultTrace(t *testing.T) {
	fake, owner, _ := fleetTestSetup(t)
	code, job := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs",
		`{"workflow":"name: w\ninputs: {}\nops: []\n","site":"office","inputs":{"x":["1"]},"hardware":{"gpu_memory":"16Gi"}}`,
		owner)
	if code != http.StatusAccepted || job["id"] != "office:ll:req-zzzzzz999999" {
		t.Fatalf("run = %d %v", code, job)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(fake.body[0]), &sent)
	if sent["hardware"] == nil {
		t.Error("hardware must be sent at REQUEST level")
	}
	item := sent["data"].([]any)[0].(map[string]any)
	if item["hardware"] != nil || item["output_location"] == nil {
		t.Errorf("data[0] = %v", item)
	}
	// Per user: Lumilake gives an S3 prefix to the first principal to write it.
	if loc, _ := item["output_location"].(map[string]any); loc["prefix"] != fleetOutputPrefix(owner) {
		t.Errorf("output_location = %v, want the caller's own prefix", item["output_location"])
	}
	// Written as the caller (their compute PAT), not the service read token.
	if a := fake.auth[0]; a == "Bearer svc-read-token" || !strings.HasPrefix(a, "Bearer lm_pat_") {
		t.Errorf("Lumilake write went upstream with %q", a)
	}

	code, st := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/office:ll:req-zzzzzz999999", "", owner)
	if code != 200 || st["status"] != "running" || st["progress"] == nil {
		t.Fatalf("status = %d %v", code, st)
	}
	if code, _ := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/office:ll:req-zzzzzz999999?view=result", "", owner); code != 409 {
		t.Errorf("unfinished result = %d, want 409", code)
	}
	code, tr := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/office:ll:req-zzzzzz999999?view=trace", "", owner)
	wfs, _ := tr["workflows"].([]any)
	if code != 200 || len(wfs) != 1 || wfs[0].(map[string]any)["id"] != "office:fm:wfl-x1" {
		t.Fatalf("trace = %d %v", code, tr)
	}
	if code, _ := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/office:ll:req-zzzzzz999999?view=logs", "", owner); code != 400 {
		t.Errorf("logs on a Lumilake job = %d, want 400 naming trace", code)
	}
	// The canvas status route follows fleet-run Lumilake jobs too.
	if !callerOwnsComputeJob(fleetUserSub(t, owner), "office", "req-zzzzzz999999") {
		t.Error("callerOwnsComputeJob does not recognise a fleet-run job")
	}
}

func TestFleetRunRejectsBadInput(t *testing.T) {
	_, owner, _ := fleetTestSetup(t)
	for body, want := range map[string]int{
		`{"workflow":""}`:                                         400,
		`{"workflow":"just: a map\n"}`:                            400,
		`{"workflow":"ops: []\n","site":"../etc"}`:                400,
		`{"workflow":"ops: []\n","format":"docker"}`:              400,
		`{"workflow":"ops: []\n","labels":{"study":"has space"}}`: 400,
	} {
		if code, out := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs", body, owner); code != want {
			t.Errorf("%s = %d %v, want %d", body, code, out, want)
		}
	}
	if code, _ := fleetCallAPI(t, "GET", "/api/v1/me/fleet/jobs/home:zz:1", "", owner); code != 400 {
		t.Errorf("malformed id = %d, want 400", code)
	}
}

func fleetUserSub(t *testing.T, tok string) string {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = r
	sub, ok := currentUserID(c)
	if !ok {
		t.Fatal("test PAT does not resolve")
	}
	return sub
}

// Lumilake 422s both `inputs: null` and `inputs: {}` ("inputs is required").
// With no inputs in the request, the workflow's own declared `inputs:` are
// sent — found on production, where a no-inputs dry run failed on all sites.
func TestFleetLumilakeRunWithoutInputsSendsTheDeclaredOnes(t *testing.T) {
	fake, owner, _ := fleetTestSetup(t)
	code, out := fleetCallAPI(t, "POST", "/api/v1/me/fleet/jobs",
		`{"workflow":"name: w\ninputs:\n  Stock: [NVDA]\nops: []\n","site":"office"}`, owner)
	if code != http.StatusAccepted {
		t.Fatalf("run = %d %v", code, out)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(fake.body[0]), &sent)
	item := sent["data"].([]any)[0].(map[string]any)
	inputs, _ := item["inputs"].(map[string]any)
	if stock, _ := inputs["Stock"].([]any); len(stock) != 1 || stock[0] != "NVDA" {
		t.Fatalf("inputs sent as %#v, want the declared {Stock: [NVDA]}", item["inputs"])
	}
}

func TestDeclaredWorkflowInputs(t *testing.T) {
	if got := declaredWorkflowInputs("ops: []\n"); got == nil || len(got) != 0 {
		t.Errorf("no inputs block = %#v, want {}", got)
	}
	if got := declaredWorkflowInputs("not: [yaml"); got == nil {
		t.Error("unparseable workflow must still give a non-nil map")
	}
	if got := declaredWorkflowInputs("inputs:\n  A: [x]\n"); len(got) != 1 {
		t.Errorf("declared = %#v", got)
	}
}

func TestFleetWorkflowTaskIDs(t *testing.T) {
	for _, tc := range []struct {
		name string
		wf   map[string]any
		want []string
	}{
		{"task_ids", map[string]any{"task_ids": []any{"tsk-a", "tsk-b"}}, []string{"tsk-a", "tsk-b"}},
		{"tasks", map[string]any{"tasks": []any{map[string]any{"task_id": "tsk-a"}}}, []string{"tsk-a"}},
		{"neither", map[string]any{"status": "DONE"}, nil},
	} {
		if got := fleetWorkflowTaskIDs(tc.wf); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFleetOutputPrefixIsPerUser(t *testing.T) {
	a, b := fleetOutputPrefix("u-a"), fleetOutputPrefix("u-b")
	if a == b || a != "fleet-jobs/u-a/" {
		t.Errorf("prefixes %q %q: want distinct, per-user, slash-terminated", a, b)
	}
}
