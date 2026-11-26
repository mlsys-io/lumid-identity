package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const testSimImage = "ghcr.io/mlsys-io/hello-mlsys-agent@sha256:" +
	"1111111111111111111111111111111111111111111111111111111111111111"

func decodeInputs(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", s, err)
	}
	return m
}

func TestMeasureKeyIsTheContentNotTheSpelling(t *testing.T) {
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	a := `{"image":"` + testSimImage + `","job":"evaluate","payload":{"task":"9.2","seeds":[42],"candidates":[{"id":"c32","x":1}]}}`
	b := `{"payload":{"candidates":[{"x":1,"id":"c32"}],"seeds":[42],"task":"9.2"},"job":"evaluate","site":"home","timeout_s":900,"image":"` + testSimImage + `"}`
	pa, err := mlsysSimulatorPlan(decodeInputs(t, a))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := mlsysSimulatorPlan(decodeInputs(t, b))
	if err != nil {
		t.Fatal(err)
	}
	ka, kb := measureKey("mlsys-simulator", pa.version, pa.material), measureKey("mlsys-simulator", pb.version, pb.material)
	if ka != kb {
		t.Fatalf("key order / site / timeout changed the key: %s vs %s", ka, kb)
	}
	// A different seed is a different measurement.
	c := strings.Replace(a, "[42]", "[43]", 1)
	pc, _ := mlsysSimulatorPlan(decodeInputs(t, c))
	if measureKey("mlsys-simulator", pc.version, pc.material) == ka {
		t.Fatal("a different seed produced the same key")
	}
	// A different image (the instrument's version) is a different measurement.
	other := strings.Replace(testSimImage, "1111", "2222", 1)
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage+",vu="+other)
	pd, err := mlsysSimulatorPlan(decodeInputs(t, strings.Replace(a, testSimImage, other, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if measureKey("mlsys-simulator", pd.version, pd.material) == ka {
		t.Fatal("a different image produced the same key")
	}
	if pa.site != "office" || pb.site != "home" {
		t.Errorf("sites = %q, %q; want the office default and the explicit home", pa.site, pb.site)
	}
}

func TestMeasureNumbersKeepTheirText(t *testing.T) {
	// 42 and 42.0 are the same float but not the same input text: canonical
	// JSON must not reformat (UseNumber), or two spellings collide silently.
	s, err := canonicalJSON(decodeInputs(t, `{"b":42,"a":0.10}`))
	if err != nil || s != `{"a":0.10,"b":42}` {
		t.Fatalf("canonical = %q (%v)", s, err)
	}
}

func TestMlsysPlanRefusesWhatIsNotTheInstrument(t *testing.T) {
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	for name, in := range map[string]string{
		"unpinned image": `{"image":"ghcr.io/mlsys-io/hello-mlsys-agent:latest","job":"evaluate","payload":{"a":1}}`,
		"other job":      `{"image":"` + testSimImage + `","job":"sandbox","payload":{"a":1}}`,
		"empty payload":  `{"image":"` + testSimImage + `","job":"evaluate","payload":{}}`,
		"bad site":       `{"image":"` + testSimImage + `","job":"evaluate","payload":{"a":1},"site":"../x"}`,
	} {
		if _, err := mlsysSimulatorPlan(decodeInputs(t, in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMlsysWorkflowIsTheAppsGraph(t *testing.T) {
	wf, err := mlsysWorkflow(testSimImage, "vt", "evaluate", map[string]any{"task": "9.2", "note": "it's \"quoted\"\n✓"}, "measure-x", 600)
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]any
	if err := json.Unmarshal([]byte(wf), &g); err != nil {
		t.Fatalf("graph is not JSON (so not YAML either): %v", err)
	}
	stage := g["spec"].(map[string]any)["stages"].([]any)[0].(map[string]any)["spec"].(map[string]any)
	if stage["image"] != testSimImage || stage["network"] != "none" || stage["taskType"] != "python" ||
		stage["entrypoint"] != "main" {
		t.Fatalf("stage = %v", stage)
	}
	code := stage["code"].(string)
	if !strings.Contains(code, "from mlab.jobs import run") || !strings.Contains(code, `run("evaluate", PAYLOAD)`) {
		t.Fatalf("code = %s", code)
	}
	// The payload literal must be valid Python and decode back to the JSON.
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	cmd := exec.Command(py, "-c", "import json,sys\nns={}\nexec(sys.stdin.read().split('def main')[0], ns)\n"+
		"print(json.loads(ns['PAYLOAD'])['note'])")
	cmd.Stdin = strings.NewReader(code)
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "it's \"quoted\"\n✓" {
		t.Fatalf("python read %q (%v)", out, err)
	}
}

// ── The full flow against the fake fleet (needs TEST_MYSQL_DSN) ─────────

func measureRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/me/measure", MeMeasure)
	r.GET("/api/v1/me/measure/instruments", MeMeasureInstruments)
	r.GET("/api/v1/me/measure/:key", MeMeasureGet)
	return r
}

func measureCall(t *testing.T, method, path, body, tok string) (int, map[string]any) {
	t.Helper()
	w := fleetServe(t, measureRouter(), method, path, body, tok)
	var env map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	data, _ := env["data"].(map[string]any)
	if data == nil {
		data = map[string]any{"_message": env["message"]}
	}
	return w.Code, data
}

func measureBodyFor(payload string) string {
	var b bytes.Buffer
	b.WriteString(`{"instrument":"mlsys-simulator","app":"mlsys-research","inputs":{"image":"` + testSimImage +
		`","job":"evaluate","site":"home","payload":` + payload + `}}`)
	return b.String()
}

func measureCleanup(t *testing.T, subs ...string) {
	t.Cleanup(func() {
		common.DB.Where("executor_sub IN ?", subs).Delete(&models.MeasureResult{})
		common.DB.Where("user_sub IN ?", subs).Delete(&models.MeasureRequest{})
	})
}

func subOf(t *testing.T, tok string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = r
	sub, ok := currentUserID(c)
	if !ok {
		t.Fatal("token did not resolve")
	}
	return sub
}

func TestMeasureRunsOnceAndServesEveryoneAfter(t *testing.T) {
	fake, owner, other := fleetTestSetup(t)
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	measureCleanup(t, subOf(t, owner), subOf(t, other))
	payload := `{"task":"9.2","seeds":[42],"candidates":[{"id":"c32-once"}]}`

	code, first := measureCall(t, "POST", "/api/v1/me/measure", measureBodyFor(payload), owner)
	if code != http.StatusAccepted || first["status"] != "running" || first["executor_ref"] != "home:fm:wfl-abc123" {
		t.Fatalf("first = %d %v", code, first)
	}
	posts := 0
	for i, call := range fake.calls {
		if call == "POST /fm/home/api/v1/workflows" {
			posts++
			if !strings.Contains(fake.body[i], testSimImage) || !strings.Contains(fake.body[i], `"network":"none"`) {
				t.Errorf("submitted graph lacks the pinned image / no-network: %s", fake.body[i])
			}
		}
	}
	if posts != 1 {
		t.Fatalf("upstream submits = %d, want 1", posts)
	}
	key := first["key"].(string)

	// Reading it advances it: the fake job is DONE and tsk-1 carries a value.
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+key, "", owner)
	res, _ := got["result"].(map[string]any)
	if code != 200 || got["status"] != "succeeded" || res == nil || res["reused"] != false {
		t.Fatalf("get = %d %v", code, got)
	}
	if v, _ := res["value"].(map[string]any); v["ok"] == nil {
		t.Fatalf("value = %v", res["value"])
	}
	if res["measured_on"] != "mlsys-simulator vt" {
		t.Errorf("measured_on = %v", res["measured_on"])
	}

	// Another user, same content: served from the row, no new job, and
	// nothing that names the first runner's job.
	code, again := measureCall(t, "POST", "/api/v1/me/measure", measureBodyFor(
		`{"candidates":[{"id":"c32-once"}],"seeds":[42],"task":"9.2"}`), other)
	ares, _ := again["result"].(map[string]any)
	if code != 200 || again["key"] != key || again["status"] != "succeeded" || ares["reused"] != true {
		t.Fatalf("second user = %d %v", code, again)
	}
	if _, leaked := again["executor_ref"]; leaked {
		t.Errorf("the second user sees the first runner's job id")
	}
	posts = 0
	for _, call := range fake.calls {
		if call == "POST /fm/home/api/v1/workflows" {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("a cache hit submitted again (%d submits)", posts)
	}
	var row models.MeasureResult
	common.DB.First(&row, "mkey = ?", key)
	if row.Hits != 1 {
		t.Errorf("hits = %d, want 1", row.Hits)
	}
}

func TestMeasureAFailedRunSaysWhyAndIsRetried(t *testing.T) {
	fake, owner, _ := fleetTestSetup(t)
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	measureCleanup(t, subOf(t, owner))
	// "will-fail" in the body routes the fake to a FAILED workflow.
	body := measureBodyFor(`{"task":"will-fail","seeds":[1]}`)
	code, first := measureCall(t, "POST", "/api/v1/me/measure", body, owner)
	if code != http.StatusAccepted {
		t.Fatalf("first = %d %v", code, first)
	}
	code, got := measureCall(t, "GET", "/api/v1/me/measure/"+first["key"].(string), "", owner)
	if code != 200 || got["status"] != "failed" || !strings.Contains(got["error"].(string), "ValueError: boom") {
		t.Fatalf("failed get = %d %v", code, got)
	}
	before := len(fake.calls)
	code, retry := measureCall(t, "POST", "/api/v1/me/measure", body, owner)
	if code != http.StatusAccepted || retry["status"] != "running" {
		t.Fatalf("retry = %d %v", code, retry)
	}
	if !strings.Contains(strings.Join(fake.calls[before:], ","), "POST /fm/home/api/v1/workflows") {
		t.Fatal("a failed measurement was not resubmitted")
	}
}

func TestMeasureRunningCapSaysNotMeasured(t *testing.T) {
	_, owner, _ := fleetTestSetup(t)
	t.Setenv("MEASURE_MLSYS_IMAGES", "vt="+testSimImage)
	t.Setenv("MEASURE_RUNNING_CAP", "1")
	measureCleanup(t, subOf(t, owner))
	if code, _ := measureCall(t, "POST", "/api/v1/me/measure", measureBodyFor(`{"task":"9.1","seeds":[7]}`), owner); code != http.StatusAccepted {
		t.Fatalf("first = %d", code)
	}
	code, refused := measureCall(t, "POST", "/api/v1/me/measure", measureBodyFor(`{"task":"9.1","seeds":[8]}`), owner)
	if code != http.StatusTooManyRequests || refused["status"] != "not_measured" || refused["retry_after"] == nil {
		t.Fatalf("over cap = %d %v", code, refused)
	}
}

func TestMeasureUnknownKeyAndInstrument(t *testing.T) {
	_, owner, _ := fleetTestSetup(t)
	if code, _ := measureCall(t, "GET", "/api/v1/me/measure/"+strings.Repeat("a", 64), "", owner); code != 404 {
		t.Errorf("unknown key = %d", code)
	}
	if code, _ := measureCall(t, "GET", "/api/v1/me/measure/not-a-key", "", owner); code != 404 {
		t.Errorf("malformed key = %d", code)
	}
	if code, _ := measureCall(t, "POST", "/api/v1/me/measure", `{"instrument":"nope","inputs":{}}`, owner); code != 400 {
		t.Errorf("unknown instrument = %d", code)
	}
	code, list := measureCall(t, "GET", "/api/v1/me/measure/instruments", "", owner)
	if ins, _ := list["instruments"].([]any); code != 200 || len(ins) == 0 {
		t.Errorf("instruments = %d %v", code, list)
	}
}
