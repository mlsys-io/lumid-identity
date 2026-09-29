package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func studyWFs() []studyWorkflow {
	var score, cmd studyWorkflow
	score.Name, score.Engine.Type, score.Engine.Metric = "score", "flowmesh", "accuracy"
	cmd.Name, cmd.Engine.Type = "free", "command"
	return []studyWorkflow{score, cmd}
}

func intp(i int) *int { return &i }

func TestValidateStudy(t *testing.T) {
	good := func() studyBody {
		return studyBody{
			ID: "s", Workflow: "score", Metric: &experimentMetric{Name: "accuracy"},
			Experiments: []studyExperiment{{"id": "cold"}, {"id": "warm"}},
		}
	}
	cases := map[string]struct {
		edit    func(*studyBody)
		problem string
	}{
		"ok":                  {func(*studyBody) {}, ""},
		"no experiments":      {func(b *studyBody) { b.Experiments = nil }, "at least one experiment"},
		"repeated id":         {func(b *studyBody) { b.Experiments = append(b.Experiments, studyExperiment{"id": "cold"}) }, "repeated"},
		"bad id":              {func(b *studyBody) { b.Experiments[0]["id"] = "a/b" }, "must be a slug"},
		"min_samples 0":       {func(b *studyBody) { b.MinSamples = intp(0) }, "per experiment"},
		"too many samples":    {func(b *studyBody) { b.Samples = 21 }, "between 1 and 20"},
		"unknown workflow":    {func(b *studyBody) { b.Workflow = "nope" }, "not declared by this agent (declared: free, score)"},
		"metric not reported": {func(b *studyBody) { b.Metric.Name = "f1" }, "reports `accuracy`"},
	}
	for name, tc := range cases {
		b := good()
		tc.edit(&b)
		problems, _ := validateStudy(&b, studyWFs(), true)
		joined := strings.Join(problems, "; ")
		if tc.problem == "" && len(problems) > 0 {
			t.Errorf("%s: unexpected problems %v", name, problems)
		}
		if tc.problem != "" && !strings.Contains(joined, tc.problem) {
			t.Errorf("%s: problems %q do not mention %q", name, joined, tc.problem)
		}
	}
}

func TestValidateStudySaysWhenItCouldNotCheck(t *testing.T) {
	b := studyBody{ID: "s", Workflow: "score", Metric: &experimentMetric{Name: "x"},
		Experiments: []studyExperiment{{"id": "a"}}}
	problems, warnings := validateStudy(&b, nil, false)
	if len(problems) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "not checked") {
		t.Fatalf("problems=%v warnings=%v", problems, warnings)
	}
}

func TestValidateStudyWarnsWhenAFleetWorkflowRecordsNothing(t *testing.T) {
	var wf studyWorkflow
	wf.Name, wf.Engine.Type = "g", "flowmesh"
	b := studyBody{ID: "s", Workflow: "g", Metric: &experimentMetric{Name: "score"},
		Experiments: []studyExperiment{{"id": "a"}}}
	_, warnings := validateStudy(&b, []studyWorkflow{wf}, true)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "set it to score") {
		t.Fatalf("warnings=%v", warnings)
	}
}

func TestStudyDefineAndRunQueuesOneIntent(t *testing.T) {
	_, owner, _ := fleetTestSetup(t) // MySQL + a real PAT; skips without TEST_MYSQL_DSN
	r := fleetRouter()
	r.POST("/api/v1/me/agents/:agent/studies", MeStudyDefine)
	body := `{"id":"judge_study","workflow":"score","metric":{"name":"accuracy"},
		"dataset_id":"cases_v1","min_samples":3,
		"experiments":[{"id":"cold"},{"id":"warm","env":{"TEMP":"0.7"}}]}`
	w := fleetServe(t, r, "POST", "/api/v1/me/agents/an-agent/studies?run=1", body, owner)
	if w.Code != 202 {
		t.Fatalf("define = %d %s", w.Code, w.Body.String())
	}
	var env struct {
		Data struct {
			IntentID    string           `json:"intent_id"`
			Experiments []map[string]any `json:"experiments"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	var intent models.MeAppIntent
	if err := common.DB.Where("id = ?", env.Data.IntentID).First(&intent).Error; err != nil {
		t.Fatalf("intent not written: %v", err)
	}
	t.Cleanup(func() { common.DB.Delete(&intent) })
	if intent.Action != "patch_experiment" {
		t.Errorf("action = %s", intent.Action)
	}
	var p map[string]any
	_ = json.Unmarshal([]byte(intent.Payload), &p)
	run, _ := p["run"].(map[string]any)
	if p["loop"] != "score" || p["kind"] != "arms" || run["samples"] != float64(3) {
		t.Errorf("payload = %v", p)
	}
	if arms, _ := p["arms"].([]any); len(arms) != 2 {
		t.Errorf("arms = %v", p["arms"])
	}
	if len(env.Data.Experiments) != 2 || env.Data.Experiments[0]["runs_queued"] != float64(3) {
		t.Errorf("response experiments = %v", env.Data.Experiments)
	}

	w = fleetServe(t, r, "POST", "/api/v1/me/agents/an-agent/studies",
		`{"id":"s","workflow":"score","metric":{"name":"a"},"dataset_id":"d","experiments":[]}`, owner)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "at least one experiment") {
		t.Errorf("empty study = %d %s", w.Code, w.Body.String())
	}
}
