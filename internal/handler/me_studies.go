package handler

import (
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// Studies — define a study and run its experiments in ONE call.
//
//	POST /me/agents/:agent/studies          define (create or replace)
//	POST /me/agents/:agent/studies?run=1    define, then run every experiment
//
// GLOSSARY.md (LumidOS): a STUDY compares EXPERIMENTS on one metric over one
// dataset; an experiment is one configured run of a workflow. This is the same
// entry experiments[] + arms[] has always declared — the handler maps a study
// onto experimentWriteBody and the patch_experiment intent, so every existing
// reader, the ledger and the Experiments panel see one shape.
//
// WHY ONE CALL. Today "run a comparison" is define_experiment, then
// add_experiment_arm once per arm, then make sure a loop is attached, then
// dispatch_experiment_arm once per arm — about eight steps across chat, HTTP and
// hand-edited YAML, each able to leave a half-built experiment behind. Here the
// definition and its runs travel in one intent (`run` in the payload), which the
// scheduler applies in order: separate intents written in the same second have
// no claim order, and a run queued before its definition is refused.
//
// VALIDATED AT DEFINE TIME, all problems at once (422 with `errors`), because
// every one of these has cost real runs before being noticed:
//   - the workflow must exist in the agent's spec;
//   - the metric must be the one that workflow reports (engine.metric), or an
//     experiment aggregates a key no row carries and reads n=0 forever;
//   - at least one experiment, ids unique slugs;
//   - min_samples counts runs PER EXPERIMENT and must be >= 1.
// A check that could not run (the spec is not readable from here) is returned
// as a warning naming it — silence always means "checked and passed".

type studyExperiment = map[string]any

type studyBody struct {
	ID          string            `json:"id"`
	Workflow    string            `json:"workflow"`
	Metric      *experimentMetric `json:"metric"`
	Hypothesis  string            `json:"hypothesis,omitempty"`
	Description string            `json:"description,omitempty"`
	DatasetID   string            `json:"dataset_id,omitempty"`
	Cases       []string          `json:"cases,omitempty"`
	Experiments []studyExperiment `json:"experiments"`
	MinSamples  *int              `json:"min_samples,omitempty"`
	Criteria    string            `json:"success_criteria,omitempty"`
	Baseline    map[string]any    `json:"baseline,omitempty"`
	Run         bool              `json:"run,omitempty"`
	Samples     int               `json:"samples,omitempty"`
	Args        map[string]any    `json:"args,omitempty"`
}

// studyWorkflow is what the define-time checks need to know about a loop.
type studyWorkflow struct {
	Name   string `yaml:"name"`
	Engine struct {
		Type       string `yaml:"type"`
		Metric     string `yaml:"metric"`
		Experiment expRef `yaml:"experiment"`
	} `yaml:"engine"`
}

// agentWorkflows reads the agent's loops from its spec, or ok=false when the
// spec cannot be read from here.
func agentWorkflows(userID, agent string) ([]studyWorkflow, bool) {
	dir := resolveAppDir(userID, agent)
	if dir == "" {
		return nil, false
	}
	path, found := ResolveSpecPath(dir)
	if !found {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var spec struct {
		Loops []studyWorkflow `yaml:"loops"`
	}
	if yaml.Unmarshal(b, &spec) != nil {
		return nil, false
	}
	return spec.Loops, true
}

// validateStudy returns (problems, warnings). Problems block the write.
func validateStudy(b *studyBody, workflows []studyWorkflow, specReadable bool) ([]string, []string) {
	var problems, warnings []string
	if len(b.Experiments) == 0 {
		problems = append(problems, "`experiments` is required: a study compares at least one experiment")
	}
	seen := map[string]bool{}
	for i, e := range b.Experiments {
		id, _ := e["id"].(string)
		switch {
		case strings.TrimSpace(id) == "":
			// validateExperimentShape reports this one.
		case !slugRe.MatchString(id) || strings.ContainsAny(id, "/\\"):
			problems = append(problems, "experiments["+strconv.Itoa(i)+"].id must be a slug")
		case seen[id]:
			problems = append(problems, "experiment id "+id+" is repeated")
		}
		seen[id] = true
	}
	if b.MinSamples != nil && *b.MinSamples < 1 {
		problems = append(problems, "`min_samples` counts runs per experiment and must be at least 1")
	}
	if b.Samples < 0 || b.Samples > 20 {
		problems = append(problems, "`samples` (runs per experiment) must be between 1 and 20")
	}
	if b.Workflow == "" {
		return problems, warnings // validateExperimentShape names the missing workflow
	}
	if !specReadable {
		warnings = append(warnings,
			"not checked: the agent's spec is not readable here, so the workflow and the metric it reports were not verified")
		return problems, warnings
	}
	var wf *studyWorkflow
	names := make([]string, 0, len(workflows))
	for i := range workflows {
		names = append(names, workflows[i].Name)
		if workflows[i].Name == b.Workflow {
			wf = &workflows[i]
		}
	}
	if wf == nil {
		sort.Strings(names)
		problems = append(problems, "workflow "+b.Workflow+" is not declared by this agent (declared: "+
			strings.Join(names, ", ")+")")
		return problems, warnings
	}
	if b.Metric != nil && wf.Engine.Metric != "" && wf.Engine.Metric != b.Metric.Name {
		problems = append(problems, "workflow "+b.Workflow+" reports `"+wf.Engine.Metric+
			"`, but this study measures `"+b.Metric.Name+"` — no run would ever carry it")
	}
	if wf.Engine.Type == "flowmesh" && wf.Engine.Metric == "" {
		warnings = append(warnings, "workflow "+b.Workflow+
			" names no engine.metric, so its runs record nothing for this study; set it to "+
			metricName(b))
	}
	return problems, warnings
}

func metricName(b *studyBody) string {
	if b.Metric == nil {
		return "the study's metric"
	}
	return b.Metric.Name
}

// MeStudyDefine — POST /me/agents/:agent/studies[?run=1].
func MeStudyDefine(c *gin.Context) {
	userID, authed := currentUserID(c)
	if !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	agent := c.Param("agent")
	if !slugRe.MatchString(agent) || strings.Contains(agent, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid agent")
		return
	}
	var b studyBody
	if err := c.ShouldBindJSON(&b); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if q := c.Query("run"); q == "1" || q == "true" {
		b.Run = true
	}

	exp := experimentWriteBody{
		ID: b.ID, Loop: b.Workflow, Kind: "arms", Description: b.Description,
		Hypothesis: b.Hypothesis, Metric: b.Metric, DatasetID: b.DatasetID, Cases: b.Cases,
		Arms: b.Experiments, Criteria: b.Criteria, MinSamples: b.MinSamples, Baseline: b.Baseline,
	}
	workflows, readable := agentWorkflows(userID, agent)
	for _, w := range workflows {
		if w.Name == b.Workflow {
			exp.computeGraph = computeGraphEngines[w.Engine.Type]
		}
	}
	problems := validateExperimentShape(&exp)
	// validateExperimentShape speaks the old words; say them in the new ones.
	for i, p := range problems {
		p = strings.ReplaceAll(p, "`loop`", "`workflow`")
		p = strings.ReplaceAll(p, "arms[", "experiments[")
		problems[i] = strings.ReplaceAll(p, "an experiment attached to no loop", "a study with no workflow")
	}
	more, warnings := validateStudy(&b, workflows, readable)
	problems = append(problems, more...)
	_, modelWarnings := validateExperimentModels(&exp)
	warnings = append(warnings, modelWarnings...)
	if len(problems) > 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ret_code": 1422, "message": "not a valid study: " + strings.Join(problems, "; "),
			"data": gin.H{"errors": problems, "warnings": warnings},
		})
		return
	}

	payload := map[string]any{
		"app": agent, "experiment": b.ID, "loop": b.Workflow, "metric": b.Metric,
		"kind": "arms", "arms": b.Experiments,
	}
	for k, v := range map[string]string{
		"description": b.Description, "hypothesis": b.Hypothesis,
		"dataset_id": b.DatasetID, "success_criteria": b.Criteria,
	} {
		if v != "" {
			payload[k] = v
		}
	}
	if len(b.Cases) > 0 {
		payload["cases"] = b.Cases
	}
	if b.MinSamples != nil {
		payload["min_samples"] = *b.MinSamples
	}
	if len(b.Baseline) > 0 {
		payload["baseline"] = b.Baseline
	}
	samples := b.Samples
	if samples == 0 {
		samples = 1
		if b.MinSamples != nil {
			samples = min(*b.MinSamples, 20)
		}
	}
	if b.Run {
		run := map[string]any{"samples": samples}
		if len(b.Args) > 0 {
			run["args"] = b.Args
		}
		payload["run"] = run
	}

	id := writeIntent(c, "patch_experiment", userID, payload)
	if id == "" {
		return // writeIntent already wrote the error response
	}
	experiments := make([]gin.H, 0, len(b.Experiments))
	for _, e := range b.Experiments {
		eid, _ := e["id"].(string)
		entry := gin.H{"id": eid}
		if b.Run {
			entry["runs_queued"] = samples
		}
		experiments = append(experiments, entry)
	}
	status := "defining"
	if b.Run {
		status = "defining_and_queuing"
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "study queued",
		"data": gin.H{
			"intent_id": id, "agent": agent, "study": b.ID, "workflow": b.Workflow,
			"status": status, "experiments": experiments, "warnings": warnings,
		},
	})
}
