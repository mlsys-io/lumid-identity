package handler

// Experiment WRITE path — the half that did not exist.
//
// Until now nothing anywhere could create or edit an experiment: there were zero
// write endpoints under /me/*experiment*, and the only writer was the machine-only
// internal.POST /app-experiments bridge that a finished cycle self-reports through.
// Defining a metric or a case scope meant hand-editing .xpcloud.yaml AND
// .manifest.json, app_push, then per-tenant propagation — which is how
// quant-research shipped `real_tape_rate` against rows that only ever carried
// `real_tape` and reported n=0 over 19 real runs.
//
// WHY AN INTENT AND NOT A DIRECT WRITE. Identity mounts no tenant volume (that is
// the whole reason materialiseTenantApp exists), so it physically cannot edit the
// caller's bundle. The write therefore goes the way `install` already goes: queue
// an intent, let the scheduler — which holds the PVC — apply it.
//
// WHY OWNERSHIP IS NOT CHECKED HERE. resolveOwnedAppDir looks for the tenant dir on
// the LOCAL disk, which on identity never exists; it would fall through to
// "shared, not yours" and 403 every legitimate write. The authoritative check lives
// on the scheduler — _installed_app_dir(tenant_home, app), the same one that
// produces "app 'X' not installed for this user" — so this handler validates SHAPE
// and lets the scheduler own INSTALLATION, exactly as run_loop does.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// experimentMetric — the declared metric. `name` is the key evaluate() aggregates
// out of each result row's metrics{}, so it must match what the loop's command
// actually emits; a mismatch is silent and reports n=0 forever.
type experimentMetric struct {
	Name           string `json:"name"`
	HigherIsBetter *bool  `json:"higher_is_better,omitempty"`
}

type experimentWriteBody struct {
	ID          string            `json:"id"`
	Loop        string            `json:"loop"`
	Kind        string            `json:"kind,omitempty"`
	Description string            `json:"description,omitempty"`
	Hypothesis  string            `json:"hypothesis,omitempty"`
	Metric      *experimentMetric `json:"metric"`
	DatasetID   string            `json:"dataset_id,omitempty"`
	Cases       []string          `json:"cases,omitempty"`
	Arms        []map[string]any  `json:"arms,omitempty"`
	Criteria    string            `json:"success_criteria,omitempty"`
	MinSamples  *int              `json:"min_samples,omitempty"`
	Baseline    map[string]any    `json:"baseline,omitempty"`
	Dispatch    map[string]any    `json:"dispatch,omitempty"`
}

// validateExperimentShape enforces the one rule that separates the two kinds of
// thing this platform runs:
//
//	workflow   = a loop. no metric, no scope.
//	experiment = a loop + a METRIC + a dataset/case SCOPE.
//
// Both halves are load-bearing and both have failed in production. Without a
// metric there is nothing to aggregate. Without a scope, min_samples counts over
// an undefined population — mbb-consultant's own spec records the cost: "19 early
// results were measured over whatever cases happened to be asked, which no
// threshold can interpret."
func validateExperimentShape(b *experimentWriteBody) []string {
	var problems []string
	if strings.TrimSpace(b.ID) == "" {
		problems = append(problems, "`id` is required")
	} else if !slugRe.MatchString(b.ID) || strings.ContainsAny(b.ID, "/\\") {
		problems = append(problems, "`id` must be a slug (letters, digits, - and _)")
	}
	if strings.TrimSpace(b.Loop) == "" {
		problems = append(problems,
			"`loop` is required — an experiment attached to no loop has nowhere to dispatch to")
	}
	if b.Metric == nil || strings.TrimSpace(b.Metric.Name) == "" {
		problems = append(problems,
			"`metric.name` is required: a loop WITHOUT a metric is a workflow, not an experiment")
	}
	if strings.TrimSpace(b.DatasetID) == "" && len(b.Cases) == 0 {
		problems = append(problems,
			"a scope is required: set `dataset_id` or `cases[]`, or min_samples counts over an undefined population")
	}
	for i, a := range b.Arms {
		if id, _ := a["id"].(string); strings.TrimSpace(id) == "" {
			problems = append(problems, "arms["+strconv.Itoa(i)+"].id missing")
		}
	}
	return problems
}

// MeAppExperimentUpsert — POST /me/apps/:app/experiments (create)
//
//	PATCH /me/apps/:app/experiments/:id (edit)
//
// Queues a `patch_experiment` intent; the scheduler edits the caller's own tenant
// bundle TEXTUALLY (never a yaml round-trip — the comments in those specs are the
// decision record) and mirrors into .manifest.json so spec_manifest_parity holds.
func MeAppExperimentUpsert(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) || strings.Contains(app, "/") {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	var body experimentWriteBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	// PATCH carries the id in the path; POST carries it in the body.
	if pid := c.Param("id"); pid != "" {
		body.ID = pid
	}
	if problems := validateExperimentShape(&body); len(problems) > 0 {
		fail(c, http.StatusUnprocessableEntity, 1422,
			"not a valid experiment: "+strings.Join(problems, "; "))
		return
	}

	payload := map[string]any{
		"app":        app,
		"experiment": body.ID,
		"loop":       body.Loop,
		"metric":     body.Metric,
	}
	for k, v := range map[string]any{
		"kind": body.Kind, "description": body.Description, "hypothesis": body.Hypothesis,
		"dataset_id": body.DatasetID, "success_criteria": body.Criteria,
	} {
		if s, _ := v.(string); s != "" {
			payload[k] = s
		}
	}
	if len(body.Cases) > 0 {
		payload["cases"] = body.Cases
	}
	if len(body.Arms) > 0 {
		payload["arms"] = body.Arms
	}
	if body.MinSamples != nil {
		payload["min_samples"] = *body.MinSamples
	}
	if len(body.Baseline) > 0 {
		payload["baseline"] = body.Baseline
	}
	if len(body.Dispatch) > 0 {
		payload["dispatch"] = body.Dispatch
	}

	id := writeIntent(c, "patch_experiment", userID, payload)
	if id == "" {
		return // writeIntent already wrote the error response
	}
	// 202 and no claim about the result. Identity queues; the scheduler applies.
	// Callers poll the intent (waitForIntent) exactly as they do for install.
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "experiment queued",
		"data": gin.H{"intent_id": id, "app": app, "experiment": body.ID, "status": "pending"},
	})
}
