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
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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

// ── The model guard ───────────────────────────────────────────────────────────
//
// A model name that resolves NOWHERE does not error. It abstains. mbb-ai declared
// `judge_model: gemma4`, the gateway had already retired Gemma-4 (upstream moved
// Gemma-4 -> Qwen3.8-27B -> DeepSeek-V4-Flash), and the seat simply never scored:
// a "median of 3" panel quietly became a panel of one, and an n=300 verdict was
// published off an instrument nobody had checked.
//
// Two namespaces exist and they are NOT interchangeable. The gateway serves mesh
// aliases and rejects HuggingFace ids; Lumilake loads HuggingFace ids into vLLM and
// rejects aliases ("not a valid model identifier on huggingface.co"). So each name
// is validated against the namespace it declares, never against both.
//
// Measured 2026-09-13: six distinct model-identity failures in one day, every one
// of them found by burning a run rather than at define-time.
var (
	gatewayModelsMu   sync.Mutex
	gatewayModelsAt   time.Time
	gatewayModelsList map[string]bool
)

// gatewayModels returns the set of model ids the gateway serves, or ok=false when
// the list could not be fetched. Cached for a minute: define-time is interactive
// and the served set changes on deploys, not on requests.
func gatewayModels() (map[string]bool, bool) {
	gatewayModelsMu.Lock()
	defer gatewayModelsMu.Unlock()
	if gatewayModelsList != nil && time.Since(gatewayModelsAt) < time.Minute {
		return gatewayModelsList, true
	}
	// LUMID_LLM_GATEWAY_URL is the name the scheduler's _model_warnings reads;
	// accepting both keeps one variable from configuring half the estate.
	// The in-cluster Service is lumid-llm:8088 — :8080 was wrong and the guard
	// duly reported "could not reach the LLM gateway" instead of passing
	// silently, which is the only reason the mistake was visible at all.
	base := strings.TrimRight(os.Getenv("LUMID_LLM_URL"), "/")
	if base == "" {
		base = strings.TrimRight(os.Getenv("LUMID_LLM_GATEWAY_URL"), "/")
	}
	if base == "" {
		base = "http://lumid-llm:8088"
	}
	req, err := http.NewRequest("GET", base+"/v1/models", nil)
	if err != nil {
		return nil, false
	}
	if tok := os.Getenv("LUMID_LLM_GATEWAY_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || len(out.Data) == 0 {
		return nil, false
	}
	set := make(map[string]bool, len(out.Data))
	for _, m := range out.Data {
		set[strings.ToLower(strings.TrimSpace(m.ID))] = true
	}
	gatewayModelsList, gatewayModelsAt = set, time.Now()
	return set, true
}

// armModelNames pulls every declared model out of one arm: the singular fields and
// each seat of a judge panel. The panel is the half that actually broke — a missing
// seat changes the instrument without changing any number on screen.
// Arm keys are APP-SPECIFIC — mbb-consultant uses analyst_model/judge_model/
// judge_panel, quant-research names no models at all — so there is no platform
// contract to check against. The `*_model` / `*_panel` suffix convention is the
// same heuristic the scheduler applies (_model_warnings in me_intent_picker.py);
// matching it exactly matters more than being clever, because two guards that
// disagree about what counts as a model is how a definition passes one reader
// and fails the other.
func armModelNames(a map[string]any) []string {
	var out []string
	for k, v := range a {
		if !strings.HasSuffix(k, "_model") && !strings.HasSuffix(k, "_panel") && k != "model" {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out = append(out, strings.TrimSpace(t))
			}
		case []any:
			for _, seat := range t {
				if s, _ := seat.(string); strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
		}
	}
	sort.Strings(out) // map iteration is random; a stable message is testable
	return out
}

// validateExperimentModels returns hard problems and soft warnings.
//
// A name the gateway does not serve is a PROBLEM: it is the gemma4 shape and it
// silently produces a smaller panel. An unreachable gateway is a WARNING: refusing
// to define an experiment because a sidecar is down would be worse than the bug,
// but pretending the check ran would be worse still — so it is reported.
func validateExperimentModels(b *experimentWriteBody) (problems []string, warnings []string) {
	// Everything below is ADVISORY. The scheduler's _model_warnings reached the
	// same conclusion first and for a stated reason: arm keys are app-specific,
	// so this is a heuristic, and a heuristic must not be able to refuse a
	// legitimate definition. What identity adds is WHERE the warning lands —
	// back in the caller's 202 at define time, instead of only in a scheduler
	// log nobody reads until the run is already wrong.
	var names []string
	for _, a := range b.Arms {
		names = append(names, armModelNames(a)...)
	}
	if len(names) == 0 {
		return nil, nil
	}
	var gatewayNames []string
	for _, n := range names {
		if strings.HasPrefix(strings.ToLower(n), "lumilake:") {
			// lumilake:<site>:<hf-id>. SplitN(3) because an HF id has no colon
			// but does have slashes.
			parts := strings.SplitN(n, ":", 3)
			if len(parts) != 3 || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
				warnings = append(warnings, "`"+n+"` is not a valid Lumilake model: expected lumilake:<site>:<huggingface-id>")
			} else if !strings.Contains(parts[2], "/") {
				warnings = append(warnings, "`"+n+"` does not look like a HuggingFace id (expected <org>/<model>); the gateway's mesh aliases are rejected by vLLM")
			}
			continue
		}
		gatewayNames = append(gatewayNames, n)
	}
	if len(gatewayNames) == 0 {
		return problems, warnings
	}
	known, ok := gatewayModels()
	if !ok {
		return problems, append(warnings,
			"could not reach the LLM gateway, so model names were NOT checked; a name it does not serve will abstain silently rather than error")
	}
	for _, n := range gatewayNames {
		if !known[strings.ToLower(n)] {
			warnings = append(warnings, "the gateway does not serve `"+n+
				"` — it would not error, it would ABSTAIN, silently shrinking the panel (this is the gemma4 failure)")
		}
	}
	return problems, warnings
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
	problems := validateExperimentShape(&body)
	_, modelWarnings := validateExperimentModels(&body)
	if len(problems) > 0 {
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
		"data": gin.H{"intent_id": id, "app": app, "experiment": body.ID, "status": "pending",
			// Non-empty when a guard could not run. Silence here means the
			// check ran and passed; it never means "no check exists".
			"warnings": modelWarnings},
	})
}
