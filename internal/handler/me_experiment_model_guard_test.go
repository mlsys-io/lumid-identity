package handler

// A model name that resolves nowhere ABSTAINS; it does not error.
//
// mbb-ai declared `judge_model: gemma4` after the gateway had retired Gemma-4.
// The seat never scored, a "median of 3" panel silently became a panel of one,
// and an n=300 verdict was published off an instrument nobody had checked. The
// number on screen looked exactly the same as a healthy one.
//
// These tests drive the real validateExperimentModels against a stub gateway.
// The panel cases matter most: a missing SEAT changes the instrument without
// changing any visible value.
//
// Findings are WARNINGS, not rejections. The scheduler's _model_warnings got
// there first and said why: arm keys are app-specific, so the *_model/*_panel
// convention is a heuristic, and a heuristic must never refuse a legitimate
// definition. What identity adds is delivering the warning to the CALLER at
// define time rather than to a scheduler log read after the run is wrong.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// stubGateway serves a /v1/models list and clears the package cache so each
// test sees its own gateway rather than the previous test's.
func stubGateway(t *testing.T, body string, status int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/models") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	prev := os.Getenv("LUMID_LLM_URL")
	os.Setenv("LUMID_LLM_URL", srv.URL)
	gatewayModelsMu.Lock()
	gatewayModelsList = nil
	gatewayModelsMu.Unlock()
	t.Cleanup(func() {
		srv.Close()
		os.Setenv("LUMID_LLM_URL", prev)
		gatewayModelsMu.Lock()
		gatewayModelsList = nil
		gatewayModelsMu.Unlock()
	})
}

const servedModels = `{"data":[{"id":"deepseek-v4-flash"},{"id":"qwen3.8-27b"}]}`

func armsOf(a ...map[string]any) *experimentWriteBody {
	return &experimentWriteBody{Arms: a}
}

func TestUnservedModelIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	problems, warnings := validateExperimentModels(armsOf(
		map[string]any{"id": "a", "judge_model": "gemma4"}))
	if len(problems) != 0 {
		t.Fatalf("a heuristic must not BLOCK a definition: %v", problems)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning about gemma4, got %v", warnings)
	}
	if !strings.Contains(warnings[0], "gemma4") || !strings.Contains(warnings[0], "ABSTAIN") {
		t.Fatalf("warning should name the model and the failure mode: %q", warnings[0])
	}
}

func TestServedModelPasses(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	problems, warnings := validateExperimentModels(armsOf(
		map[string]any{"id": "a", "judge_model": "deepseek-v4-flash"}))
	if len(problems) != 0 || len(warnings) != 0 {
		t.Fatalf("a served model must pass silently: %v %v", problems, warnings)
	}
}

// The exact mbb-ai shape: the singular field is fine, one PANEL SEAT is not.
func TestUnservedPanelSeatIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	_, warnings := validateExperimentModels(armsOf(map[string]any{
		"id":          "panel_median3",
		"judge_model": "deepseek-v4-flash",
		"judge_panel": []any{"deepseek-v4-flash", "qwen3.8-27b", "gemma4"},
	}))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "gemma4") {
		t.Fatalf("a dead panel seat must be caught: %v", warnings)
	}
}

func TestLumilakeIdsAreCheckedInTheirOwnNamespace(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// A HuggingFace id is NOT in the gateway list and must not be judged against it.
	problems, warnings := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:home:google/gemma-4-12B-it-qat-w4a16-ct"}))
	if len(problems) != 0 || len(warnings) != 0 {
		t.Fatalf("a valid lumilake id must not be tested against the gateway: %v %v", problems, warnings)
	}
}

func TestGatewayAliasInTheLumilakeLaneIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// vLLM answers "not a valid model identifier on huggingface.co" at RUN time.
	_, warnings := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:home:gemma4"}))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "HuggingFace") {
		t.Fatalf("an alias in the lumilake lane must be caught: %v", warnings)
	}
}

func TestLumilakeWithoutASiteIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// An un-sited /ll/ POST proxies to cloud, which has no workers, so the job
	// QUEUES FOREVER instead of failing.
	_, warnings := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:google/gemma-4-12B-it"}))
	if len(warnings) != 1 {
		t.Fatalf("a site-less lumilake id must be caught: %v", warnings)
	}
}

// An unreachable gateway must not block a define — but it must not pretend the
// check ran either. Silence is what let gemma4 through in the first place.
func TestUnreachableGatewayWarnsInsteadOfPassingSilently(t *testing.T) {
	stubGateway(t, "", http.StatusInternalServerError)
	problems, warnings := validateExperimentModels(armsOf(
		map[string]any{"id": "a", "judge_model": "anything-at-all"}))
	if len(problems) != 0 {
		t.Fatalf("an unreachable gateway must not reject: %v", problems)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "NOT checked") {
		t.Fatalf("the caller must be told the check did not run: %v", warnings)
	}
}

func TestNoArmsIsNotAnError(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	problems, warnings := validateExperimentModels(&experimentWriteBody{})
	if len(problems) != 0 || len(warnings) != 0 {
		t.Fatalf("an experiment with no arms declares no models: %v %v", problems, warnings)
	}
}

// The suffix convention must match the scheduler's, or a definition passes one
// reader and fails the other — the two-implementations failure the codebase
// already records for metrics.
func TestAnySuffixedKeyIsScanned(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	_, warnings := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "critic_model": "gemma4", "reviewer_panel": []any{"also-dead"}}))
	if len(warnings) != 2 {
		t.Fatalf("both *_model and *_panel keys must be scanned, got %v", warnings)
	}
}

func TestNonModelKeysAreIgnored(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	_, warnings := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "prompt_variant": "cards_v2", "temperature": 0.0}))
	if len(warnings) != 0 {
		t.Fatalf("an arm that names no model declares no model: %v", warnings)
	}
}
