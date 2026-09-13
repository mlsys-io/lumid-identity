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
	if len(problems) != 1 {
		t.Fatalf("expected gemma4 to be rejected, got problems=%v warnings=%v", problems, warnings)
	}
	if !strings.Contains(problems[0], "gemma4") || !strings.Contains(problems[0], "ABSTAIN") {
		t.Fatalf("problem should name the model and the failure mode: %q", problems[0])
	}
}

func TestServedModelPasses(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	problems, _ := validateExperimentModels(armsOf(
		map[string]any{"id": "a", "judge_model": "deepseek-v4-flash"}))
	if len(problems) != 0 {
		t.Fatalf("a served model must pass: %v", problems)
	}
}

// The exact mbb-ai shape: the singular field is fine, one PANEL SEAT is not.
func TestUnservedPanelSeatIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	problems, _ := validateExperimentModels(armsOf(map[string]any{
		"id":          "panel_median3",
		"judge_model": "deepseek-v4-flash",
		"judge_panel": []any{"deepseek-v4-flash", "qwen3.8-27b", "gemma4"},
	}))
	if len(problems) != 1 || !strings.Contains(problems[0], "gemma4") {
		t.Fatalf("a dead panel seat must be caught: %v", problems)
	}
}

func TestLumilakeIdsAreCheckedInTheirOwnNamespace(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// A HuggingFace id is NOT in the gateway list and must not be judged against it.
	problems, _ := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:home:google/gemma-4-12B-it-qat-w4a16-ct"}))
	if len(problems) != 0 {
		t.Fatalf("a valid lumilake id must not be tested against the gateway: %v", problems)
	}
}

func TestGatewayAliasInTheLumilakeLaneIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// vLLM answers "not a valid model identifier on huggingface.co" at RUN time.
	problems, _ := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:home:gemma4"}))
	if len(problems) != 1 || !strings.Contains(problems[0], "HuggingFace") {
		t.Fatalf("an alias in the lumilake lane must be caught: %v", problems)
	}
}

func TestLumilakeWithoutASiteIsRejected(t *testing.T) {
	stubGateway(t, servedModels, http.StatusOK)
	// An un-sited /ll/ POST proxies to cloud, which has no workers, so the job
	// QUEUES FOREVER instead of failing.
	problems, _ := validateExperimentModels(armsOf(map[string]any{
		"id": "a", "analyst_model": "lumilake:google/gemma-4-12B-it"}))
	if len(problems) != 1 {
		t.Fatalf("a site-less lumilake id must be caught: %v", problems)
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
