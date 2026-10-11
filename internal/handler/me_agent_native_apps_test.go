package handler

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

// The 2026-10-11 leak: restoring the LumidOS bridge made a role=user
// `agent_list` return the operator's apps. These pin that the app read tools
// never reach the bridge, and that the bridge refuses everyone but the operator.

func nativeTestCtx() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/api/v1/me/agent/chat", nil)
	return c
}

func TestAgentListIsCallerScopedAndNeverHitsTheBridge(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	// If anything still dialled the bridge, make it a hard, visible failure.
	t.Setenv("LUMIDOS_URL", "http://127.0.0.1:1")

	mine := filepath.Join(home, ".tenants", "user-a", ".xp", "apps", "my-app")
	theirs := filepath.Join(home, ".tenants", "user-b", ".xp", "apps", "their-app")
	for _, d := range []string{mine, theirs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, tool := range []string{"agent_list", "app_list"} {
		res, ok := dispatchTool(nativeTestCtx(), "user-a", "user", tool, map[string]any{})
		if !ok {
			t.Fatalf("%s: not ok: %v", tool, res)
		}
		if _, isErr := res["error"]; isErr {
			t.Fatalf("%s reached the bridge: %v", tool, res)
		}
		// Round-trip through JSON — that is the shape the model receives.
		raw, _ := json.Marshal(res["apps"])
		var apps []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &apps); err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, a := range apps {
			names[a.Name] = true
		}
		if !names["my-app"] || names["their-app"] {
			t.Fatalf("%s: want only the caller's apps, got %v", tool, names)
		}
	}
}

func TestBridgeToolsFailClosedForNonOperators(t *testing.T) {
	t.Setenv("LUMIDOS_URL", "http://127.0.0.1:1")
	for _, role := range []string{"user", "admin"} {
		res, ok := dispatchTool(nativeTestCtx(), "user-a", role, "xp_status", map[string]any{})
		if ok {
			t.Fatalf("role %s: bridge tool succeeded: %v", role, res)
		}
		msg, _ := res["error"].(string)
		if msg == "" || msg == "lumidos tool bridge unavailable" {
			t.Fatalf("role %s: expected the not-available refusal, got %v", role, res)
		}
		if res["retryable"] != false {
			t.Fatalf("role %s: refusal must be non-retryable: %v", role, res)
		}
	}
}

func TestBridgeAllowedOnlyForOperator(t *testing.T) {
	if !bridgeAllowed("super_admin") || bridgeAllowed("admin") || bridgeAllowed("user") || bridgeAllowed("") {
		t.Fatal("bridge must be super_admin-only")
	}
}

func TestAgentInstallStillNeedsApproval(t *testing.T) {
	res, ok := dispatchTool(nativeTestCtx(), "user-a", "user", "agent_install",
		map[string]any{"slug": "owner/app"})
	if ok {
		t.Fatalf("install ran without approval: %v", res)
	}
}

func TestAgentDetailRejectsMalformedSlugs(t *testing.T) {
	for _, slug := range []string{"", "noslash", "a/b/c", "../x", "a/.."} {
		if _, err := publicRepoDetail(nativeTestCtx().Request.Context(), slug); err == nil {
			t.Fatalf("slug %q accepted", slug)
		}
	}
}
