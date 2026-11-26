package handler

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
)

// The chat's workflow_detail tool resolves a simple-scheme variant through the
// same lookup as the workflow page (readLoopsForDetail). It used to answer
// "workflow not found" for Studio-made variants, and the chat then said it had
// no tool to read the workflow's runs.
func TestChatWorkflowDetailFindsASimpleSchemeVariant(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LUMID_OPERATOR_HOME", home)
	dir := filepath.Join(home, ".tenants", "u1", ".xp", "apps", "lab")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := "name: lab\nworkflows:\n- id: simulate\n  steps: {python: simulate}\n" +
		"- id: sla_tuned\n  parent: simulate\n  run: manual\n  steps: {python: simulate}\n"
	if err := os.WriteFile(filepath.Join(dir, ".xpcloud.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)

	out := toolWorkflowDetail(c, "u1", "lab:sla_tuned")
	if out["error"] != nil {
		t.Fatalf("variant not found: %v", out["error"])
	}
	if out["loop"] != "sla_tuned" || out["source"] != "tenant" {
		t.Fatalf("got %v", out)
	}
	if got := toolWorkflowDetail(c, "u1", "lab:nope"); got["error"] == nil {
		t.Fatalf("an unknown workflow must still say so: %v", got)
	}
}
