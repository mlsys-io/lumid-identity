// me_validate.go — POST /api/v1/me/workflows/validate
//
// Server-truth pre-flight for the "New workflow" wizard (NewWorkflowFlow).
// MeComposeWorkflow writes a `<slug>-draft` bundle (xpcloud.yaml +
// manifest.json) into the caller's tenant tree and resolves each pipeline
// skill against xp.io. This endpoint reads that written draft back off disk
// and runs the same checks app-ci's `gate_manifest_lint` enforces
// (sdk/ops/app_ci.py) — name/kind/version validity + a pipeline-shape check
// (loops present, each loop has steps[] or an engine) — so the wizard's
// validation card reflects what was actually written, not a client guess.
//
// Read-only; best-effort (a missing/odd shape becomes a failing check with a
// human detail, never a 500).
package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// Mirrors app_ci.py _NAME_RE / _VALID_KINDS exactly.
var validateNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)

var validateKinds = map[string]bool{
	"app": true, "autoresearch": true, "agent": true, "skill": true, "annotation": true,
}

type validateCheck struct {
	Check  string   `json:"check"`
	Status string   `json:"status"` // "pass" | "fail"
	Detail string   `json:"detail"`
	Issues []string `json:"issues,omitempty"`
}

// MeValidateWorkflow validates a composed draft bundle. Body: {"draft_slug":"<slug>-draft"}
// (the value MeComposeWorkflow returns as data.draft_slug). Falls back to "slug".
func MeValidateWorkflow(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		DraftSlug string `json:"draft_slug"`
		Slug      string `json:"slug"`
	}
	_ = c.ShouldBindJSON(&body)
	slug := body.DraftSlug
	if slug == "" {
		slug = body.Slug
	}
	if slug == "" || !slugRe.MatchString(slug) {
		fail(c, http.StatusBadRequest, 1400, "missing or invalid draft_slug")
		return
	}

	var checks []validateCheck
	dir := filepath.Join(tenantAppsDir(userID), slug)
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		checks = []validateCheck{
			validateManifestLint(dir),
			validatePipelineShape(dir),
		}
	} else if row := storedAppSpec(userID, slug); row != nil {
		// identity mounts no tenant volume; the scheduler can see the disk. A
		// draft composed on a cloud pod is a stage_app intent whose spec was
		// written to me_app_specs at compose time — validate that. The manifest
		// is not stored; compose builds it from the same name/kind/version the
		// spec carries, so it is rebuilt from the spec here.
		spec := []byte(row.SpecYAML)
		checks = []validateCheck{
			validateManifestLintBytes(manifestFromSpec(spec), nil),
			validatePipelineShapeBytes(spec, nil),
		}
	} else {
		fail(c, http.StatusNotFound, 1404, "draft not found — compose it first")
		return
	}
	allPass := true
	for _, ck := range checks {
		if ck.Status != "pass" {
			allPass = false
		}
	}
	ok(c, "ok", gin.H{"slug": slug, "ok": allPass, "checks": checks})
}

// validateManifestLint mirrors app_ci gate_manifest_lint over the draft's
// manifest.json: name regex, kind ∈ valid kinds, non-empty version.
func validateManifestLint(dir string) validateCheck {
	mfPath, _ := ResolveManifestPath(dir)
	b, err := os.ReadFile(mfPath)
	return validateManifestLintBytes(b, err)
}

// manifestFromSpec rebuilds the draft manifest compose writes — name, kind,
// version, description — from the spec's own top-level fields. nil when the
// spec does not parse (the lint then reports it unparseable).
func manifestFromSpec(spec []byte) []byte {
	var doc struct {
		Name        string `yaml:"name"`
		Kind        string `yaml:"kind"`
		Version     string `yaml:"version"`
		Description string `yaml:"description"`
	}
	if yaml.Unmarshal(spec, &doc) != nil {
		return nil
	}
	b, _ := json.Marshal(map[string]any{
		"name": doc.Name, "kind": doc.Kind, "version": doc.Version, "description": doc.Description,
	})
	return b
}

func validateManifestLintBytes(b []byte, err error) validateCheck {
	ck := validateCheck{Check: "manifest_lint", Status: "pass"}
	if err != nil || b == nil {
		ck.Status = "fail"
		ck.Detail = "manifest.json missing"
		ck.Issues = []string{"expected manifest.json in the draft bundle"}
		return ck
	}
	var m map[string]any
	if yaml.Unmarshal(b, &m) != nil || m == nil { // yaml.v3 parses JSON too
		ck.Status = "fail"
		ck.Detail = "manifest.json unparseable"
		return ck
	}
	var issues []string
	if name, _ := m["name"].(string); name == "" || !validateNameRe.MatchString(name) {
		issues = append(issues, "`name` invalid (must match ^[a-z][a-z0-9-]{1,62}[a-z0-9]$)")
	}
	if kind, _ := m["kind"].(string); !validateKinds[kind] {
		issues = append(issues, "`kind` invalid (expected app/autoresearch/agent/skill/annotation)")
	}
	if ver, _ := m["version"].(string); ver == "" {
		issues = append(issues, "`version` missing")
	}
	if len(issues) > 0 {
		ck.Status = "fail"
		ck.Detail = pluralIssues(len(issues))
		ck.Issues = issues
	} else {
		ck.Detail = "name, kind and version are valid"
	}
	return ck
}

// validatePipelineShape confirms xpcloud.yaml parses and declares at least one
// loop, and that every loop is runnable: it has a non-empty steps[] (Pattern A)
// or an engine (Pattern B). This is the "do I have a real pipeline?" gate.
func validatePipelineShape(dir string) validateCheck {
	specPath, _ := ResolveSpecPath(dir)
	b, err := os.ReadFile(specPath)
	return validatePipelineShapeBytes(b, err)
}

func validatePipelineShapeBytes(b []byte, err error) validateCheck {
	ck := validateCheck{Check: "pipeline_shape", Status: "pass"}
	if err != nil || b == nil {
		ck.Status = "fail"
		ck.Detail = "xpcloud.yaml missing"
		return ck
	}
	var doc struct {
		Loops []struct {
			Name   string `yaml:"name"`
			Steps  []any  `yaml:"steps"`
			Engine any    `yaml:"engine"`
		} `yaml:"loops"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		ck.Status = "fail"
		ck.Detail = "xpcloud.yaml unparseable"
		return ck
	}
	if len(doc.Loops) == 0 {
		ck.Status = "fail"
		ck.Detail = "no loops declared"
		return ck
	}
	var issues []string
	for _, lp := range doc.Loops {
		nm := lp.Name
		if nm == "" {
			nm = "(unnamed)"
		}
		if len(lp.Steps) == 0 && lp.Engine == nil {
			issues = append(issues, "loop "+nm+" has no steps and no engine — add at least one skill")
		}
	}
	if len(issues) > 0 {
		ck.Status = "fail"
		ck.Detail = pluralIssues(len(issues))
		ck.Issues = issues
	} else {
		n := len(doc.Loops)
		if n == 1 {
			ck.Detail = "1 runnable loop"
		} else {
			ck.Detail = itoa(int64(n)) + " runnable loops"
		}
	}
	return ck
}

func pluralIssues(n int) string {
	if n == 1 {
		return "1 issue"
	}
	return itoa(int64(n)) + " issues"
}
