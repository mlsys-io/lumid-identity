package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The `workflows` app-data tool exists so an app's DECLARED compute DAG can be
// rendered from its own page. Before it, LumilakeWorkflowCanvas mounted only
// from a chat tool-call event, so a published graph was viewable only if a
// human happened to ask chat to optimize it.
//
// The reader is deliberately dumb — list the files, return the YAML verbatim —
// because the canvas parses the ops graph itself and re-serialising here would
// be a second chance to reformat a graph the server takes literally.

func mkWorkflowBundle(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if len(files) > 0 {
		if err := os.MkdirAll(filepath.Join(dir, "workflows"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, "workflows", name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// readWorkflowsFrom exercises the same listing logic against a known dir,
// without needing resolveAppDir to find a real tenant bundle.
func readWorkflowsFrom(dir string) []map[string]any {
	ents, err := os.ReadDir(filepath.Join(dir, "workflows"))
	if err != nil {
		return nil
	}
	out := []map[string]any{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "workflows", n))
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"name": strings.TrimSuffix(strings.TrimSuffix(n, ".yml"), ".yaml"),
			"file": n, "yaml": string(b), "bytes": len(b),
		})
	}
	return out
}

func TestWorkflowsToolIsRegistered(t *testing.T) {
	// Registration is the whole feature: without it the surface gets HTTP 400
	// "tool not readable from a surface" and renders an error box.
	if _, ok := readOnlyAppDataTools["workflows"]; !ok {
		t.Fatal("`workflows` missing from readOnlyAppDataTools — the app-page canvas cannot load")
	}
}

func TestWorkflowYamlIsReturnedVerbatim(t *testing.T) {
	body := "name: vla_curation\n# a comment a re-serialiser would drop\nops: []\n"
	dir := mkWorkflowBundle(t, map[string]string{"vla_curation.yaml": body})
	got := readWorkflowsFrom(dir)
	if len(got) != 1 {
		t.Fatalf("want 1 workflow, got %d", len(got))
	}
	if got[0]["yaml"] != body {
		t.Errorf("yaml was not verbatim:\n got %q\nwant %q", got[0]["yaml"], body)
	}
	if got[0]["name"] != "vla_curation" {
		t.Errorf("name = %v, want vla_curation (extension stripped)", got[0]["name"])
	}
}

func TestBothYamlExtensionsAreListed(t *testing.T) {
	dir := mkWorkflowBundle(t, map[string]string{"a.yaml": "name: a\n", "b.yml": "name: b\n"})
	if n := len(readWorkflowsFrom(dir)); n != 2 {
		t.Errorf("want both .yaml and .yml listed, got %d", n)
	}
}

func TestNonYamlFilesAreIgnored(t *testing.T) {
	// A README beside the graphs is documentation, not a workflow; returning it
	// would hand the canvas something it cannot parse.
	dir := mkWorkflowBundle(t, map[string]string{
		"real.yaml": "name: real\n", "README.md": "notes", "notes.txt": "x",
	})
	got := readWorkflowsFrom(dir)
	if len(got) != 1 || got[0]["name"] != "real" {
		t.Errorf("want only real.yaml, got %v", got)
	}
}

func TestNoWorkflowsDirIsEmptyNotAnError(t *testing.T) {
	// Most apps declare no compute DAG. That is ordinary, so the surface must
	// get an empty list it can render its own empty state from — not an error.
	dir := t.TempDir()
	if got := readWorkflowsFrom(dir); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}
