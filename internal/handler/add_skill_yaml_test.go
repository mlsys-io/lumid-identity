package handler

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type skillSpec struct {
	Name         string `yaml:"name"`
	SkillImports []struct {
		Repo    string `yaml:"repo"`
		Version string `yaml:"version"`
	} `yaml:"skill_imports"`
}

func parseSpec(t *testing.T, s string) skillSpec {
	t.Helper()
	var out skillSpec
	if err := yaml.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("result is not valid YAML: %v\n%s", err, s)
	}
	return out
}

// FLB-QR-04: quant-research ships `skill_imports: []`; the old line append
// produced `skill_imports: []\n  - community/x`, which does not parse.
func TestAppendToSkillImportsFlowEmptyList(t *testing.T) {
	in := "# app spec\nname: quant-research\nskill_imports: []\nloops:\n  - name: backtest\n"
	out, added, err := appendToSkillImports(in, "alice/python-repl")
	if err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	sp := parseSpec(t, out)
	if len(sp.SkillImports) != 1 || sp.SkillImports[0].Repo != "alice/python-repl" {
		t.Fatalf("skill_imports = %+v", sp.SkillImports)
	}
	if sp.Name != "quant-research" || !strings.Contains(out, "# app spec") || !strings.Contains(out, "name: backtest") {
		t.Fatalf("other content lost:\n%s", out)
	}
}

func TestAppendToSkillImportsExistingAndDedupe(t *testing.T) {
	in := "name: a\nskill_imports:\n  - repo: community/findata\n    version: main\n  - bob/bare\n"
	out, added, err := appendToSkillImports(in, "community/python-repl")
	if err != nil || !added {
		t.Fatalf("added=%v err=%v", added, err)
	}
	if n := strings.Count(out, "repo:"); n != 2 {
		t.Fatalf("want 2 repo entries, got %d:\n%s", n, out)
	}
	for _, dup := range []string{"community/findata", "bob/bare"} {
		if _, added, _ := appendToSkillImports(out, dup); added {
			t.Fatalf("%s re-added", dup)
		}
	}
}

func TestAppendToSkillImportsMissingOrNullKey(t *testing.T) {
	for _, in := range []string{"name: a\n", "name: a\nskill_imports:\n"} {
		out, added, err := appendToSkillImports(in, "o/s")
		if err != nil || !added {
			t.Fatalf("%q: added=%v err=%v", in, added, err)
		}
		if sp := parseSpec(t, out); len(sp.SkillImports) != 1 || sp.SkillImports[0].Repo != "o/s" {
			t.Fatalf("%q -> %+v", in, sp.SkillImports)
		}
	}
}

func TestAppendToSkillImportsRejectsBrokenSpec(t *testing.T) {
	if _, _, err := appendToSkillImports("skill_imports: []\n  - x\n", "o/s"); err == nil {
		t.Fatal("expected an error for an unparseable spec, not a silent write")
	}
}
