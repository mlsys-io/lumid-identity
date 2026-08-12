package handler

import (
	"os"
	"path/filepath"
	"testing"
)

// Measured against the REAL dataset: every shipped case must fit its role's cap,
// or the role silently loses cases. Skips when the dataset isn't present.
func TestRealCasesFitTheirRoleCaps(t *testing.T) {
	src := "/home/webmaster/.xp/apps/mbb-casebook-cases/data"
	files, err := filepath.Glob(filepath.Join(src, "*.json"))
	if err != nil || len(files) == 0 {
		t.Skip("dataset not present")
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "data", "seed")
	os.MkdirAll(seed, 0o755)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		os.WriteFile(filepath.Join(seed, filepath.Base(f)), b, 0o644)
	}
	roles := []string{caseRoleInterviewee, caseRoleInterviewer, caseRoleJudge}
	bad := map[string]int{}
	for _, f := range files {
		id := filepath.Base(f)
		id = id[:len(id)-len(".json")]
		for _, r := range roles {
			if _, ok := caseContextForRole(dir, id, r); !ok {
				bad[r]++
				t.Logf("REFUSED %s for %s", r, id)
			}
		}
	}
	for r, n := range bad {
		t.Errorf("role %s refused %d of %d real cases", r, n, len(files))
	}
	t.Logf("checked %d cases x %d roles", len(files), len(roles))
}
