package handler

// LQ-20261006-04 / -05: three copies of one tenant's .xpcloud.yaml disagreed.
//
//   - the applied editor save (app_file_write, 10-06 14:34): +custom loop, no study
//   - the install on the scheduler, echoed to me_app_specs: +study binding at
//     14:42 (patch_experiment), then BOTH dropped by the 10-10 bulk update
//   - the published bundle: neither
//
// Manage / Advanced YAML read the first, the Workflows page read the third, the
// runtime ran the second. These pin the precedence that makes them one answer.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func TestSpecEchoSupersedesOnlyALaterChange(t *testing.T) {
	write := time.Date(2026, 10, 6, 14, 34, 44, 0, time.UTC)
	cases := map[string]struct {
		echo time.Time
		want bool
	}{
		// app_file_write echoes BEFORE its intent completes — its own echo
		// must never knock the overlay out.
		"the write's own echo, a moment before completion": {write.Add(-200 * time.Millisecond), false},
		"same instant":                     {write, false},
		"patch_experiment eight min later": {write.Add(8 * time.Minute), true},
		"bulk update four days later":      {write.Add(96 * time.Hour), true},
		"no echo row":                      {time.Time{}, false},
	}
	for name, c := range cases {
		if got := specEchoSupersedes(write, c.echo); got != c.want {
			t.Errorf("%s: specEchoSupersedes=%v, want %v", name, got, c.want)
		}
	}
}

func setupSpecOverlayDB(t *testing.T) {
	db := setupIntentDB(t) // skips without TEST_MYSQL_DSN
	if err := db.AutoMigrate(&models.MeAppSpec{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MeAppSpec{})
}

const (
	qrSub           = "u-lq0406"
	qrSavedSpec     = "name: quant-research\nloops:\n- name: analyze\n- name: qa_custom_analyze_20261006\n  schedule: '@trigger'\n"
	qrInstalledSpec = "name: quant-research\nversion: 0.7.120\nloops:\n- name: analyze\n- name: harvest_outbox\n"
)

func seedSave(t *testing.T, at time.Time) {
	t.Helper()
	row := models.MeAppIntent{ID: "lq0406-write", Action: appFileWriteAction, UserSub: qrSub, Status: "done",
		Payload:   `{"app":"quant-research","path":".xpcloud.yaml","op":"write","content":` + mustJSON(qrSavedSpec) + `}`,
		CreatedAt: at, CompletedAt: &at}
	if err := common.DB.Create(&row).Error; err != nil {
		t.Fatalf("seed write: %v", err)
	}
}

func seedEcho(t *testing.T, spec string, at time.Time) {
	t.Helper()
	if err := upsertStoredAppSpec(qrSub, "quant-research", spec, ""); err != nil {
		t.Fatalf("seed echo: %v", err)
	}
	if err := common.DB.Model(&models.MeAppSpec{}).Where("user_sub = ? AND app = ?", qrSub, "quant-research").
		Update("updated_at", at).Error; err != nil {
		t.Fatalf("stamp echo: %v", err)
	}
}

// The live sequence: save → (own echo) → a later scheduler-side rewrite. The
// editor must show what the install now holds, not the save it outlived.
func TestALaterInstallChangeRetiresTheSpecOverlay(t *testing.T) {
	setupSpecOverlayDB(t)
	saved := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	seedSave(t, saved)
	seedEcho(t, qrInstalledSpec, saved.Add(time.Hour))

	if _, _, found := appFileOverlay(qrSub, "quant-research", appFileSpecRel); found {
		t.Fatal("the spec overlay survived a newer echo of the install — Manage keeps " +
			"listing a loop the runtime no longer has, and every save conflicts on base_sha")
	}
	got := string(readAppSpecBytes(qrSub, "quant-research", ""))
	if !strings.Contains(got, "version: 0.7.120") || strings.Contains(got, "qa_custom_analyze") {
		t.Fatalf("readAppSpecBytes served %q; want the echoed install spec", got)
	}
}

// Its own echo (written just before completion) must not retire the save.
func TestAWritesOwnEchoKeepsTheOverlay(t *testing.T) {
	setupSpecOverlayDB(t)
	saved := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	seedEcho(t, qrSavedSpec, saved.Add(-300*time.Millisecond))
	seedSave(t, saved)
	if b, _, found := appFileOverlay(qrSub, "quant-research", appFileSpecRel); !found || string(b) != qrSavedSpec {
		t.Fatalf("overlay found=%v %q; want the applied save", found, b)
	}
}

// The workflow list's cross-node fallback reads the same spec as the editor:
// a tenant-added loop shows up as a workflow row (and so in New study).
func TestWorkflowFallbackListsTheInstalledLoops(t *testing.T) {
	setupSpecOverlayDB(t)
	t.Setenv("LUMID_OPERATOR_HOME", t.TempDir())
	saved := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	// Registered as installed through the run record (tenantInstalledAppNames).
	if err := common.DB.AutoMigrate(&models.MeAppRun{}); err != nil {
		t.Fatalf("automigrate runs: %v", err)
	}
	common.DB.Where("user_sub = ?", qrSub).Delete(&models.MeAppRun{})
	if err := common.DB.Create(&models.MeAppRun{UserSub: qrSub, App: "quant-research", Loop: "analyze", RunTs: saved.Unix()}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}
	seedEcho(t, qrSavedSpec, saved.Add(-time.Second))
	seedSave(t, saved)

	names := map[string]bool{}
	for _, r := range scheduledWorkflows(qrSub) {
		if r.App == "quant-research" {
			names[r.Name] = true
		}
	}
	if !names["qa_custom_analyze_20261006"] || !names["analyze"] {
		t.Fatalf("workflow rows = %v; want the installed spec's loops incl. the tenant-added one", names)
	}
	common.DB.Where("user_sub = ?", qrSub).Delete(&models.MeAppRun{})
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
