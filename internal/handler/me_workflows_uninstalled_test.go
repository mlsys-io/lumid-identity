package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// An uninstalled app leaves the installed-app list (and with it the Workflows
// page): a done install intent and a run record both outlive the uninstall.
// Measured 2026-11-28: admin's two uninstalled e2e copies kept 19 workflow rows.
func TestTenantInstalledAppNamesDropsUninstalled(t *testing.T) {
	db := setupIntentDB(t)
	if err := db.AutoMigrate(&models.MeAppRun{}); err != nil {
		t.Fatalf("automigrate runs: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MeAppRun{})
	const sub = "aaaaaaaa-0000-0000-0000-00000000wf01"
	t0 := time.Now().Add(-2 * time.Hour)
	mk := func(id, action, payload string, at time.Time) {
		if err := db.Create(&models.MeAppIntent{ID: id, Action: action, UserSub: sub, Payload: payload,
			Status: "done", CreatedAt: at}).Error; err != nil {
			t.Fatalf("intent: %v", err)
		}
	}
	mk("i1", "install", `{"slug":"o/gone-app"}`, t0)
	mk("i2", "install", `{"slug":"o/kept-app"}`, t0)
	mk("i3", "install", `{"slug":"o/back-app"}`, t0)
	mk("u1", "uninstall", `{"app":"gone-app"}`, t0.Add(time.Hour))
	mk("u2", "uninstall", `{"app":"back-app"}`, t0.Add(30*time.Minute))
	mk("i4", "install", `{"slug":"o/back-app"}`, t0.Add(time.Hour)) // reinstalled after the uninstall
	// A run BEFORE the uninstall must not keep gone-app alive; a run-only app with no uninstall stays.
	db.Create(&models.MeAppRun{UserSub: sub, App: "gone-app", Loop: "l", RunTs: t0.Add(10 * time.Minute).Unix()})
	db.Create(&models.MeAppRun{UserSub: sub, App: "ran-app", Loop: "l", RunTs: t0.Unix()})

	got := map[string]bool{}
	for _, n := range tenantInstalledAppNames(sub) {
		got[n] = true
	}
	if got["gone-app"] {
		t.Fatalf("uninstalled app still listed: %v", got)
	}
	for _, want := range []string{"kept-app", "back-app", "ran-app"} {
		if !got[want] {
			t.Fatalf("%s missing: %v", want, got)
		}
	}
}
