package handler

// Integration tests for the cross-node app-edit override store (ITEM 3/5) +
// the internal fetch/upsert endpoints. MySQL-gated, same harness as the other
// me_docs/intent tests (FOR UPDATE SKIP LOCKED etc. aren't exercised here, but
// the JSON-blob semantics + upsert are worth pinning against real MySQL).
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run AppEditOverrides
//	  go test ./internal/handler -run AppSpecStore

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func setupOverrideStoreDB(t *testing.T) *gorm.DB {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping override-store integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.MeDoc{}, &models.MeAppSpec{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MeDoc{})
	db.Where("1 = 1").Delete(&models.MeAppSpec{})
	common.DB = db
	return db
}

func TestAppEditOverridesRoundTrip(t *testing.T) {
	setupOverrideStoreDB(t)
	const user = "user-override-store"
	const app = "venue-link-matcher"

	// config override
	if err := appConfigOverrideSave(user, app, `{"model":"sonnet","top_k":5}`); err != nil {
		t.Fatalf("config save: %v", err)
	}
	if got, ok := appConfigOverrideGet(user, app); !ok || got != `{"model":"sonnet","top_k":5}` {
		t.Fatalf("config get mismatch: %q ok=%v", got, ok)
	}

	// surface override (per (app, surface))
	if err := appSurfaceOverrideSave(user, app, "home", "# tuned home"); err != nil {
		t.Fatalf("surface save: %v", err)
	}
	if err := appSurfaceOverrideSave(user, app, "detail", "# tuned detail"); err != nil {
		t.Fatalf("surface save 2: %v", err)
	}
	if got, ok := appSurfaceOverrideGet(user, app, "home"); !ok || got != "# tuned home" {
		t.Fatalf("surface get mismatch: %q ok=%v", got, ok)
	}
	if got, ok := appSurfaceOverrideGet(user, app, "detail"); !ok || got != "# tuned detail" {
		t.Fatalf("surface detail mismatch: %q ok=%v", got, ok)
	}

	// loop overrides — two loops on one app, plus a decoy on another app.
	if err := appLoopOverrideSave(user, app, "match_cycle", `{"schedule":"0 8 * * *","model":"opus"}`); err != nil {
		t.Fatalf("loop save: %v", err)
	}
	if err := appLoopOverrideSave(user, app, "sweep", `{"enabled":false}`); err != nil {
		t.Fatalf("loop save 2: %v", err)
	}
	if err := appLoopOverrideSave(user, "other-app", "x", `{"enabled":true}`); err != nil {
		t.Fatalf("loop save decoy: %v", err)
	}
	all := appLoopOverridesForApp(user, app)
	if len(all) != 2 || all["match_cycle"] == "" || all["sweep"] == "" {
		t.Fatalf("loop overrides for app wrong: %#v", all)
	}
	if _, leaked := all["x"]; leaked {
		t.Fatalf("decoy loop leaked across apps")
	}

	// upsert semantics — re-saving the config replaces, not duplicates.
	if err := appConfigOverrideSave(user, app, `{"model":"opus"}`); err != nil {
		t.Fatalf("config re-save: %v", err)
	}
	if got, _ := appConfigOverrideGet(user, app); got != `{"model":"opus"}` {
		t.Fatalf("config not replaced: %q", got)
	}
}

func TestAppSpecStore(t *testing.T) {
	setupOverrideStoreDB(t)
	const user = "user-spec-store"
	const app = "venue-link-matcher"

	spec := "name: venue-link-matcher\nui:\n  surface:\n    markdown: ui/home.md\n"
	files := map[string]string{"ui/home.md": "# Home surface"}
	if err := meAppSpecSave(user, app, spec, files); err != nil {
		t.Fatalf("spec save: %v", err)
	}

	// meAppSpecGet round-trips both spec + ui files.
	gotSpec, gotFiles, ok := meAppSpecGet(user, app)
	if !ok || string(gotSpec) != spec {
		t.Fatalf("spec get mismatch: ok=%v spec=%q", ok, gotSpec)
	}
	if gotFiles["ui/home.md"] != "# Home surface" {
		t.Fatalf("ui files mismatch: %#v", gotFiles)
	}

	// specForApp returns the DB spec first + a reader that serves the ui file
	// from the DB (no network — a bogus path returns nil via published fallback).
	sb, reader, resolved := specForApp(user, app)
	if !resolved || string(sb) != spec {
		t.Fatalf("specForApp spec mismatch: resolved=%v", resolved)
	}
	if string(reader("ui/home.md")) != "# Home surface" {
		t.Fatalf("specForApp reader missed the DB ui file")
	}

	// appInstalledForUser sees the materialized spec row.
	if !appInstalledForUser(user, app) {
		t.Fatalf("appInstalledForUser should be true with a spec row")
	}
	if appInstalledForUser(user, "no-such-app") {
		t.Fatalf("appInstalledForUser should be false for an unknown app")
	}

	// upsert refreshes.
	if err := meAppSpecSave(user, app, spec+"# v2\n", map[string]string{"ui/home.md": "# v2"}); err != nil {
		t.Fatalf("spec re-save: %v", err)
	}
	_, gotFiles2, _ := meAppSpecGet(user, app)
	if gotFiles2["ui/home.md"] != "# v2" {
		t.Fatalf("spec not refreshed on upsert: %#v", gotFiles2)
	}
}

func TestInternalAppOverrideFetch(t *testing.T) {
	setupOverrideStoreDB(t)
	os.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	const user = "user-internal-fetch"
	const app = "venue-link-matcher"

	if err := appConfigOverrideSave(user, app, `{"model":"sonnet"}`); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := appLoopOverrideSave(user, app, "match_cycle", `{"model":"opus"}`); err != nil {
		t.Fatalf("seed loop: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/internal", RequireBridge())
	g.POST("/app-config-override/fetch", InternalAppConfigOverrideFetch)
	g.POST("/app-loop-overrides/fetch", InternalAppLoopOverridesFetch)
	g.POST("/app-spec", InternalAppSpecUpsert)

	// config fetch → parsed object
	out := overlayPost(t, r, "/api/v1/internal/app-config-override/fetch",
		gin.H{"user_sub": user, "app": app})
	over := out["data"].(map[string]any)["override"].(map[string]any)
	if over["model"] != "sonnet" {
		t.Fatalf("config override fetch mismatch: %#v", over)
	}

	// loop overrides fetch → [{loop, override}]
	out = overlayPost(t, r, "/api/v1/internal/app-loop-overrides/fetch",
		gin.H{"user_sub": user, "app": app})
	loops := out["data"].(map[string]any)["overrides"].([]any)
	if len(loops) != 1 {
		t.Fatalf("expected 1 loop override, got %d", len(loops))
	}
	first := loops[0].(map[string]any)
	if first["loop"] != "match_cycle" {
		t.Fatalf("loop override loop mismatch: %#v", first)
	}

	// app-spec upsert via the internal endpoint, then read it back through the store.
	uiFiles, _ := json.Marshal(map[string]string{"ui/home.md": "# via endpoint"})
	var uf map[string]string
	_ = json.Unmarshal(uiFiles, &uf)
	overlayPost(t, r, "/api/v1/internal/app-spec",
		gin.H{"user_sub": user, "app": app, "spec_yaml": "name: x\n", "ui_files": uf})
	if _, files, ok := meAppSpecGet(user, app); !ok || files["ui/home.md"] != "# via endpoint" {
		t.Fatalf("app-spec upsert via endpoint did not persist: %#v", files)
	}
}
