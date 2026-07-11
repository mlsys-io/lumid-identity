package handler

// Integration test for the bridge-gated overlay read half (WS-4/5):
// /internal/app-prompt-overrides/fetch + /internal/app-signals/{claim,ack}.
// Runs only when TEST_MYSQL_DSN is set (same harness as the intent-queue test).
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' go test ./internal/handler -run AppOverlays

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func setupOverlayDB(t *testing.T) *gorm.DB {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping overlay integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.MeDoc{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	db.Where("1 = 1").Delete(&models.MeDoc{})
	common.DB = db
	return db
}

func overlayRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/internal", RequireBridge())
	g.POST("/app-prompt-overrides/fetch", InternalAppPromptOverridesFetch)
	g.POST("/app-signals/claim", InternalAppSignalsClaim)
	g.POST("/app-signals/ack", InternalAppSignalsAck)
	return r
}

func overlayPost(t *testing.T, r *gin.Engine, path string, body any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s → HTTP %d: %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON from %s: %v", path, err)
	}
	return out
}

func TestAppOverlaysRoundTrip(t *testing.T) {
	setupOverlayDB(t)
	os.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	r := overlayRouter()

	const user = "user-overlay-test"
	const app = "venue-link-matcher"

	// Seed: two prompt overrides (one for another app — must not leak) and
	// two signals (one already consumed — must not be claimed).
	saveOverride := func(app, name, content string) {
		doc, _ := json.Marshal(promptOverrideDoc{App: app, Name: name, Content: content})
		if err := meDocSave(user, meDocKindPrompt, promptOverrideID(app, name), string(doc)); err != nil {
			t.Fatalf("seed override: %v", err)
		}
	}
	saveOverride(app, "judge.md", "# tuned judge prompt")
	saveOverride("other-app", "judge.md", "# other app's prompt")

	saveSignal := func(id string, rec signalRecord) {
		doc, _ := json.Marshal(signalDoc{App: app, Rec: rec})
		if err := meDocSave(user, meDocKindSignal, id, string(doc)); err != nil {
			t.Fatalf("seed signal: %v", err)
		}
	}
	saveSignal("sig-1", signalRecord{Ts: "2026-07-11T00:00:00Z", Action: "branch",
		Loop: "match_cycle", Note: "try N>=3", By: user, Status: "pending"})
	saveSignal("sig-2", signalRecord{Ts: "2026-07-10T00:00:00Z", Action: "branch",
		Loop: "match_cycle", By: user, Status: "consumed"})

	// 1. Prompt overrides fetch — only THIS app's override comes back.
	out := overlayPost(t, r, "/api/v1/internal/app-prompt-overrides/fetch",
		gin.H{"user_sub": user, "app": app})
	ovr := out["data"].(map[string]any)["overrides"].(map[string]any)
	if len(ovr) != 1 || ovr["judge.md"] != "# tuned judge prompt" {
		t.Fatalf("unexpected overrides: %#v", ovr)
	}

	// 2. Signals claim — only the pending one, with its doc id.
	out = overlayPost(t, r, "/api/v1/internal/app-signals/claim",
		gin.H{"user_sub": user, "app": app})
	sigs := out["data"].(map[string]any)["signals"].([]any)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 pending signal, got %d", len(sigs))
	}
	first := sigs[0].(map[string]any)
	if first["id"] != "sig-1" {
		t.Fatalf("expected sig-1, got %v", first["id"])
	}
	rec := first["rec"].(map[string]any)
	if rec["note"] != "try N>=3" {
		t.Fatalf("record mangled: %#v", rec)
	}

	// 3. Ack — doc deleted; second claim returns nothing.
	out = overlayPost(t, r, "/api/v1/internal/app-signals/ack",
		gin.H{"user_sub": user, "ids": []string{"sig-1"}})
	if n := out["data"].(map[string]any)["deleted"].(float64); n != 1 {
		t.Fatalf("expected 1 deleted, got %v", n)
	}
	out = overlayPost(t, r, "/api/v1/internal/app-signals/claim",
		gin.H{"user_sub": user, "app": app})
	if sigs := out["data"].(map[string]any)["signals"].([]any); len(sigs) != 0 {
		t.Fatalf("expected no signals after ack, got %d", len(sigs))
	}
}
