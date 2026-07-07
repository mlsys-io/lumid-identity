package handler

// Integration test for the DB-backed /me/apps intent queue. Runs only when
// TEST_MYSQL_DSN is set (a throwaway MySQL) — MySQL is required because the
// claim path uses FOR UPDATE SKIP LOCKED, which SQLite can't model.
//
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' go test ./internal/handler -run MeIntentQueue

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func setupIntentDB(t *testing.T) *gorm.DB {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping DB queue integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.MeAppIntent{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	// Clean slate.
	db.Where("1 = 1").Delete(&models.MeAppIntent{})
	common.DB = db
	return db
}

func bridgeRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/internal", RequireBridge())
	g.POST("/me-intents/claim", InternalMeIntentsClaim)
	g.POST("/me-intents/:id/result", InternalMeIntentResult)
	return r
}

func TestMeIntentQueueRoundTrip(t *testing.T) {
	db := setupIntentDB(t)
	os.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	r := bridgeRouter()

	// Seed: an install intent WITH a bearer (simulates a private-repo install),
	// and an uninstall intent (no bearer). Insert directly to avoid the
	// signing-key dependency of insertIntent's bearer mint.
	now := time.Now()
	rows := []models.MeAppIntent{
		{ID: "intent-install-1", Action: "install", UserSub: "user-A",
			Payload: `{"slug":"user-A/venue-link-matcher","runtime":"local"}`,
			Bearer:  "SECRET-BEARER-JWT", Status: "pending", CreatedAt: now},
		{ID: "intent-uninstall-1", Action: "uninstall", UserSub: "user-A",
			Payload: `{"app":"old-app"}`, Status: "pending", CreatedAt: now},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// --- claim ---
	claim := func() []claimedIntent {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/claim", bytes.NewReader([]byte("{}")))
		req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("claim status %d: %s", w.Code, w.Body.String())
		}
		var out struct {
			Data struct {
				Intents []claimedIntent `json:"intents"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("claim decode: %v", err)
		}
		return out.Data.Intents
	}

	got := claim()
	if len(got) != 2 {
		t.Fatalf("expected 2 claimed, got %d", len(got))
	}
	// Bearer must be merged into payload for the picker.
	var installClaim *claimedIntent
	for i := range got {
		if got[i].IntentID == "intent-install-1" {
			installClaim = &got[i]
		}
	}
	if installClaim == nil {
		t.Fatal("install intent not in claim batch")
	}
	if installClaim.Payload["bearer"] != "SECRET-BEARER-JWT" {
		t.Fatalf("bearer not merged into payload: %v", installClaim.Payload["bearer"])
	}

	// Rows are now claimed → a second claim returns nothing.
	if again := claim(); len(again) != 0 {
		t.Fatalf("second claim should be empty, got %d", len(again))
	}

	// --- result (success) ---
	resBody, _ := json.Marshal(map[string]any{"ok": true, "action": "install", "data": map[string]any{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/intent-install-1/result", bytes.NewReader(resBody))
	req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("result status %d: %s", w.Code, w.Body.String())
	}
	var row models.MeAppIntent
	db.Where("id = ?", "intent-install-1").First(&row)
	if row.Status != "done" || row.CompletedAt == nil {
		t.Fatalf("expected done+completed, got status=%s completed=%v", row.Status, row.CompletedAt)
	}

	// --- pendingInstallCards: done install → a "ready" card (identity can't
	// see the file cross-node, so the DB row is the registry). ---
	cards := pendingInstallCards("user-A", map[string]bool{})
	var found *pendingCard
	for i := range cards {
		if cards[i].name == "venue-link-matcher" {
			found = &cards[i]
		}
	}
	if found == nil {
		t.Fatalf("venue-link-matcher card missing; cards=%+v", cards)
	}
	if found.status != "ready" {
		t.Fatalf("expected ready card, got %q", found.status)
	}

	// --- bridge gate: wrong secret rejected ---
	req = httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/claim", bytes.NewReader([]byte("{}")))
	req.Header.Set("X-Bridge-Secret", "WRONG")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bridge secret should be 401, got %d", w.Code)
	}
}

// TestMeIntentResultFailure — a picker error envelope marks the row failed.
func TestMeIntentResultFailure(t *testing.T) {
	db := setupIntentDB(t)
	os.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", "test-bridge-secret")
	r := bridgeRouter()
	db.Create(&models.MeAppIntent{ID: "intent-fail-1", Action: "install", UserSub: "user-B",
		Payload: `{"slug":"user-B/broken"}`, Status: "claimed", CreatedAt: time.Now()})

	body, _ := json.Marshal(map[string]any{"ok": false, "action": "install", "error": "clone 404"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/intent-fail-1/result", bytes.NewReader(body))
	req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("result status %d: %s", w.Code, w.Body.String())
	}
	var row models.MeAppIntent
	db.Where("id = ?", "intent-fail-1").First(&row)
	if row.Status != "failed" {
		t.Fatalf("expected failed, got %s", row.Status)
	}
	cards := pendingInstallCards("user-B", map[string]bool{})
	if len(cards) != 1 || cards[0].status != "failed" || cards[0].err != "clone 404" {
		t.Fatalf("expected 1 failed card w/ error, got %+v", cards)
	}
}
