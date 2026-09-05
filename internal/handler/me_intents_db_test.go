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

// staleClaimAfter re-queues a claimed-but-uncompleted intent on the assumption
// that the PICKER died for reasons unrelated to the intent. When the intent's
// own work is what kills the picker, that assumption inverts and the retry
// becomes a poison pill. Observed 2026-08-12: one venue-link-matcher.match_cycle
// run_loop intent OOM-killed lumid-scheduler 13 times over ~2h — one kill per
// reclaim — taking every other in-flight loop down with it each time, until an
// operator marked it failed by hand.
//
// This pins the bound: after maxClaimAttempts claims with no result, the intent
// is abandoned rather than re-queued.
func TestMeIntentQueuePoisonPillIsAbandoned(t *testing.T) {
	db := setupIntentDB(t)
	r := bridgeRouter()

	claim := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/claim", bytes.NewReader([]byte("{}")))
		req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("claim status %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Data struct {
				Intents []claimedIntent `json:"intents"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return len(body.Data.Intents)
	}

	if err := db.Create(&models.MeAppIntent{
		ID: "intent-poison", Action: "run_loop", UserSub: "user-A",
		Payload: `{"app":"venue-link-matcher","loop":"match_cycle"}`,
		Status:  "pending", CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Simulate the loop: claim, picker dies without reporting, claim goes stale.
	for i := 1; i <= maxClaimAttempts; i++ {
		if n := claim(); n != 1 {
			t.Fatalf("attempt %d: claimed %d intents, want 1", i, n)
		}
		var row models.MeAppIntent
		if err := db.First(&row, "id = ?", "intent-poison").Error; err != nil {
			t.Fatalf("attempt %d: reload: %v", i, err)
		}
		if row.Attempts != i {
			t.Fatalf("attempt %d: attempts=%d, want %d — the counter must advance on CLAIM, "+
				"since a picker that dies never reports", i, row.Attempts, i)
		}
		// Back-date the claim so the next poll treats it as a crashed picker.
		if err := db.Model(&models.MeAppIntent{}).Where("id = ?", "intent-poison").
			Update("claimed_at", time.Now().Add(-staleClaimAfter-time.Minute)).Error; err != nil {
			t.Fatalf("attempt %d: backdate: %v", i, err)
		}
	}

	// The next poll must abandon it, not hand it out again.
	if n := claim(); n != 0 {
		t.Fatalf("poison pill was re-dispatched after %d attempts (claimed %d) — the loop is unbounded",
			maxClaimAttempts, n)
	}
	var row models.MeAppIntent
	if err := db.First(&row, "id = ?", "intent-poison").Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.Status != "failed" {
		t.Fatalf("status=%q, want %q — an abandoned intent must be terminal, not left claimed/pending", row.Status, "failed")
	}
	if row.CompletedAt == nil {
		t.Fatal("abandoned intent must carry completed_at, or it reads as still in flight")
	}
	if row.Result == "" {
		t.Fatal("abandoned intent must record WHY, or the user sees a silent failure")
	}
}

// A healthy intent must not be abandoned: attempts advance on claim, but a
// reported result ends the lifecycle well before the bound.
func TestMeIntentQueueHealthyIntentUnaffected(t *testing.T) {
	db := setupIntentDB(t)
	r := bridgeRouter()

	if err := db.Create(&models.MeAppIntent{
		ID: "intent-ok", Action: "run_loop", UserSub: "user-A",
		Payload: `{"app":"x","loop":"y"}`, Status: "pending", CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/claim", bytes.NewReader([]byte("{}")))
	req.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("claim status %d", w.Code)
	}

	res := httptest.NewRequest(http.MethodPost, "/api/v1/internal/me-intents/intent-ok/result",
		bytes.NewReader([]byte(`{"ok":true}`)))
	res.Header.Set("X-Bridge-Secret", "test-bridge-secret")
	res.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, res)
	if w2.Code != 200 {
		t.Fatalf("result status %d: %s", w2.Code, w2.Body.String())
	}

	var row models.MeAppIntent
	if err := db.First(&row, "id = ?", "intent-ok").Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if row.Status != "done" {
		t.Fatalf("status=%q, want done — the guard must not disturb the happy path", row.Status)
	}
	if row.Attempts != 1 {
		t.Fatalf("attempts=%d, want 1", row.Attempts)
	}
}

// MeIntentGet is scoped to the CALLER's intents: matching on id alone let any
// authenticated user who learned an intent UUID read another user's intent
// (payloads carry app names, loop args and run subjects). A foreign id must
// behave exactly like a nonexistent one.
func TestIntentLookupIsCallerScoped(t *testing.T) {
	db := setupIntentDB(t)
	row := models.MeAppIntent{
		ID: "11111111-2222-4333-8444-555555555555", Action: "run_loop",
		UserSub: "user-a", Payload: `{"app":"quant-research"}`,
		Status: "pending", CreatedAt: time.Now(),
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	var got models.MeAppIntent
	// The exact query MeIntentGet issues, for the wrong caller:
	err := db.Where("id = ? AND user_sub = ?", row.ID, "user-b").First(&got).Error
	if err == nil {
		t.Fatal("user-b read user-a's intent — the scoping is gone")
	}
	// And for the owner:
	if err := db.Where("id = ? AND user_sub = ?", row.ID, "user-a").First(&got).Error; err != nil {
		t.Fatalf("owner could not read their own intent: %v", err)
	}
}
