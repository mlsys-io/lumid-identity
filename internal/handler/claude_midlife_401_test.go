package handler

// The at-risk signal must fire from the SERVING path, while the account still
// works — not from the snapshot probe, which discovers the problem minutes
// later and usually only once it is already too late to act.
//
// pre_expiry_401_at had one writer: refreshSnapshot, which stamps it
// immediately before tryRefreshToken. When the refresh then fails, the marker
// and the quarantine are written in the same call — at_risk and quarantined go
// 0 -> 1 together and nobody is paged during the window when "find the other
// holder" is still cheap advice. And because that branch is gated on
// jwtExpiry() proving the token had life left, our own 45-minute sweep means
// the probe usually meets an already-expired token and the signal is never
// written at all.
//
// Measured on 2026-08-21: both quarantine lines read caller=snapshot-probe with
// NO (pre-expiry-401) marker, at_risk was 0 throughout, and claude-proxy had
// seen ac2@nati refused at 19:28:41 — 4m14s before identity found out.
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run MidLife401

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

func setupMidLifeDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping mid-life-401 integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.ClaudeQuotaToken{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	return db
}

func midLifeRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/internal/claude-account/mid-life-401", InternalClaudeAccountMidLife401)
	return r
}

func postMidLife(t *testing.T, email string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email":  email,
		"detail": `{"type":"authentication_error","message":"OAuth access token has been revoked."}`,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/claude-account/mid-life-401", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	midLifeRouter().ServeHTTP(w, req)
	return w
}

func seedLiveAccount(t *testing.T, db *gorm.DB, email string, revoked bool) {
	t.Helper()
	db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{})
	t.Cleanup(func() { db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}) })
	row := models.ClaudeQuotaToken{Email: email, ValueEncrypted: "enc", RefreshTokenEncrypted: "ref"}
	if revoked {
		at := time.Now().Add(-time.Minute)
		row.RevokedAt, row.RevokeReason = &at, "invalid_grant"
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestMidLife401RaisesAtRiskWhileStillServing(t *testing.T) {
	db := setupMidLifeDB(t)
	const email = "midlife-live@test"
	seedLiveAccount(t, db, email, false)

	if w := postMidLife(t, email); w.Code != http.StatusOK {
		t.Fatalf("report returned %d: %s", w.Code, w.Body.String())
	}

	var row models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&row).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.PreExpiry401At == nil {
		t.Fatal("pre_expiry_401_at not set — the serving-path signal was dropped")
	}
	if row.PreExpiry401Reason == "" {
		t.Error("pre_expiry_401_reason empty — the operator has nothing to act on")
	}
	// The whole point: the EXISTING at-risk alert must now fire for this row.
	if !preExpiry401Recent(&row, time.Now()) {
		t.Error("preExpiry401Recent = false — at_risk_accounts[] would stay empty, which is the 2026-08-21 failure")
	}
	// And it must NOT have quarantined or benched anything.
	if row.RevokedAt != nil || row.BenchUntil != nil {
		t.Errorf("signal-only endpoint changed pool state: revoked=%v bench=%v", row.RevokedAt, row.BenchUntil)
	}
}

func TestMidLife401SkipsAlreadyQuarantined(t *testing.T) {
	db := setupMidLifeDB(t)
	const email = "midlife-dead@test"
	seedLiveAccount(t, db, email, true)

	w := postMidLife(t, email)
	if w.Code != http.StatusOK {
		t.Fatalf("returned %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Recorded bool `json:"recorded"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Recorded {
		t.Error("recorded a signal on an already-quarantined family — it would restart the 6h at-risk window on a dead account")
	}
	var row models.ClaudeQuotaToken
	db.Where("email = ?", email).First(&row)
	if row.PreExpiry401At != nil {
		t.Error("pre_expiry_401_at stamped on a quarantined account")
	}
}

func TestMidLife401BurstLogsOnceButKeepsTheWindowAlive(t *testing.T) {
	db := setupMidLifeDB(t)
	const email = "midlife-burst@test"
	seedLiveAccount(t, db, email, false)

	first := postMidLife(t, email)
	second := postMidLife(t, email)
	for i, w := range []*httptest.ResponseRecorder{first, second} {
		if w.Code != http.StatusOK {
			t.Fatalf("report %d returned %d", i+1, w.Code)
		}
	}
	var r1, r2 struct {
		Recorded bool `json:"recorded"`
		Fresh    bool `json:"fresh"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &r1)
	_ = json.Unmarshal(second.Body.Bytes(), &r2)
	if !r1.Fresh {
		t.Error("first report not marked fresh — it would never be logged")
	}
	if r2.Fresh {
		t.Error("second report marked fresh — a 401 burst would spam the log once per request")
	}
	if !r2.Recorded {
		t.Error("second report not recorded — re-stamping is what keeps the alert alive while the condition persists")
	}
}

func TestMidLife401IgnoresRemovedAccount(t *testing.T) {
	db := setupMidLifeDB(t)
	const email = "midlife-removed@test"
	seedLiveAccount(t, db, email, false)
	db.Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}) // tombstone

	if w := postMidLife(t, email); w.Code != http.StatusNotFound {
		t.Errorf("removed account returned %d, want 404 — a tombstone is not a pool member", w.Code)
	}
}

func TestMidLife401RejectsEmptyEmail(t *testing.T) {
	setupMidLifeDB(t)
	body, _ := json.Marshal(map[string]string{"email": "  ", "detail": "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/claude-account/mid-life-401", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	midLifeRouter().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("empty email returned %d, want 400", w.Code)
	}
}
