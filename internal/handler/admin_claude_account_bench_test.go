package handler

// Regression test for the 2026-08-19 fix: InternalClaudeAccountBench must clear
// bench_dead when the proxy reports a live success (seconds<=0), not just an
// ordinary probe bench. See the doc comment on InternalClaudeAccountBench for
// the incident this pins: ac2@nati was falsely marked bench_dead on a stale
// sticky-cached token, kept serving real 200s the whole time, and — because the
// old code held "dead" open forever pending a manual re-add — an operator
// reading the stale dashboard state deleted a perfectly healthy account and
// took the pool down to a single quota-exhausted account.
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run AccountBench

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func setupAccountBenchDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping claude-account/bench integration test")
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

func accountBenchRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/internal/claude-account/bench", InternalClaudeAccountBench)
	return r
}

func postBench(t *testing.T, r *gin.Engine, email string, seconds int, dead bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"email": email, "seconds": seconds, "dead": dead, "reason": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/claude-account/bench", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// TestAccountBench_SuccessClearsDeadBench is the core regression: a reported
// success (seconds<=0) must release a bench_dead=true row, exactly as it
// already released an ordinary (non-dead) bench.
func TestAccountBench_SuccessClearsDeadBench(t *testing.T) {
	db := setupAccountBenchDB(t)
	email := fmt.Sprintf("bench-dead-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() { db.Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}) })

	until := time.Now().Add(6 * time.Hour)
	if err := db.Create(&models.ClaudeQuotaToken{
		Email: email, ValueEncrypted: "x", RefreshTokenEncrypted: "y",
		BenchUntil: &until, BenchReason: "claude-proxy: upstream HTTP 401", BenchDead: true,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := accountBenchRouter()
	w := postBench(t, r, email, 0, false) // proxy's success-report shape
	if w.Code != http.StatusOK {
		t.Fatalf("release: status=%d body=%s", w.Code, w.Body.String())
	}

	var got models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.BenchDead {
		t.Error("bench_dead still true after a reported success — the dashboard would keep telling an operator to re-add a live account")
	}
	if got.BenchUntil != nil {
		t.Errorf("bench_until still set: %v", got.BenchUntil)
	}
}

// TestAccountBench_DeadStreakStillEscalates makes sure the fix above didn't
// weaken the other half: a genuine 3rd consecutive auth failure must still
// persist bench_dead=true (only a PROVEN success clears it).
func TestAccountBench_DeadStreakStillEscalates(t *testing.T) {
	db := setupAccountBenchDB(t)
	email := fmt.Sprintf("bench-escalate-%d@example.com", time.Now().UnixNano())
	t.Cleanup(func() { db.Where("email = ?", email).Delete(&models.ClaudeQuotaToken{}) })

	if err := db.Create(&models.ClaudeQuotaToken{Email: email, ValueEncrypted: "x", RefreshTokenEncrypted: "y"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := accountBenchRouter()
	w := postBench(t, r, email, 21600, true) // 6h dead bench, as claude-proxy sends on streak==3
	if w.Code != http.StatusOK {
		t.Fatalf("bench: status=%d body=%s", w.Code, w.Body.String())
	}

	var got models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !got.BenchDead {
		t.Fatal("bench_dead not set after a dead-streak report")
	}
	if got.BenchUntil == nil || !got.BenchUntil.After(time.Now()) {
		t.Errorf("bench_until not in the future: %v", got.BenchUntil)
	}
}
