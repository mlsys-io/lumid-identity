package handler

// End-to-end through the HTTP handler claude-proxy actually calls. The Opus cap
// shipped in v0.5.469 was computed correctly by CheckAndCharge but DROPPED here
// (this handler builds its response map field by field), so the cap was inert
// in prod while the CheckAndCharge-level test passed. This pins the wire.
//
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' go test ./internal/handler -run InternalChargeOpus

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestInternalChargeOpusFieldsOnTheWire(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.User{}, &models.UsageEvent{}, &models.ClaudePoolWindow{}, &models.ClaudeRecordingPref{}); err != nil {
		t.Fatal(err)
	}
	common.DB = db
	t.Setenv("LUMID_QUOTA_CLAUDE_5H_TOKENS", "45000000")
	t.Setenv("LUMID_QUOTA_CLAUDE_7D_TOKENS", "500000000")
	sub := "00000000-0000-4000-8000-0000000c0de5"
	db.Where("id = ?", sub).Delete(&models.User{})
	db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
	db.Where("user_sub = ?", sub).Delete(&models.ClaudePoolWindow{})
	if err := db.Create(&models.User{ID: sub, Email: "opus-wire@test.local", Role: "admin", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	db.Create(&models.ClaudePoolWindow{UserSub: sub, FiveHourAnchor: now.Add(-time.Hour), SevenDayAnchor: now.Add(-72 * time.Hour)})
	db.Create(&models.UsageEvent{UserSub: sub, Ts: now.Add(-48 * time.Hour), Kind: "claude_proxy", Model: "claude-opus-5-5", InputTokens: 155_000_000})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/charge", InternalUsageCharge)
	b, _ := json.Marshal(map[string]any{"user_sub": sub, "kind": "claude_proxy", "model": "", "dry_run": true})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/charge", bytes.NewReader(b)))
	var resp struct {
		Data map[string]any `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	d := resp.Data
	if d["opus_exhausted"] != true || d["opus_window"] != "7d" || d["opus_seven_day_limit"] != float64(150_000_000) || d["opus_reset"] == "" || d["allowed"] != true {
		t.Fatalf("opus fields missing/wrong on the wire: %s", w.Body.String())
	}
	db.Where("id = ?", sub).Delete(&models.User{})
	db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
	db.Where("user_sub = ?", sub).Delete(&models.ClaudePoolWindow{})
}
