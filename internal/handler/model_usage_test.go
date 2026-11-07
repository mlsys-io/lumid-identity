package handler

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

func TestModelUsageUpsertAndSummary(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	releaseTestDBOnCleanup(t, db)
	db.Migrator().DropTable(&models.ModelUsageMinute{})
	if err := db.AutoMigrate(&models.ModelUsageMinute{}); err != nil {
		t.Fatal(err)
	}
	common.DB = db
	os.Setenv("SOC_RELAY_STATUS_URL", "http://127.0.0.1:1/status") // relay down: live must be null, not an error
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/u", InternalModelUsage)
	r.GET("/s", AdminModelUsage)
	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute).Unix()
	for i := 0; i < 2; i++ {
		b, _ := json.Marshal(map[string]interface{}{"rows": []map[string]interface{}{{
			"source": "claude", "model": "claude-sonnet-5", "minute": minute,
			"requests": 3, "streams": 3, "in_tokens": 9000, "out_tokens": 900, "gen_ms": 15000, "ttft_ms": 3000,
		}}})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/u", bytes.NewReader(b)))
		if w.Code != 200 {
			t.Fatalf("ingest %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/s?minutes=60", nil))
	var resp struct {
		Data struct {
			Summary []socUsageSummary `json:"summary"`
			Live    any               `json:"live"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != 200 || len(resp.Data.Summary) != 1 || resp.Data.Live != nil {
		t.Fatalf("resp %d %s", w.Code, w.Body.String())
	}
	s := resp.Data.Summary[0]
	if s.Requests != 6 || s.StreamTPS != 60 || s.AggOutTPS != 6 || s.AvgTTFTMs != 1000 {
		t.Fatalf("summary %+v", s)
	}
}
