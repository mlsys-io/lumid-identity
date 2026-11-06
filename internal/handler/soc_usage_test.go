package handler

// MySQL integration test for the SoC usage upsert + TKPS summary.
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' go test ./internal/handler -run SocUsage

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

func TestSocUsageUpsertAndSummary(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	releaseTestDBOnCleanup(t, db)
	db.Migrator().DropTable(&models.SocKeyUsage{})
	if err := db.AutoMigrate(&models.SocKeyUsage{}); err != nil {
		t.Fatal(err)
	}
	common.DB = db
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/u", InternalSocKeyUsage)
	r.GET("/s", AdminSocKeysUsage)

	minute := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute).Unix()
	post := func(out int64, gen int64) {
		b, _ := json.Marshal(map[string]interface{}{"rows": []map[string]interface{}{{
			"key_id": 5, "model": "deepseek-v4.1-flash", "minute": minute,
			"requests": 2, "streams": 2, "in_tokens": 100, "out_tokens": out, "gen_ms": gen, "ttft_ms": 400,
		}}})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/u", bytes.NewReader(b)))
		if w.Code != 200 {
			t.Fatalf("ingest %d %s", w.Code, w.Body.String())
		}
	}
	post(600, 10000) // replica A
	post(600, 10000) // replica B, same (key, model, minute) -> summed

	var row models.SocKeyUsage
	db.First(&row)
	if row.Requests != 4 || row.OutTokens != 1200 || row.GenMs != 20000 {
		t.Fatalf("upsert did not sum: %+v", row)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/s?minutes=60", nil))
	var resp struct {
		Data struct {
			Summary []socUsageSummary `json:"summary"`
			Today   []socKeyToday     `json:"keys_today"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Data.Summary) != 1 {
		t.Fatalf("summary: %s", w.Body.String())
	}
	s := resp.Data.Summary[0]
	if s.StreamTPS != 60 || s.AggOutTPS != 4 || s.AvgTTFTMs != 200 {
		t.Fatalf("tps math: %+v", s)
	}
	if len(resp.Data.Today) != 1 || resp.Data.Today[0].OutTokens != 1200 {
		t.Fatalf("today: %+v", resp.Data.Today)
	}
}
