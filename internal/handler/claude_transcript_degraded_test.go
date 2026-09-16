package handler

// degraded_turns must count only turns that were MEANT to take a relay hop and
// did not. A central-labelled turn has via_relay=false BY DESIGN — no relay hop
// ever happens for cluster-direct egress — so it must not be counted as silent
// degradation. This pins the exclusion in AdminClaudeFieldBoxes.
//
//	TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//	  go test ./internal/handler -run Degraded

import (
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

func setupDegradedDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping degraded_turns integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.ClaudeSessionTurn{}, &models.ClaudeSession{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	return db
}

func seedDegradedTurn(t *testing.T, db *gorm.DB, fieldBox string, viaRelay bool, ts time.Time) {
	t.Helper()
	row := models.ClaudeSessionTurn{
		ConvKey:   "degraded-test-" + fieldBox,
		TurnIndex: 1,
		Ts:        ts,
		FieldBox:  fieldBox,
		ViaRelay:  viaRelay,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed turn field_box=%q via_relay=%v: %v", fieldBox, viaRelay, err)
	}
	t.Cleanup(func() { db.Unscoped().Where("conv_key = ?", row.ConvKey).Delete(&models.ClaudeSessionTurn{}) })
}

func getFieldBoxes(t *testing.T) map[string]interface{} {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin/claude/field-boxes", AdminClaudeFieldBoxes)
	req := httptest.NewRequest(http.MethodGet, "/admin/claude/field-boxes?hours=24", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("AdminClaudeFieldBoxes status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Data struct {
			Totals struct {
				DegradedTurns int64 `json:"degraded_turns"`
			} `json:"totals"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return map[string]interface{}{"degraded": body.Data.Totals.DegradedTurns}
}

// The fixture must contain BOTH a central turn AND a genuinely-degraded box
// turn, and assert the count equals the latter only. A fixture with only
// central rows would pass against a hardcoded zero — the "fixture too clean to
// fail" trap. The non-central case still counting is the positive control.
func TestDegradedTurnsExcludesCentral(t *testing.T) {
	db := setupDegradedDB(t)
	now := time.Now().UTC()

	// A central turn: via_relay=false by design, must NOT count as degraded.
	seedDegradedTurn(t, db, ClaudeCentralLabel, false, now.Add(-time.Hour))
	// A genuinely-degraded box turn: meant to hop, did not. MUST count.
	seedDegradedTurn(t, db, "denmark", false, now.Add(-time.Hour))
	// A healthy box turn: hopped as intended. Must not count.
	seedDegradedTurn(t, db, "denmark", true, now.Add(-time.Hour))

	got := getFieldBoxes(t)
	if got["degraded"].(int64) != 1 {
		t.Fatalf("degraded_turns = %d, want 1 (only the denmark non-relay turn; "+
			"the central turn and the healthy denmark turn must be excluded)", got["degraded"])
	}
}

// Positive control in isolation: with no central rows at all, a non-relay box
// turn still counts. Guards against the exclusion accidentally swallowing the
// whole signal (e.g. a WHERE that drops every non-relay turn). A healthy
// relayed turn is seeded too, because the degraded count is gated on the
// signal cutoff existing — without any via_relay=true row the handler
// legitimately reports nothing, which would make this test vacuous.
func TestDegradedTurnsStillCountsNonCentral(t *testing.T) {
	db := setupDegradedDB(t)
	now := time.Now().UTC()

	seedDegradedTurn(t, db, "chicago", false, now.Add(-time.Hour))
	seedDegradedTurn(t, db, "chicago", true, now.Add(-time.Hour))

	got := getFieldBoxes(t)
	if got["degraded"].(int64) != 1 {
		t.Fatalf("degraded_turns = %d, want 1 (a non-relay chicago turn must still count)", got["degraded"])
	}
}
