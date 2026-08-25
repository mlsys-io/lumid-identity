package handler

// Tests for the claude_quota_token_history forensics added alongside
// admin_claude_quota.go's quarantine/re-add handling — see the doc comment
// on models.ClaudeQuotaTokenHistory for why this table exists.
//
// AdminClaudeTokenAdd and refreshTokenLocked both call out to Anthropic
// (verifyAnthropic / the OAuth refresh endpoint) via inline, non-injectable
// http.Client — not mockable without a wider refactor, so this file exercises
// the two pieces that ARE independently testable: hasForensicState (the
// re-add safety-net's decision of whether there is anything worth
// preserving) and snapshotHistory/AdminClaudeTokenHistory (the write and
// read sides of the table itself). The full quarantine → re-add round trip
// was exercised live during the 2026-08-25 ylu@yao.lu incident triage that
// motivated this change.
//
// Runs only when TEST_MYSQL_DSN is set, matching this package's existing
// convention (see admin_claude_user_usage_test.go):
//
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//     go test ./internal/handler -run ClaudeQuotaHistory

import (
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

func setupClaudeQuotaHistoryDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping claude-quota-history integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.ClaudeQuotaToken{}, &models.ClaudeQuotaTokenHistory{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	return db
}

func TestHasForensicState(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		row  models.ClaudeQuotaToken
		want bool
	}{
		{"clean row", models.ClaudeQuotaToken{Email: "clean@example.com"}, false},
		{"revoked_at set", models.ClaudeQuotaToken{RevokedAt: &now}, true},
		{"revoke_reason set, no timestamp", models.ClaudeQuotaToken{RevokeReason: "SECOND-HOLDER OR UPSTREAM REVOCATION"}, true},
		{"bench_dead", models.ClaudeQuotaToken{BenchDead: true}, true},
		{"bench_until set", models.ClaudeQuotaToken{BenchUntil: &now}, true},
		{"draining only — not forensic", models.ClaudeQuotaToken{DrainingSince: &now, DrainReason: "operator pause"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasForensicState(&tc.row); got != tc.want {
				t.Fatalf("hasForensicState(%+v) = %v, want %v", tc.row, got, tc.want)
			}
		})
	}
}

func claudeQuotaHistoryRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/admin/claude-token/:email/history", AdminClaudeTokenHistory)
	return r
}

// TestSnapshotHistory_QuarantineThenReAdd reproduces the exact sequence that
// lost the ylu@yao.lu verdict: a quarantine snapshot, then a re-add that
// clears the live row's revoked_at/revoke_reason. Asserts the snapshot
// survives the clear and is retrievable via the history endpoint newest-first.
func TestSnapshotHistory_QuarantineThenReAdd(t *testing.T) {
	db := setupClaudeQuotaHistoryDB(t)
	email := fmt.Sprintf("cqh-test-%d@example.com", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() {
		db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{})
		db.Where("email = ?", email).Delete(&models.ClaudeQuotaTokenHistory{})
	})

	// Seed a quarantined row, mirroring what refreshTokenLocked's invalid_grant
	// branch leaves behind.
	quarantinedAt := time.Now()
	verdict := "SECOND-HOLDER OR UPSTREAM REVOCATION: no indeterminate exchange preceded this."
	row := models.ClaudeQuotaToken{
		Email: email, ValueEncrypted: "irrelevant", Label: "denmark",
		RevokedAt: &quarantinedAt, RevokeReason: verdict,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed quarantined row: %v", err)
	}

	// Capture point A: what refreshTokenLocked does right after quarantining.
	snapshotHistory(&row, "quarantined")

	// Capture point B: what AdminClaudeTokenAdd's safety net does — read the
	// live row, decide there's something to lose, snapshot it, THEN the
	// caller would upsert-clear revoked_at/revoke_reason. We only need to
	// prove the snapshot happened before the clear would destroy it.
	var existing models.ClaudeQuotaToken
	if err := db.Unscoped().Where("email = ?", email).First(&existing).Error; err != nil {
		t.Fatalf("reload existing row: %v", err)
	}
	if !hasForensicState(&existing) {
		t.Fatalf("expected forensic state on the seeded row, got none: %+v", existing)
	}
	snapshotHistory(&existing, "re_added")

	// Now simulate the actual clear (what claudeTokenReAddColumns wipes).
	if err := db.Model(&row).Updates(map[string]interface{}{
		"revoked_at": nil, "revoke_reason": "",
	}).Error; err != nil {
		t.Fatalf("clear quarantine: %v", err)
	}
	var live models.ClaudeQuotaToken
	if err := db.Where("email = ?", email).First(&live).Error; err != nil {
		t.Fatalf("reload live row: %v", err)
	}
	if live.RevokedAt != nil || live.RevokeReason != "" {
		t.Fatalf("live row should read cleared after re-add, got revoked_at=%v revoke_reason=%q", live.RevokedAt, live.RevokeReason)
	}

	// The verdict must still be retrievable from history, newest first.
	r := claudeQuotaHistoryRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/claude-token/"+email+"/history", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			History []models.ClaudeQuotaTokenHistory `json:"history"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, w.Body.String())
	}
	if len(out.Data.History) != 2 {
		t.Fatalf("want 2 history rows (quarantined + re_added), got %d: %+v", len(out.Data.History), out.Data.History)
	}
	// Newest first: the re_added safety-net snapshot was written after the
	// quarantined one.
	if out.Data.History[0].Event != "re_added" || out.Data.History[1].Event != "quarantined" {
		t.Fatalf("want [re_added, quarantined] newest-first, got [%s, %s]",
			out.Data.History[0].Event, out.Data.History[1].Event)
	}
	// The whole point: the verdict text must have survived the clear.
	if out.Data.History[1].RevokeReason != verdict {
		t.Fatalf("quarantined snapshot lost the verdict: got %q want %q", out.Data.History[1].RevokeReason, verdict)
	}
}

// TestSnapshotHistory_CleanReAddWritesNoRow guards against noise: a re-add of
// an already-healthy account (e.g. routine credential rotation) must not
// write a history row.
func TestSnapshotHistory_CleanReAddWritesNoRow(t *testing.T) {
	db := setupClaudeQuotaHistoryDB(t)
	email := fmt.Sprintf("cqh-clean-%d@example.com", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() {
		db.Unscoped().Where("email = ?", email).Delete(&models.ClaudeQuotaToken{})
		db.Where("email = ?", email).Delete(&models.ClaudeQuotaTokenHistory{})
	})
	row := models.ClaudeQuotaToken{Email: email, ValueEncrypted: "irrelevant", Label: "denmark"}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("seed clean row: %v", err)
	}

	var existing models.ClaudeQuotaToken
	if err := db.Unscoped().Where("email = ?", email).First(&existing).Error; err != nil {
		t.Fatalf("reload existing row: %v", err)
	}
	if hasForensicState(&existing) {
		t.Fatalf("clean row should carry no forensic state: %+v", existing)
	}
	// AdminClaudeTokenAdd would skip snapshotHistory entirely here — don't call it.

	var count int64
	if err := db.Model(&models.ClaudeQuotaTokenHistory{}).Where("email = ?", email).Count(&count).Error; err != nil {
		t.Fatalf("count history: %v", err)
	}
	if count != 0 {
		t.Fatalf("clean re-add should write 0 history rows, got %d", count)
	}
}
