package handler

// Integration test for AdminClaudeUserUsage's fixed-window bulk JOIN
// (internal/handler/admin_claude_quota.go) against a throwaway MySQL — the
// highest-complexity new SQL introduced by the hard-window quota redesign
// (internal/common/quota.go). Runs only when TEST_MYSQL_DSN is set, matching
// this package's existing convention (see me_intents_db_test.go):
//
//   TEST_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/test?parseTime=true' \
//     go test ./internal/handler -run AdminClaudeUserUsage

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

func setupAdminClaudeUsageDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping admin claude-user-usage integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Token{}, &models.UsageEvent{}, &models.ClaudePoolWindow{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	return db
}

func adminClaudeUsageRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/admin/claude-user-usage", AdminClaudeUserUsage)
	return r
}

// TestAdminClaudeUserUsage_FixedWindowJoin seeds three users in the three
// states the fixed-window cutover produces:
//   - a LIVE window with events both inside and outside the 5h sub-window
//   - an EXPIRED (never-rolled) window, surfaced only via a recent PAT
//   - PRE-CUTOVER history with no claude_pool_windows row at all
//
// and asserts the bulk JOIN reproduces exactly what ClaudePoolUsage would
// compute per-user (anchor-bounded sums, blank reset for idle windows,
// pre-cutover users excluded).
func TestAdminClaudeUserUsage_FixedWindowJoin(t *testing.T) {
	db := setupAdminClaudeUsageDB(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	liveSub := "au-live-" + suffix
	expiredSub := "au-expired-" + suffix
	precutoverSub := "au-precut-" + suffix

	t.Cleanup(func() {
		for _, sub := range []string{liveSub, expiredSub, precutoverSub} {
			db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
			db.Where("user_sub = ?", sub).Delete(&models.ClaudePoolWindow{})
			db.Where("user_id = ?", sub).Delete(&models.Token{})
			db.Where("id = ?", sub).Delete(&models.User{})
		}
	})

	now := time.Now().UTC()
	users := []models.User{
		{ID: liveSub, Email: liveSub + "@example.com", Role: "user", Status: "active"},
		{ID: expiredSub, Email: expiredSub + "@example.com", Role: "user", Status: "active"},
		{ID: precutoverSub, Email: precutoverSub + "@example.com", Role: "user", Status: "active"},
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatalf("seed users: %v", err)
	}

	// --- liveSub: both windows live. five_hour_anchor opened 1h ago (4h
	// left); seven_day_anchor opened 3d ago (4d left, well before the 5h
	// anchor). One event before the 5h anchor but after the 7d anchor
	// (counts toward seven only); one event after the 5h anchor (counts
	// toward both).
	liveWin := models.ClaudePoolWindow{
		UserSub: liveSub, FiveHourAnchor: now.Add(-1 * time.Hour), SevenDayAnchor: now.Add(-3 * 24 * time.Hour),
	}
	if err := db.Create(&liveWin).Error; err != nil {
		t.Fatalf("seed live window: %v", err)
	}
	liveEvents := []models.UsageEvent{
		{UserSub: liveSub, Ts: now.Add(-2 * 24 * time.Hour), Kind: "claude_proxy", Model: "claude-sonnet-5", InputTokens: 400, OutputTokens: 100},
		{UserSub: liveSub, Ts: now.Add(-30 * time.Minute), Kind: "claude_proxy", Model: "claude-sonnet-5", InputTokens: 700, OutputTokens: 300},
	}
	if err := db.Create(&liveEvents).Error; err != nil {
		t.Fatalf("seed live events: %v", err)
	}

	// --- expiredSub: both windows fully expired (never rolled forward —
	// simulates a user who hasn't made a claude_proxy call since expiry).
	// Give them a recent claude:proxy PAT so they still surface via the
	// PAT-holder merge, but with zeroed usage and blank resets.
	expiredWin := models.ClaudePoolWindow{
		UserSub: expiredSub, FiveHourAnchor: now.Add(-48 * time.Hour), SevenDayAnchor: now.Add(-30 * 24 * time.Hour),
	}
	if err := db.Create(&expiredWin).Error; err != nil {
		t.Fatalf("seed expired window: %v", err)
	}
	// Stale events predating the (also expired) anchors — must NOT count.
	staleEvent := models.UsageEvent{UserSub: expiredSub, Ts: now.Add(-49 * time.Hour), Kind: "claude_proxy", Model: "claude-sonnet-5", InputTokens: 999, OutputTokens: 0}
	if err := db.Create(&staleEvent).Error; err != nil {
		t.Fatalf("seed stale event: %v", err)
	}
	expiredLastUsed := now.Add(-10 * time.Minute)
	expiredToken := models.Token{
		ID: "tok-" + expiredSub, UserID: expiredSub, Prefix: "lm_", Hash: "irrelevant-" + expiredSub,
		Scopes: "claude:proxy", LastUsedAt: &expiredLastUsed, CreatedAt: now.Add(-100 * 24 * time.Hour),
	}
	if err := db.Create(&expiredToken).Error; err != nil {
		t.Fatalf("seed expired-user token: %v", err)
	}

	// --- precutoverSub: real usage_events history but NO claude_pool_windows
	// row at all — the state every user is in immediately after this
	// feature deploys, before their next real charge opens a fresh anchor.
	precutoverEvent := models.UsageEvent{UserSub: precutoverSub, Ts: now.Add(-1 * time.Hour), Kind: "claude_proxy", Model: "claude-sonnet-5", InputTokens: 500, OutputTokens: 0}
	if err := db.Create(&precutoverEvent).Error; err != nil {
		t.Fatalf("seed pre-cutover event: %v", err)
	}

	r := adminClaudeUsageRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/claude-user-usage", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	type userRow struct {
		Email         string  `json:"email"`
		FiveHour      int     `json:"five_hour_tokens"`
		SevenDay      int     `json:"seven_day_tokens"`
		FiveHourReset string  `json:"five_hour_reset"`
		SevenDayReset string  `json:"seven_day_reset"`
		FiveHourPct   float64 `json:"five_hour_pct"`
	}
	var out struct {
		Data struct {
			Users []userRow `json:"users"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, w.Body.String())
	}

	byEmail := map[string]userRow{}
	for _, u := range out.Data.Users {
		byEmail[u.Email] = u
	}

	// liveSub: five=700+300=1000 (only the -30min event), seven=400+100+700+300=1500.
	live, ok := byEmail[liveSub+"@example.com"]
	if !ok {
		t.Fatalf("live user missing from results: %+v", out.Data.Users)
	}
	if live.FiveHour != 1000 {
		t.Fatalf("live user five_hour_tokens=%d want 1000", live.FiveHour)
	}
	if live.SevenDay != 1500 {
		t.Fatalf("live user seven_day_tokens=%d want 1500", live.SevenDay)
	}
	if live.FiveHourReset == "" || live.SevenDayReset == "" {
		t.Fatalf("live user should have both resets populated, got five=%q seven=%q", live.FiveHourReset, live.SevenDayReset)
	}
	if parsed, err := time.Parse(time.RFC3339, live.FiveHourReset); err != nil || !parsed.After(now) {
		t.Fatalf("live user five_hour_reset=%q should parse as a future instant: err=%v", live.FiveHourReset, err)
	}

	// expiredSub: surfaced only via the PAT-holder merge, zeroed, no resets —
	// the stale pre-expiry event must not leak into the sum.
	expired, ok := byEmail[expiredSub+"@example.com"]
	if !ok {
		t.Fatalf("expired-but-PAT-holding user missing from results: %+v", out.Data.Users)
	}
	if expired.FiveHour != 0 || expired.SevenDay != 0 {
		t.Fatalf("expired user should read zero usage (idle window), got five=%d seven=%d", expired.FiveHour, expired.SevenDay)
	}
	if expired.FiveHourReset != "" || expired.SevenDayReset != "" {
		t.Fatalf("expired user should have blank resets (idle), got five=%q seven=%q", expired.FiveHourReset, expired.SevenDayReset)
	}

	// precutoverSub: no anchor row at all → excluded entirely, not a zeroed row.
	if _, ok := byEmail[precutoverSub+"@example.com"]; ok {
		t.Fatalf("pre-cutover user (no anchor row) should be excluded from results entirely, found: %+v", byEmail[precutoverSub+"@example.com"])
	}
}
