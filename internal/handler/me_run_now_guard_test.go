package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

func TestRunNowScopesAllow(t *testing.T) {
	for scopes, want := range map[string]bool{
		"*":                        true,
		"lumid:read lumid:write":   true,
		"flowmesh:workflows:write": true,
		"lumid:run":                true,
		"lqt:strategy":             false, // the measured case
		"claude:proxy":             false,
		"lumid:read":               false,
		"lumid:read lumid:strategy lqt:strategy lqt:trading": false,
		"": false,
	} {
		if got := runNowScopesAllow(scopes); got != want {
			t.Errorf("%q: got %v, want %v", scopes, got, want)
		}
	}
}

func TestRunNowRetryCountsDownToTheWindow(t *testing.T) {
	now := time.Now()
	if got := runNowRetry(now.Add(-50*time.Minute), time.Hour, now); got < 599 || got > 601 {
		t.Errorf("retry = %d, want ~600", got)
	}
	if got := runNowRetry(time.Time{}, time.Hour, now); got != 60 {
		t.Errorf("unknown oldest = %d, want 60", got)
	}
}

// ── Against MySQL (needs TEST_MYSQL_DSN) ──────────────────────────────────

func runNowTestUser(t *testing.T, role string) string {
	t.Helper()
	if os.Getenv("TEST_MYSQL_DSN") == "" {
		t.Skip("TEST_MYSQL_DSN not set")
	}
	db := setupClaudePoolTestDB(t)
	sub := claudePoolTestUser(t, db, "runnow")
	if role != "user" {
		db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, sub)
	}
	t.Cleanup(func() {
		db.Where("user_sub = ?", sub).Delete(&models.MeAppIntent{})
		db.Where("user_id = ?", sub).Delete(&models.Token{})
	})
	return sub
}

func seedRunIntents(t *testing.T, sub string, n int, ago time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		row := models.MeAppIntent{ID: fmt.Sprintf("rn-%s-%d-%d", sub[len(sub)-6:], i, time.Now().UnixNano()%1e6),
			Action: "run_loop", UserSub: sub, Payload: `{}`, Status: "done"}
		if err := common.DB.Create(&row).Error; err != nil {
			t.Fatalf("seed intent: %v", err)
		}
		common.DB.Model(&row).UpdateColumn("created_at", time.Now().Add(-ago))
	}
}

func TestRunNowLimitRefusesPastTheHourlyCapAndSaysHowToRead(t *testing.T) {
	sub := runNowTestUser(t, "user")
	t.Setenv("RUN_NOW_PER_HOUR", "3")
	seedRunIntents(t, sub, 2, 10*time.Minute)
	if why, _ := runNowLimit(sub); why != "" {
		t.Fatalf("under the cap: refused %q", why)
	}
	seedRunIntents(t, sub, 1, 50*time.Minute)
	why, retry := runNowLimit(sub)
	if why == "" || !strings.Contains(why, "limit 3") || !strings.Contains(why, "/api/research/backtests/") {
		t.Fatalf("over the cap: %q", why)
	}
	if retry < 500 || retry > 700 {
		t.Errorf("retry = %d, want ~600 (the 50-minute-old run leaves the window in ~10 min)", retry)
	}
	// Older than the window: not counted.
	sub2 := runNowTestUser(t, "user")
	seedRunIntents(t, sub2, 5, 2*time.Hour)
	if why, _ := runNowLimit(sub2); why != "" {
		t.Errorf("runs from two hours ago counted against the hour: %q", why)
	}
}

func TestRunNowLimitExemptsAdmins(t *testing.T) {
	sub := runNowTestUser(t, "admin")
	t.Setenv("RUN_NOW_PER_HOUR", "1")
	seedRunIntents(t, sub, 3, time.Minute)
	if why, _ := runNowLimit(sub); why != "" {
		t.Fatalf("admin refused: %q", why)
	}
}

func TestRunNowScopeObservesThenEnforces(t *testing.T) {
	sub := runNowTestUser(t, "user")
	if config.G == nil {
		config.G = &config.Config{}
		t.Cleanup(func() { config.G = nil })
	}
	narrow, _, err := mintPATForUser(sub, "my laptop", []string{"lqt:strategy"}, nil, "native")
	if err != nil {
		t.Fatal(err)
	}
	wide, _, _ := mintPATForUser(sub, "cli", []string{"lumid:read", "lumid:write"}, nil, "native")
	ctxWith := func(tok string) *gin.Context {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = r
		return c
	}
	t.Setenv("RUN_NOW_REQUIRE_SCOPE", "")
	if why := runNowScopeRefusal(ctxWith(narrow), sub, "quant-research", "backtest"); why != "" {
		t.Fatalf("observe mode refused: %q", why)
	}
	t.Setenv("RUN_NOW_REQUIRE_SCOPE", "enforce")
	why := runNowScopeRefusal(ctxWith(narrow), sub, "quant-research", "backtest")
	if !strings.Contains(why, `"my laptop"`) || !strings.Contains(why, "lumid:write") {
		t.Fatalf("enforce: %q", why)
	}
	if why := runNowScopeRefusal(ctxWith(wide), sub, "quant-research", "backtest"); why != "" {
		t.Errorf("a lumid:write token refused: %q", why)
	}
	// A session JWT carries no scopes and is not a PAT: never refused here.
	if why := runNowScopeRefusal(ctxWith("eyJhbGciOi.fake.jwt"), sub, "quant-research", "backtest"); why != "" {
		t.Errorf("a non-PAT bearer refused: %q", why)
	}
}
