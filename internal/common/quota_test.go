package common

// End-to-end quota test — exercises CheckAndCharge against the live
// lumid_identity MySQL with a synthetic user_sub, then cleans up.
//
// Run via:
//   docker run --rm --network=host -v /proj/lumid_identity:/src \
//     -v /tmp/gocache:/root/.cache/go-build -v /tmp/gopath:/go \
//     -w /src -e LUMID_QUOTA_TEST_DSN="root:<pw>@tcp(172.17.0.1:3306)/lumid_identity?parseTime=true&loc=UTC" \
//     golang:1.25 go test -buildvcs=false -v ./internal/common/ -run TestQuota_

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"lumid_identity/models"
)

func connectTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("LUMID_QUOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("LUMID_QUOTA_TEST_DSN not set — skipping live-DB quota test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.AutoMigrate(&models.UsageEvent{}, &models.ClaudePoolWindow{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func cleanupSub(t *testing.T, db *gorm.DB, sub string) {
	t.Helper()
	db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
	db.Where("user_sub = ?", sub).Delete(&models.ClaudePoolWindow{})
}

func TestQuota_CyclesDaily(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CYCLES_DAILY", "10") // tight cap for fast test
	t.Setenv("LUMID_QUOTA_LLM_TOKENS_DAILY", "1000000")
	t.Setenv("LUMID_QUOTA_GMAIL_DAILY", "1000")
	t.Setenv("LUMID_QUOTA_SLACK_DAILY", "1000")

	db := connectTestDB(t)
	sub := fmt.Sprintf("qt-cycles-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	for i := 1; i <= 10; i++ {
		res, err := CheckAndCharge(db, ChargeReq{UserSub: sub, Kind: "cycle_start"})
		if err != nil {
			t.Fatalf("charge %d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("charge %d should be allowed, got deny=%q today=%+v", i, res.DenyReason, res.Today)
		}
		if res.Today.Cycles != i {
			t.Fatalf("charge %d: today.cycles=%d want %d", i, res.Today.Cycles, i)
		}
	}
	// 11th must be denied.
	res, err := CheckAndCharge(db, ChargeReq{UserSub: sub, Kind: "cycle_start"})
	if err != nil {
		t.Fatalf("charge 11: %v", err)
	}
	if res.Allowed {
		t.Fatalf("charge 11 should be denied")
	}
	if res.DenyReason != "quota_exceeded_cycles_daily" {
		t.Fatalf("want deny=quota_exceeded_cycles_daily got %q", res.DenyReason)
	}
	if res.Today.Cycles != 10 {
		t.Fatalf("after deny today.cycles=%d want 10 (no charge on deny)", res.Today.Cycles)
	}

	// DryRun at-cap is also denied AND writes nothing.
	res, _ = CheckAndCharge(db, ChargeReq{UserSub: sub, Kind: "cycle_start", DryRun: true})
	if res.Allowed {
		t.Fatalf("dry_run at cap should be denied")
	}
	var cnt int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&cnt)
	if cnt != 10 {
		t.Fatalf("after dry_run row count=%d want 10", cnt)
	}
}

func TestQuota_LLMTokens(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CYCLES_DAILY", "100000")
	t.Setenv("LUMID_QUOTA_LLM_TOKENS_DAILY", "500000")
	t.Setenv("LUMID_QUOTA_GMAIL_DAILY", "1000")
	t.Setenv("LUMID_QUOTA_SLACK_DAILY", "1000")

	db := connectTestDB(t)
	sub := fmt.Sprintf("qt-llm-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	// Burn exactly the budget across two calls.
	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "cycle_llm",
		Endpoint:    "personal-agent.morning_brief",
		Model:       "claude-haiku-4-5",
		InputTokens: 200_000, OutputTokens: 50_000,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("call 1: err=%v allowed=%v", err, res.Allowed)
	}
	res, err = CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "cycle_llm",
		InputTokens: 200_000, OutputTokens: 50_000,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("call 2: err=%v allowed=%v", err, res.Allowed)
	}
	if res.Today.LLMTokens != 500_000 {
		t.Fatalf("today.llm_tokens=%d want 500000", res.Today.LLMTokens)
	}
	// One more token tips us over.
	res, _ = CheckAndCharge(db, ChargeReq{UserSub: sub, Kind: "cycle_llm", OutputTokens: 1})
	if res.Allowed {
		t.Fatalf("over-cap should deny")
	}
	if res.DenyReason != "quota_exceeded_llm_tokens_daily" {
		t.Fatalf("want llm_tokens deny, got %q", res.DenyReason)
	}
}

func TestQuota_ExternalAPI(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CYCLES_DAILY", "100000")
	t.Setenv("LUMID_QUOTA_LLM_TOKENS_DAILY", "100000000")
	t.Setenv("LUMID_QUOTA_GMAIL_DAILY", "5")
	t.Setenv("LUMID_QUOTA_SLACK_DAILY", "3")

	db := connectTestDB(t)
	sub := fmt.Sprintf("qt-extapi-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	for i := 1; i <= 5; i++ {
		res, _ := CheckAndCharge(db, ChargeReq{
			UserSub: sub, Kind: "external_api", Endpoint: "gmail.send",
		})
		if !res.Allowed {
			t.Fatalf("gmail send %d should allow", i)
		}
	}
	res, _ := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "external_api", Endpoint: "gmail.send",
	})
	if res.Allowed || res.DenyReason != "quota_exceeded_gmail_daily" {
		t.Fatalf("over-cap gmail: allowed=%v deny=%q", res.Allowed, res.DenyReason)
	}

	// Slack is independent counter.
	for i := 1; i <= 3; i++ {
		res, _ := CheckAndCharge(db, ChargeReq{
			UserSub: sub, Kind: "external_api", Endpoint: "slack.post",
		})
		if !res.Allowed {
			t.Fatalf("slack post %d should allow", i)
		}
	}
	res, _ = CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "external_api", Endpoint: "slack.post",
	})
	if res.Allowed || res.DenyReason != "quota_exceeded_slack_daily" {
		t.Fatalf("over-cap slack: allowed=%v deny=%q", res.Allowed, res.DenyReason)
	}

	// Unknown endpoint — recorded but ungated. We dial back the
	// cycle cap to force a deny here would be wrong (different kind).
	res, _ = CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "external_api", Endpoint: "telegram.post",
	})
	if !res.Allowed {
		t.Fatalf("unknown external_api endpoint should pass (ungated): deny=%q", res.DenyReason)
	}
}

func TestQuota_DryRunNoSideEffect(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CYCLES_DAILY", "100000")
	db := connectTestDB(t)
	sub := fmt.Sprintf("qt-dryrun-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	res, err := CheckAndCharge(db, ChargeReq{
		UserSub: sub, Kind: "cycle_start", DryRun: true,
	})
	if err != nil || !res.Allowed {
		t.Fatalf("dry_run under cap: err=%v allowed=%v", err, res.Allowed)
	}
	var cnt int64
	db.Model(&models.UsageEvent{}).Where("user_sub = ?", sub).Count(&cnt)
	if cnt != 0 {
		t.Fatalf("dry_run wrote %d rows want 0", cnt)
	}
}

func TestQuota_FetchTodayTotals_Empty(t *testing.T) {
	db := connectTestDB(t)
	sub := fmt.Sprintf("qt-empty-%d", time.Now().UnixNano())
	t.Cleanup(func() { cleanupSub(t, db, sub) })

	totals, err := FetchTodayTotals(db, sub)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if totals != (Totals{}) {
		t.Fatalf("empty sub should give zero totals, got %+v", totals)
	}
}
