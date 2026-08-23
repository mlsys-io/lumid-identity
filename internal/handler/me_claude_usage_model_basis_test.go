package handler

// Pins the per-model token basis for GET /me/claude-usage.
//
// The query it guards is issued with common.DB.Raw(...).Scan(&rows) and the
// error is NOT checked, so a malformed statement yields silently empty
// per-model data that reads as "no usage" rather than as a failure. Reading the
// SQL is therefore not verification; executing it is.

import (
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func TestMeClaudeUsagePerModelBasis(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping me/claude-usage per-model basis test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	if err := db.AutoMigrate(&models.UsageEvent{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db

	sub := fmt.Sprintf("me-basis-%d", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() { db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{}) })

	now := time.Now().UTC()
	bound := now.Add(-7 * 24 * time.Hour)

	// A realistically-shaped Claude Code turn: the cache columns ARE the turn.
	// in 100 + out 200 + cacheRead 10000 + cacheWrite 1000 (400 of it 1h).
	ev := models.UsageEvent{
		UserSub: sub, Ts: now.Add(-1 * time.Hour), Kind: "claude_proxy",
		Model: "claude-sonnet-5", InputTokens: 100, OutputTokens: 200,
		CacheReadTokens: 10000, CacheCreationTokens: 1000, CacheCreation1hTokens: 400,
	}
	if err := db.Create(&ev).Error; err != nil {
		t.Fatalf("seed event: %v", err)
	}

	var rows []struct {
		Model          string
		Tokens         int
		WeightedTokens int
		CostCents      int
	}
	if err := common.DB.Raw(fmt.Sprintf(`
		SELECT COALESCE(ue.model, '')                             AS model,
		       COALESCE(SUM(ue.input_tokens + ue.output_tokens
		                    + ue.cache_read_tokens + ue.cache_creation_tokens), 0) AS tokens,
		       COALESCE(SUM(%[1]s), 0)                            AS weighted_tokens,
		       COALESCE(SUM(ue.cost_cents), 0)                    AS cost_cents
		FROM   usage_events ue
		WHERE  ue.kind = 'claude_proxy' AND ue.user_sub = ? AND ue.ts >= ?
		GROUP  BY ue.model`, common.ClaudeWeightedTokensSQL("ue.")),
		sub, bound).Scan(&rows).Error; err != nil {
		t.Fatalf("per-model query failed to EXECUTE: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 model row, got %d (%+v)", len(rows), rows)
	}

	// RAW is model-neutral: every token the turn actually used.
	wantRaw := 100 + 200 + 10000 + 1000
	if rows[0].Tokens != wantRaw {
		t.Fatalf("tokens_7d=%d want %d (in+out+cache_read+cache_creation)", rows[0].Tokens, wantRaw)
	}
	// WEIGHTED must match the shared Go twin exactly — the gate and this
	// breakdown disagreeing about a user's draw is the bug class this pins.
	wantWeighted := common.ClaudeWeightedTokens("claude-sonnet-5", 100, 200, 10000, 1000, 400)
	if rows[0].WeightedTokens != wantWeighted {
		t.Fatalf("weighted_tokens_7d=%d want %d (ClaudeWeightedTokens twin)", rows[0].WeightedTokens, wantWeighted)
	}
	// The whole point: the two are NOT interchangeable on real Claude traffic.
	if rows[0].Tokens <= rows[0].WeightedTokens {
		t.Fatalf("raw (%d) should far exceed weighted (%d) on a cache-heavy turn",
			rows[0].Tokens, rows[0].WeightedTokens)
	}
	t.Logf("raw=%d weighted=%d (ratio %.1fx)", rows[0].Tokens, rows[0].WeightedTokens,
		float64(rows[0].Tokens)/float64(rows[0].WeightedTokens))
}
