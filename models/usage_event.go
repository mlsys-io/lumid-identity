package models

import "time"

// UsageEvent — one row per server-funded LLM call (initially just
// /me/agent/chat). Drives the per-user daily token budget cap + the
// "you've used X / Y tokens today" tile on the tokens page.
//
// Schema is deliberately flat so a future cloud-runtime cycle's
// inference cost can append to the same table (set kind="cycle_llm",
// endpoint="<app>.<loop>"). Cost is tracked in cents (integer) so
// totals don't accumulate float error over a million rows.
type UsageEvent struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement"            json:"id"`
	UserSub      string    `gorm:"column:user_sub;size:36;index:idx_usage_user_ts,priority:1;not null" json:"user_sub"`
	Ts           time.Time `gorm:"column:ts;index:idx_usage_user_ts,priority:2;autoCreateTime"         json:"ts"`
	Kind         string    `gorm:"column:kind;size:32;not null"        json:"kind"`     // "chat" | "cycle_llm" | ...
	Endpoint     string    `gorm:"column:endpoint;size:128"            json:"endpoint"` // "/me/agent/chat" | "<app>.<loop>"
	Model        string    `gorm:"column:model;size:64"                json:"model"`
	InputTokens  int       `gorm:"column:input_tokens;not null;default:0"  json:"input_tokens"`
	OutputTokens int       `gorm:"column:output_tokens;not null;default:0" json:"output_tokens"`
	// RAW cached-input counts, exactly as Anthropic reported them. Stored
	// separately and unweighted so this table remains a faithful record that can
	// be reconciled against Anthropic's own — the pool QUOTA weights these (a
	// cache read costs a tenth of fresh input) but the weighting belongs at read
	// time, not in the stored truth.
	//
	// Rows written before 2026-08-12 leave these 0 and fold the weighted total
	// into InputTokens instead. That is why the read-time formula ADDS the
	// weighted cache columns rather than replacing InputTokens: on an old row
	// the two cache terms contribute nothing and the historical value stands, so
	// the transition needs no backfill and cannot double-count.
	CacheReadTokens     int `gorm:"column:cache_read_tokens;not null;default:0"     json:"cache_read_tokens"`
	CacheCreationTokens int `gorm:"column:cache_creation_tokens;not null;default:0" json:"cache_creation_tokens"`
	// The 1-HOUR-TTL share of CacheCreationTokens — a SUBSET of it, not an
	// addition. Stored separately because the two TTLs are priced differently
	// (5-minute write 1.25x base input, 1-hour write 2x), and the flat total
	// cannot distinguish them. Rows written before this column existed leave it
	// 0, so the read-time formula prices their whole creation total at the
	// 5-minute rate — exactly the prior behaviour, and no backfill is needed.
	CacheCreation1hTokens int    `gorm:"column:cache_creation_1h_tokens;not null;default:0" json:"cache_creation_1h_tokens"`
	CostCents             int    `gorm:"column:cost_cents;not null;default:0"    json:"cost_cents"`
	Meta                  string `gorm:"column:meta;type:text"               json:"meta"` // optional JSON blob
	// Which installed app and run spent it (2026-11-28), when the caller knows:
	// claude-proxy forwards them from the bearer's run claims, and a run
	// credential's own charge takes them from the credential. NULL = not
	// attributed (every row before this, and plain chat) — never guessed.
	// Deliberately unindexed: reads filter by user first (idx_usage_user_ts), and
	// a new index on this ~1M-row table would hold up identity's start-up.
	App   *string `gorm:"column:app;size:128"   json:"app,omitempty"`
	RunID *string `gorm:"column:run_id;size:64" json:"run_id,omitempty"`
}

func (UsageEvent) TableName() string { return "usage_events" }
