package models

import "time"

// SocAPIKey — a pooled NUS SoC LLM gateway key (soclaas, SOCLAAS_API_KEY).
//
// Each SoC key is personal and carries a DAILY usage limit, so claude-proxy
// serves the SoC-routed models (OPENAI_COMPAT_ROUTES `…|pool:soc`) by rotating
// across every key in this table and benching a key once it reports its daily
// limit. Imported on lum.id/code; the key itself is stored only encrypted
// (common.EncryptGrant) and leaves identity only via the bridge-secret
// /internal/soc-keys route.
type SocAPIKey struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// KeyFP is sha256(key)[:16] hex — dedupes re-imports of the same key and is
	// the only key-derived value ever shown in the UI (as its last 6 chars).
	KeyFP        string `gorm:"type:varchar(32);uniqueIndex;not null" json:"key_fp"`
	KeyEncrypted string `gorm:"type:text;not null"                    json:"-"`
	Label        string `gorm:"type:varchar(128)"                     json:"label"`
	// Who imported it (the lumid user), for attribution on the dashboard.
	OwnerSub   string `gorm:"type:varchar(36);index" json:"owner_sub"`
	OwnerEmail string `gorm:"type:varchar(255)"      json:"owner_email"`
	// Bench state, written by claude-proxy via /internal/soc-keys/bench so it
	// holds across proxy replicas. Dead = the gateway rejected the key itself
	// (401); it stays out of rotation until re-imported.
	BenchUntil  *time.Time `json:"bench_until,omitempty"`
	BenchReason string     `gorm:"size:512" json:"bench_reason,omitempty"`
	BenchDead   bool       `gorm:"not null;default:false" json:"bench_dead"`
	// Stamped by claude-proxy (throttled) when the key serves a turn.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt  time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

// SocKeyUsage — per-minute serving metrics of the SoC relay, one row per
// (key, model, minute), summed across claude-proxy replicas on upsert. KeyID 0
// = the proxy's fallback key. Drives the TKPS view on lum.id/code.
type SocKeyUsage struct {
	KeyID     uint      `gorm:"primaryKey;autoIncrement:false" json:"key_id"`
	Model     string    `gorm:"type:varchar(64);primaryKey"    json:"model"`
	Minute    time.Time `gorm:"primaryKey;index"               json:"minute"`
	Requests  int       `json:"requests"`
	Errors    int       `json:"errors"`
	Streams   int       `json:"streams"`
	InTokens  int64     `json:"in_tokens"`
	OutTokens int64     `json:"out_tokens"`
	GenMs     int64     `json:"gen_ms"`
	TTFTMs    int64     `gorm:"column:ttft_ms" json:"ttft_ms"`
	Estimated int       `json:"estimated"`
}

// ModelUsageMinute — per-minute serving metrics per (source, model), summed
// across claude-proxy replicas. source "claude" = the Anthropic account pool
// (lum.id/code Throughput). SoC traffic keeps its own per-key table above.
type ModelUsageMinute struct {
	Source    string    `gorm:"type:varchar(32);primaryKey" json:"source"`
	Model     string    `gorm:"type:varchar(96);primaryKey" json:"model"`
	Minute    time.Time `gorm:"primaryKey;index"            json:"minute"`
	Requests  int       `json:"requests"`
	Errors    int       `json:"errors"`
	Streams   int       `json:"streams"`
	InTokens  int64     `json:"in_tokens"`
	OutTokens int64     `json:"out_tokens"`
	GenMs     int64     `json:"gen_ms"`
	TTFTMs    int64     `gorm:"column:ttft_ms" json:"ttft_ms"`
	Estimated int       `json:"estimated"`
}
