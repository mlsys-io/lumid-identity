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
	ID            uint64    `gorm:"primaryKey;autoIncrement"            json:"id"`
	UserSub       string    `gorm:"column:user_sub;size:36;index:idx_usage_user_ts,priority:1;not null" json:"user_sub"`
	Ts            time.Time `gorm:"column:ts;index:idx_usage_user_ts,priority:2;autoCreateTime"         json:"ts"`
	Kind          string    `gorm:"column:kind;size:32;not null"        json:"kind"`     // "chat" | "cycle_llm" | ...
	Endpoint      string    `gorm:"column:endpoint;size:128"            json:"endpoint"` // "/me/agent/chat" | "<app>.<loop>"
	Model         string    `gorm:"column:model;size:64"                json:"model"`
	InputTokens   int       `gorm:"column:input_tokens;not null;default:0"  json:"input_tokens"`
	OutputTokens  int       `gorm:"column:output_tokens;not null;default:0" json:"output_tokens"`
	CostCents     int       `gorm:"column:cost_cents;not null;default:0"    json:"cost_cents"`
	Meta          string    `gorm:"column:meta;type:text"               json:"meta"` // optional JSON blob
}

func (UsageEvent) TableName() string { return "usage_events" }
