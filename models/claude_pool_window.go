package models

import "time"

// ClaudePoolWindow is the durable fixed-window anchor for one user's Claude
// account-pool quota. Unlike a running counter, only the window START is
// persisted — token totals stay computed live from usage_events, bounded by
// the anchor instead of a rolling "now - N" cutoff. See internal/common/quota.go
// (claudeWindowLive/ClaudePoolUsage/ClaudePoolCommit) for the semantics: a
// window is live while now < anchor+windowLen, and idle (fully reset) once
// that instant passes with no new charge.
type ClaudePoolWindow struct {
	UserSub        string    `gorm:"column:user_sub;size:36;primaryKey" json:"user_sub"`
	FiveHourAnchor time.Time `gorm:"column:five_hour_anchor;not null"   json:"five_hour_anchor"`
	SevenDayAnchor time.Time `gorm:"column:seven_day_anchor;not null"   json:"seven_day_anchor"`
	UpdatedAt      time.Time `gorm:"column:updated_at;autoUpdateTime"   json:"updated_at"`
}

func (ClaudePoolWindow) TableName() string { return "claude_pool_windows" }
