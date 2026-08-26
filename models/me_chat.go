package models

import "time"

// MeChat — a Studio chat transcript.
//
// These lived as JSON files under `tenantRoot(user)/.chats/` on the pod's own
// container filesystem. lumid-identity runs replicas: 2 behind a round-robin
// Service with no shared volume, so a thread saved on one pod was invisible to
// the other: the follow-up GET 404'd, reloads lost the transcript, and a
// multi-turn conversation only stayed coherent when consecutive requests
// happened to land on the same pod. Measured on the live pods mid-session — one
// held 2 chat files, the other 3.
//
// The body stays a JSON blob for the same reason it was a JSON file: `messages`
// is whatever shape the frontend currently sends, and pinning it to columns
// would put the wire format in lockstep with the message type. Only the fields
// the sidebar lists are promoted to real columns so listing does not need to
// parse every row.
type MeChat struct {
	ID      string `gorm:"column:id;size:64;primaryKey"        json:"id"`
	UserSub string `gorm:"column:user_sub;size:36;index:idx_mechat_user_updated,priority:1;not null" json:"user_sub"`

	Title        string `gorm:"column:title;size:512"      json:"title"`
	TitleSummary bool   `gorm:"column:title_summary"       json:"title_summary"`
	Model        string `gorm:"column:model;size:128"      json:"model,omitempty"`
	Mode         string `gorm:"column:mode;size:32"        json:"mode,omitempty"`
	App          string `gorm:"column:app;size:128;index"  json:"app,omitempty"`
	// One strategy inside that app, so a user's threads about different
	// strategies stay separable. Without the COLUMN the handler's field was
	// dropped on the way to MySQL: the API accepted strategy_id, echoed
	// nothing back, and the per-strategy Sessions table — which fails closed
	// on an unmatched id — rendered empty forever with no error anywhere.
	StrategyID string `gorm:"column:strategy_id;size:128" json:"strategy_id,omitempty"`
	// Claude CLI session id backing this thread, so --resume continuity
	// survives a reload (and, now, a different replica).
	ClaudeSessionID string `gorm:"column:claude_session_id;size:128" json:"claude_session_id,omitempty"`

	MsgCount int `gorm:"column:msg_count" json:"msg_count"`
	// Messages as stored JSON. longtext: transcripts with tool results and
	// reasoning blocks routinely exceed TEXT's 64 KB.
	Messages string `gorm:"column:messages;type:longtext" json:"-"`

	CreatedAt time.Time `gorm:"column:created_at"                                        json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;index:idx_mechat_user_updated,priority:2" json:"updated_at"`
}

func (MeChat) TableName() string { return "me_chats" }
