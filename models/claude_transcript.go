package models

import "time"

// Claude account-pool session recording. Every /v1/messages call routed
// through claude-proxy is captured as a "turn". Recording is ON by default;
// a user can opt out (ClaudeRecordingPref.Enabled=false).
//
// Storage is delta-compacted to avoid quadratic bloat: the Anthropic API is
// stateless, so each request re-sends the whole conversation in messages[].
// We store only the NEW messages since the previous turn (NewMessagesGz) plus
// the per-turn request params (system/tools/model/sampling — RequestMetaGz)
// and the full response (ResponseGz). Reconstructing a session = concatenating
// each turn's new messages in order. All blobs are gzip-compressed JSON.

// ClaudeSession is one conversation (grouped by ConvKey = hash of model +
// first user message). Summary row; turns hang off it.
type ClaudeSession struct {
	ConvKey       string    `gorm:"column:conv_key;size:32;primaryKey"                         json:"conv_key"`
	UserSub       string    `gorm:"column:user_sub;size:36;index:idx_csess_user_last,priority:1;not null" json:"user_sub"`
	Account       string    `gorm:"column:account;size:255"                                    json:"account"`
	Model         string    `gorm:"column:model;size:64"                                       json:"model"`
	Title         string    `gorm:"column:title;size:255"                                      json:"title"`
	TurnCount     int       `gorm:"column:turn_count;not null;default:0"                       json:"turn_count"`
	CumMessages   int       `gorm:"column:cum_messages;not null;default:0"                     json:"cum_messages"`
	InputTokens   int64     `gorm:"column:input_tokens;not null;default:0"                     json:"input_tokens"`
	OutputTokens  int64     `gorm:"column:output_tokens;not null;default:0"                    json:"output_tokens"`
	ToolUseCount  int       `gorm:"column:tool_use_count;not null;default:0"                   json:"tool_use_count"`
	FirstTs       time.Time `gorm:"column:first_ts"                                            json:"first_ts"`
	LastTs        time.Time `gorm:"column:last_ts;index:idx_csess_user_last,priority:2"        json:"last_ts"`
}

func (ClaudeSession) TableName() string { return "claude_sessions" }

// ClaudeSessionTurn is one request/response exchange within a session.
type ClaudeSessionTurn struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement"                                   json:"id"`
	ConvKey       string    `gorm:"column:conv_key;size:32;index:idx_cturn_conv,priority:1;not null" json:"conv_key"`
	TurnIndex     int       `gorm:"column:turn_index;index:idx_cturn_conv,priority:2;not null" json:"turn_index"`
	Ts            time.Time `gorm:"column:ts;autoCreateTime"                                   json:"ts"`
	Model         string    `gorm:"column:model;size:64"                                       json:"model"`
	Endpoint      string    `gorm:"column:endpoint;size:128"                                   json:"endpoint"`
	Stream        bool      `gorm:"column:stream;not null;default:false"                       json:"stream"`
	InputTokens   int       `gorm:"column:input_tokens;not null;default:0"                     json:"input_tokens"`
	OutputTokens  int       `gorm:"column:output_tokens;not null;default:0"                    json:"output_tokens"`
	ToolUseCount  int       `gorm:"column:tool_use_count;not null;default:0"                   json:"tool_use_count"`
	DurationMs    int       `gorm:"column:duration_ms;not null;default:0"                      json:"duration_ms"`
	// gzip(JSON). RequestMetaGz = {system, tools, max_tokens, temperature,
	// top_p, stop_sequences, metadata, model, stream} minus messages[].
	RequestMetaGz []byte `gorm:"column:request_meta_gz;type:longblob"  json:"-"`
	// NewMessagesGz = gzip(JSON array) of messages[] added since the prior turn.
	NewMessagesGz []byte `gorm:"column:new_messages_gz;type:longblob"  json:"-"`
	// ResponseGz = gzip of the full upstream response (assembled JSON for
	// non-stream, raw SSE bytes for stream). Capped by the proxy.
	ResponseGz    []byte `gorm:"column:response_gz;type:longblob"      json:"-"`
	// Truncated flags a blob that hit the proxy's per-turn size cap.
	Truncated bool `gorm:"column:truncated;not null;default:false" json:"truncated"`
	// BlobKey is set when blobs are stored in S3 (not in the LONGBLOB columns).
	// Format: "{conv_key}/{turn_index}" — derive the three field paths from it.
	// Empty string means blobs are in the LONGBLOB columns (legacy rows).
	BlobKey string `gorm:"column:blob_key;size:100;not null;default:''" json:"-"`
}

func (ClaudeSessionTurn) TableName() string { return "claude_session_turns" }

// ClaudeRecordingPref — per-user opt-out. Absence of a row means recording is
// ENABLED (on by default). A row with Enabled=false means the user opted out.
type ClaudeRecordingPref struct {
	// No `default:true` on Enabled: GORM omits zero-value (false) fields that
	// carry a default tag, which would silently flip an opt-out back to true.
	// Default-on semantics live in recordingEnabled() (absent row = enabled).
	UserSub   string    `gorm:"column:user_sub;size:36;primaryKey" json:"user_sub"`
	Enabled   bool      `gorm:"column:enabled;not null" json:"enabled"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (ClaudeRecordingPref) TableName() string { return "claude_recording_prefs" }
