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
	ConvKey string `gorm:"column:conv_key;size:32;primaryKey"                         json:"conv_key"`
	UserSub string `gorm:"column:user_sub;size:36;index:idx_csess_user_last,priority:1;not null" json:"user_sub"`
	Account string `gorm:"column:account;size:255"                                    json:"account"`
	// PoolID — which Claude pool served this session, STAMPED AT WRITE TIME.
	//
	// Deliberately stored rather than derived. Pool membership of an account is
	// mutable (ClaudeQuotaToken.PoolID moves when an operator reassigns one), so
	// joining account -> pool at READ time silently rewrites history: sessions
	// served while an account sat in "default" start reporting as whatever pool
	// it lives in today. Measured 2026-09-06 — two accounts moved into "rsi"
	// retroactively relabelled every session they had ever served.
	//
	// That matters now that policy is per-pool: "which pool was this served
	// under, and under which policy" is exactly the audit question, and a
	// derived answer cannot be trusted for any window in which an account moved.
	PoolID string `gorm:"column:pool_id;size:64;index" json:"pool_id,omitempty"`
	// FieldBox is the account Label of the field-box relay the MOST RECENT
	// turn egressed through ("dublin", "chicago", …); empty = dispatched
	// directly to Anthropic from the cluster. Session-level value is
	// last-writer-wins; per-turn truth lives on ClaudeSessionTurn.FieldBox.
	FieldBox string `gorm:"column:field_box;size:64"                                   json:"field_box"`
	// ViaRelay: did the MOST RECENT turn actually egress through that box?
	// FieldBox is intent (the lease Label); this is delivery. Labeled but
	// ViaRelay=false = the relay hop silently degraded to direct dispatch.
	ViaRelay bool `gorm:"column:via_relay;not null;default:false"                    json:"via_relay"`
	// Cumulative TRUE wire bytes across the session's turns. Feeds the
	// per-field-box I/O breakdown on /code.
	RequestBytes  int64     `gorm:"column:request_bytes;not null;default:0"  json:"request_bytes"`
	ResponseBytes int64     `gorm:"column:response_bytes;not null;default:0" json:"response_bytes"`
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
	ID        uint64    `gorm:"primaryKey;autoIncrement"                                   json:"id"`
	ConvKey   string    `gorm:"column:conv_key;size:32;index:idx_cturn_conv,priority:1;not null" json:"conv_key"`
	TurnIndex int       `gorm:"column:turn_index;index:idx_cturn_conv,priority:2;not null" json:"turn_index"`
	Ts        time.Time `gorm:"column:ts;autoCreateTime;index:idx_cturn_session,priority:2" json:"ts"`
	Model     string    `gorm:"column:model;size:64"                                       json:"model"`
	Endpoint  string    `gorm:"column:endpoint;size:128"                                   json:"endpoint"`
	// FieldBox: which field-box relay carried THIS turn (account Label);
	// empty = direct from the cluster. Per-turn because routing can change
	// mid-conversation (account re-labeled, or lease rotated to another
	// account on a different box).
	FieldBox string `gorm:"column:field_box;size:64"                                   json:"field_box"`
	// PoolID: which pool served THIS turn, stamped at write time — per-turn for
	// the same reason FieldBox is, and one step stronger: a lease can rotate to
	// an account in a different pool mid-conversation, and an operator can move
	// an account between pools between two turns of one session. The session
	// row carries last-writer-wins; this is the per-turn truth. See
	// ClaudeSession.PoolID for why it is stored rather than derived.
	PoolID string `gorm:"column:pool_id;size:64;index" json:"pool_id,omitempty"`
	// ViaRelay: whether THIS turn actually took the relay hop (delivery),
	// vs FieldBox which is only where it was meant to go (intent).
	ViaRelay bool `gorm:"column:via_relay;not null;default:false"                     json:"via_relay"`
	// SessionID is claude-proxy's lease stickiness unit for this turn — the
	// client's x-claude-code-session-id, or the user sub when absent.
	//
	// ConvKey CANNOT substitute for it. ConvKey is hash(model + first user
	// message), so distinct sessions opening with the same prompt (agent loops,
	// repeated tasks, cron runs) share one ConvKey; grouping by it makes their
	// legitimate placement on different accounts look like mid-session
	// flapping. Indexed with Ts so the teleport query — consecutive turns of one
	// SessionID whose FieldBox changes — is a range scan.
	//
	// Empty on rows written before 2026-08-17 and by any older proxy.
	SessionID string `gorm:"column:session_id;size:64;index:idx_cturn_session,priority:1" json:"session_id"`
	// TRUE wire bytes for this turn. ResponseBytes is counted per-chunk by the
	// proxy, so it is NOT limited by the transcript blob cap — a truncated
	// recording still reports its real size.
	RequestBytes  int64 `gorm:"column:request_bytes;not null;default:0"  json:"request_bytes"`
	ResponseBytes int64 `gorm:"column:response_bytes;not null;default:0" json:"response_bytes"`
	Stream        bool  `gorm:"column:stream;not null;default:false"                       json:"stream"`
	InputTokens   int   `gorm:"column:input_tokens;not null;default:0"                     json:"input_tokens"`
	OutputTokens  int   `gorm:"column:output_tokens;not null;default:0"                    json:"output_tokens"`
	ToolUseCount  int   `gorm:"column:tool_use_count;not null;default:0"                   json:"tool_use_count"`
	DurationMs    int   `gorm:"column:duration_ms;not null;default:0"                      json:"duration_ms"`
	// gzip(JSON). RequestMetaGz = {system, tools, max_tokens, temperature,
	// top_p, stop_sequences, metadata, model, stream} minus messages[].
	RequestMetaGz []byte `gorm:"column:request_meta_gz;type:longblob"  json:"-"`
	// NewMessagesGz = gzip(JSON array) of messages[] added since the prior turn.
	NewMessagesGz []byte `gorm:"column:new_messages_gz;type:longblob"  json:"-"`
	// ResponseGz = gzip of the full upstream response (assembled JSON for
	// non-stream, raw SSE bytes for stream). Capped by the proxy.
	ResponseGz []byte `gorm:"column:response_gz;type:longblob"      json:"-"`
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
