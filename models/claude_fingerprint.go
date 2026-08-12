package models

import "time"

// ClaudeFingerprintObservation is one claude-proxy replica's count of a client
// version triple it saw during a reporting interval.
//
// WHY THIS LIVES IN IDENTITY, not in the proxy: claude-proxy runs 2 replicas
// with no shared state, and the field-box fingerprint must be IDENTICAL across
// them — a box presenting two identities depending on which pod served the
// request is a worse failure than presenting a slightly old version. Each
// replica observing its own traffic and adopting independently would diverge
// exactly during a version transition, which is when it matters. Identity is
// already the single authority every replica talks to, so aggregating here is
// what makes one answer possible at all.
//
// Rows are append-only counts, never a running total: a replica reports the
// delta it accumulated since its last flush, so a restart loses at most one
// interval and never double-counts.
type ClaudeFingerprintObservation struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// The three components are stored SEPARATELY but are only ever read back
	// together. A triple is meaningful only as a whole — Claude Code 2.1.228
	// ships SDK 0.112.1, and pairing a CLI with an SDK it does not ship
	// produces a client that does not exist. See the claude-proxy pool.
	CLI  string `gorm:"size:32;index:idx_cfo_triple,priority:1" json:"cli"`
	SDK  string `gorm:"size:32;index:idx_cfo_triple,priority:2" json:"sdk"`
	Node string `gorm:"size:32;index:idx_cfo_triple,priority:3" json:"node"`
	// Count of requests carrying this triple in the reporting interval.
	Count int `gorm:"not null;default:0" json:"count"`
	// Reporting pod, for debugging a divergence claim. Not used in the
	// aggregate — the whole point is that the answer is pod-independent.
	Reporter string `gorm:"size:64" json:"reporter"`
	// ObservedAt is when the reporting interval ENDED. Bucketing is done on
	// this column, so it must be the server's clock view of the flush, not a
	// client-supplied timestamp.
	ObservedAt time.Time `gorm:"index" json:"observed_at"`
}

func (ClaudeFingerprintObservation) TableName() string {
	return "claude_fingerprint_observations"
}

// ClaudeFieldPresenting is what claude-proxy is ACTUALLY presenting for a
// field box right now, self-reported by the proxy.
//
// This replaces a re-derivation. identity used to recompute the fingerprint
// itself (claude_field_fingerprint.go) to render the /code field-box panel,
// from a pool that a comment required to stay "byte-identical" to the proxy's.
// It did not: by 2026-08-12 identity was rendering `Anthropic/JS 0.112.1`
// while the proxy sent `claude-cli/2.1.228 (external, cli)` — the panel had
// been showing a fabricated identity since the proxy changed shape on
// 2026-08-11, and nothing detected it because both sides were "correct"
// against their own copy.
//
// Reporting beats mirroring for a value one service owns: there is exactly one
// writer, and a stale row is visibly stale (UpdatedAt) rather than confidently
// wrong.
type ClaudeFieldPresenting struct {
	// Label is the relay/box name (denmark, chicago, …) — one row per box.
	Label     string    `gorm:"size:64;primaryKey" json:"label"`
	UserAgent string    `gorm:"size:128" json:"user_agent"`
	CLI       string    `gorm:"size:32" json:"cli"`
	SDK       string    `gorm:"size:32" json:"sdk"`
	Node      string    `gorm:"size:32" json:"node"`
	OS        string    `gorm:"size:16" json:"os"`
	Arch      string    `gorm:"size:16" json:"arch"`
	Runtime   string    `gorm:"size:16" json:"runtime"`
	Source    string    `gorm:"size:16" json:"source"` // override | adopted | builtin
	Reporter  string    `gorm:"size:64" json:"reporter"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (ClaudeFieldPresenting) TableName() string {
	return "claude_field_presenting"
}
