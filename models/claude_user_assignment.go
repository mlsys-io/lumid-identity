package models

import "time"

// ClaudeUserAssignment pins a user to a pooled account (and therefore to a
// field box, and therefore to one egress IP).
//
// Persisted rather than computed per-request for two reasons:
//
//  1. STABILITY. The assignment IS the user's public origin. Recomputing it
//     freely would migrate people between IPs whenever someone else's usage
//     shifted, defeating the point of the field boxes. Storing it makes the
//     assignment something that CHANGES DELIBERATELY, under the hysteresis rule
//     in the balancer, rather than something that drifts.
//
//  2. AGREEMENT. claude-proxy runs 2 replicas whose in-memory lease caches can
//     disagree, so the same user could be served from different accounts within
//     minutes. A shared table gives both replicas one answer.
//
// Replaces per-user rendezvous hashing, which distributed users RANDOMLY (3/1/1
// across three accounts) and was blind to load — one heavy user could outweigh
// every other account combined.
// PoolID makes the ACTUAL database primary key (pool_id, user_sub): once a
// user can belong to more than one ClaudePool (see ClaudePoolMember), they
// need a durable "home account" PER POOL, not one home overall — a user in
// two pools has two independent placements to remember.
//
// PoolID deliberately carries NO `primaryKey` gorm tag, unlike UserSub.
// GORM's AutoMigrate cannot safely widen an existing single-column PK to a
// composite one — on 2026-09-04 tagging both fields `primaryKey` made
// AutoMigrate emit `ALTER TABLE ... ADD pool_id ..., ADD PRIMARY KEY
// (pool_id)` against a table that already had a PRIMARY KEY on user_sub,
// which MySQL rejects outright ("Error 1068: Multiple primary key
// defined") and crash-loops every pod on boot. EnsureDefaultClaudePool
// handles the real widening with its own guarded raw SQL (backfill
// pool_id='default', then DROP PRIMARY KEY, ADD PRIMARY KEY (pool_id,
// user_sub)) — AutoMigrate must only ever see PoolID as a plain new column
// to ADD, never as a primary-key change to reconcile.
type ClaudeUserAssignment struct {
	PoolID  string `gorm:"column:pool_id;size:64;not null;default:'default'" json:"pool_id"`
	UserSub string `gorm:"column:user_sub;size:36;primaryKey"        json:"user_sub"`
	Account string `gorm:"column:account;size:255;not null"          json:"account"`
	// Load7d is the token volume that justified this placement, kept so the
	// balancer can reason about drift without re-querying history.
	Load7d     int64     `gorm:"column:load_7d;not null;default:0"  json:"load_7d"`
	AssignedAt time.Time `gorm:"column:assigned_at;autoUpdateTime"  json:"assigned_at"`
	// Reason records WHY this placement happened (initial | rebalance | account
	// removed), so an operator can tell a deliberate migration from a bug.
	Reason string `gorm:"column:reason;size:32" json:"reason"`
}

func (ClaudeUserAssignment) TableName() string { return "claude_user_assignments" }
