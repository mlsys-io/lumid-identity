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
// PoolID is part of the primary key, not just another column: once a user
// can belong to more than one ClaudePool (see ClaudePoolMember), they need a
// durable "home account" PER POOL, not one home overall — a user in two
// pools has two independent placements to remember. GORM's AutoMigrate
// cannot widen an existing PK on MySQL; the (user_sub) -> (pool_id, user_sub)
// migration is a raw ALTER in EnsureDefaultClaudePool, backfilling
// pool_id='default' for every pre-existing row.
type ClaudeUserAssignment struct {
	PoolID  string `gorm:"column:pool_id;size:64;primaryKey"         json:"pool_id"`
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
