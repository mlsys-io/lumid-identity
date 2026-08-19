package models

import "time"

// ClaudeSessionBinding — which pooled account is serving a given Claude Code
// session, shared across claude-proxy replicas and across restarts.
//
// WHY. claude-proxy pins a session to one subscription for its whole life,
// because Anthropic sees turn N of a conversation arriving on an account that
// never saw turns 1..N-1 — no prompt-cache history, referencing context it never
// received. Measured 2026-08-18: one session_id was served 1487 turns across all
// four accounts and all four egress countries inside a day.
//
// That pin lived only in pod memory, which left two holes the pin itself cannot
// see:
//
//   - Two replicas, and nothing pins a session to a POD. The landing nginx
//     proxies to a ClusterIP, so kube-proxy picks a replica per connection and a
//     session's turns land on both. Each pod then keeps its own binding. (nginx
//     cannot fix this: it sees one VIP, so hashing there changes nothing, and OSS
//     nginx cannot re-resolve a headless service's pod IPs, so they would go stale
//     on every rollout.)
//   - EVERY ROLLOUT drops all bindings. Four claude-proxy rollouts on 2026-08-19
//     each silently re-homed every in-flight conversation — the exact failure the
//     pin exists to prevent, fired by deploying the pin.
//
// Identity is the one component both replicas already talk to on every lease, so
// the binding belongs here. It is ADVISORY: the proxy's own in-memory pin and its
// wait/rehome state machine are untouched, and this only supplies prefer_email
// when a pod has no memory of the session — a fresh pod, or the sibling replica.
type ClaudeSessionBinding struct {
	// SessionKey is the client's x-claude-code-session-id when present, else the
	// user's sub. Client-supplied, so it is length-capped and never interpolated
	// anywhere but a parameterised query.
	SessionKey string    `gorm:"column:session_key;size:128;primaryKey" json:"session_key"`
	Email      string    `gorm:"column:email;size:255;not null"         json:"email"`
	UserSub    string    `gorm:"column:user_sub;size:64;index"          json:"user_sub,omitempty"`
	CreatedAt  time.Time `gorm:"autoCreateTime"                         json:"created_at"`
	// LastSeenAt bounds the table instead of a TTL: the whole point is to outlive
	// the 30-minute token lease, so expiry has to track USE, not age. Pruned on
	// the token sweep at the same 24h the proxy uses in memory.
	LastSeenAt time.Time `gorm:"column:last_seen_at;index"              json:"last_seen_at"`
}

func (ClaudeSessionBinding) TableName() string { return "claude_session_bindings" }
