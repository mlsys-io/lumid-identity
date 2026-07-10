package models

import "time"

// MeToolApproval — DB-backed handshake for the destructive-tool approval
// gate in /me/agent/chat streaming.
//
// Why: toolApprovals used to be ONLY an in-memory sync.Map of channels on
// the pod holding the paused SSE stream. Identity runs HA (replicas=2), so
// a POST /me/agent/chat/tool-approve round-robined to the OTHER pod found
// no channel and 404'd — the user clicked Approve and the stream still
// timed out on their behalf. Same cross-replica failure class that MeDoc
// and MeAppIntent already fixed for file stores.
//
// The fix is a poll+channel hybrid: the paused stream inserts a pending
// row, then waits on BOTH its local channel (instant, same-pod fast path)
// and a 1s poll of this row's Status (cross-pod path). The approve
// endpoint atomically flips pending → approved|denied and, when it happens
// to land on the stream's own pod, also feeds the channel. Rows are
// short-lived: the waiter deletes its row on every exit path, and inserts
// lazily sweep rows older than 1h.
type MeToolApproval struct {
	ID        string     `gorm:"column:id;size:36;primaryKey"`
	UserSub   string     `gorm:"column:user_sub;size:36;not null;index"`
	Tool      string     `gorm:"column:tool;size:64"`
	Status    string     `gorm:"column:status;size:16;default:pending"` // pending | approved | denied
	CreatedAt time.Time  `gorm:"column:created_at;autoCreateTime"`
	DecidedAt *time.Time `gorm:"column:decided_at"`
}

func (MeToolApproval) TableName() string { return "me_tool_approvals" }
