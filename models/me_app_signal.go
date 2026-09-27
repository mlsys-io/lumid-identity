package models

import "time"

// MeAppSignal — the DB-backed queue of trajectory control signals (a Studio
// right-click "branch from here", the chat branch_run tool).
//
// Signals used to be appended to <install>/data/control/signals.jsonl, which
// the runner's _consume_branch_signals drains at cycle start. On UKS identity
// mounts no tenant volume, so for a cloud install the append was shipped to the
// scheduler as an app_file_write intent — asynchronous, and the recorded signal
// was invisible to every read here until it had been applied and drained.
//
// The runner already asks identity for them: at every cycle start
// sdk/apps/app_runner.py::_sync_identity_overlays POSTs
// /api/v1/internal/app-signals/claim {user_sub, app}, appends each returned
// `rec` to its signals.jsonl, then POSTs /app-signals/ack {user_sub, ids}. That
// call 404'd silently until this table existed.
//
// pending → claimed (handed to a cycle) → delivered (acked). A claim that is
// never acked (the cycle crashed between claim and ack) is re-delivered after
// appSignalStaleClaim; Attempts records how often that happened.
type MeAppSignal struct {
	ID      string `gorm:"column:id;size:36;primaryKey"                                                json:"id"`
	UserSub string `gorm:"column:user_sub;size:36;not null;index:idx_meappsignal_q,priority:1"       json:"user_sub"`
	App     string `gorm:"column:app;size:128;not null;index:idx_meappsignal_q,priority:2"           json:"app"`
	Loop    string `gorm:"column:loop;size:128"                                                        json:"loop,omitempty"`
	// Rec is the signalRecord JSON exactly as the runner appends it.
	Rec         string     `gorm:"column:rec;type:mediumtext"                                                  json:"-"`
	Status      string     `gorm:"column:status;size:16;not null;default:pending;index:idx_meappsignal_q,priority:3" json:"status"`
	Attempts    int        `gorm:"column:attempts;not null;default:0"                                          json:"attempts"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime"                                            json:"created_at"`
	ClaimedAt   *time.Time `gorm:"column:claimed_at"                                                           json:"claimed_at,omitempty"`
	DeliveredAt *time.Time `gorm:"column:delivered_at"                                                         json:"delivered_at,omitempty"`
}

func (MeAppSignal) TableName() string { return "me_app_signals" }
