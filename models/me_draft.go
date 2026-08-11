package models

import "time"

// MeDraft — a staged item awaiting human review (an agent-written outbox draft,
// or a correction recorded against an app).
//
// Drafts live as files under `tenantAppsDir(user)/<app>/…` today. That works on
// one host and fails on UKS for the same reason chats did before v0.5.2: a
// CLOUD-installed tenant app has no directory on identity's filesystem at all,
// so its drafts can neither be listed nor written. The materialised bundle cache
// does not help — it is deliberately read-only, because a write into a copy that
// gets refreshed is a silent data-loss bug.
//
// Same shape of fix as models.MeChat, and deliberately the same shape of model:
// the fields a reviewer lists are columns, the rest rides in a JSON blob so the
// stored form does not have to track every producer's payload.
type MeDraft struct {
	ID      string `gorm:"column:id;size:64;primaryKey"                                            json:"id"`
	UserSub string `gorm:"column:user_sub;size:36;index:idx_medraft_user_app,priority:1;not null"  json:"user_sub"`
	App     string `gorm:"column:app;size:128;index:idx_medraft_user_app,priority:2"               json:"app"`

	// Which agent produced it — a correction is attributed to the app's analyst,
	// a scored claim to its judge. Reviewers filter on this.
	Agent string `gorm:"column:agent;size:128;index" json:"agent,omitempty"`
	// Cycle this came from, when it came from one. Empty for an interactive
	// correction — which is exactly the case give_feedback could not serve,
	// since it requires loop + ts.
	CycleTS string `gorm:"column:cycle_ts;size:64" json:"cycle_ts,omitempty"`

	To         string  `gorm:"column:to_addr;size:255"  json:"to,omitempty"`
	Subject    string  `gorm:"column:subject;size:512"  json:"subject,omitempty"`
	Body       string  `gorm:"column:body;type:longtext" json:"body,omitempty"`
	Confidence float64 `gorm:"column:confidence"         json:"confidence,omitempty"`

	// pending | approved | rejected. Staged is the default for anything a judge
	// produced: a claim about quality gets a human behind it before it compounds.
	State   string `gorm:"column:state;size:32;index" json:"state"`
	ActedAt string `gorm:"column:acted_at;size:64"    json:"acted_at,omitempty"`

	// Producer-specific payload, kept opaque for the same reason MeChat.Messages
	// is: pinning it to columns would put storage in lockstep with every
	// producer's format.
	Meta string `gorm:"column:meta;type:longtext" json:"-"`

	CreatedAt time.Time `gorm:"column:created_at;index" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"       json:"updated_at"`
}

func (MeDraft) TableName() string { return "me_drafts" }
