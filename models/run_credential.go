package models

import "time"

// RunCredential is a per-run REFRESH credential (`lm_runref_*`).
//
// The scheduler daemon mints one (bridge-secret call) for each TENANT cycle it
// launches and hands it to the cycle as LUMID_RUN_REFRESH, so the cycle never
// needs identity's bridge secret. It can do exactly two things:
//
//   - be exchanged at POST /api/v1/run-credential/refresh for a short-lived
//     lum.id bearer (aud lumid-ecosystem, 15 min) for UserID — never anyone else;
//   - authenticate the handful of /internal run-reporting routes a cycle calls
//     (app-runs, app-experiments, app-signals, usage/charge, the intent result),
//     each refusing a write for any other user (and, when App is set, any
//     other app).
//
// It is NOT a PAT: the prefix deliberately does not start with `lm_pat_`, so
// introspect, currentUserID and every consumer that classifies tokens by shape
// refuse it. Stored as a SHA-256 hash only; the raw value is returned once.
type RunCredential struct {
	ID         string     `gorm:"type:varchar(36);primaryKey" json:"id"`
	TokenHash  string     `gorm:"type:char(64);uniqueIndex;not null" json:"-"`
	UserID     string     `gorm:"type:varchar(36);index;not null" json:"user_id"`
	App        string     `gorm:"type:varchar(128)" json:"app,omitempty"`
	Loop       string     `gorm:"type:varchar(128)" json:"loop,omitempty"`
	IntentID   string     `gorm:"type:varchar(64)" json:"intent_id,omitempty"` // Run-now intent this run reports to; "" for a scheduled run
	ExpiresAt  time.Time  `gorm:"index;not null" json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `gorm:"autoCreateTime" json:"created_at"`
}

func (RunCredential) TableName() string { return "run_credentials" }
