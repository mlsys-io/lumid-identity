package models

import "time"

// MeAppIntent — the DB-backed queue for /api/v1/me/apps intents
// (install / uninstall / update / add_skill / subscribe_bank / send_draft /
// publish_app).
//
// It replaces the old file queue (~/.lumilake/me-intents/<uuid>.json). That
// queue was written to identity's POD-LOCAL ephemeral filesystem and read
// from the scheduler's POD-LOCAL ephemeral filesystem — two different pods on
// two different nodes with no shared volume, so on UKS the intents never
// crossed and every UI-driven install stalled forever.
//
// The queue now lives in the auth DB (identity is the sole DB authority). The
// scheduler-side picker drains it over the /api/v1/internal/me-intents/*
// endpoints (X-Bridge-Secret gated): a claim does an atomic
// SELECT ... FOR UPDATE SKIP LOCKED so two pickers can't double-run a row,
// runs the action against its own PVC, then posts the result back. No shared
// filesystem, node-agnostic, no DB creds on the scheduler.
//
// Bearer is stored in its OWN column (never merged into Payload) so it is
// never returned to the browser via MeIntentGet — only handed to the picker
// on claim. It's a short-lived (15 min) xpcloud:write bridge JWT that lets
// the picker clone/push the user's PRIVATE repos as that user.
type MeAppIntent struct {
	ID      string `gorm:"column:id;size:36;primaryKey"                                              json:"intent_id"`
	Action  string `gorm:"column:action;size:32;not null;index:idx_meintent_status,priority:2"       json:"action"`
	UserSub string `gorm:"column:user_sub;size:36;not null;index:idx_meintent_user"                  json:"user_sub"`
	Payload string `gorm:"column:payload;type:text"                                                  json:"-"` // JSON (slug/runtime/as/app/...) — no bearer
	Bearer  string `gorm:"column:bearer;type:text"                                                   json:"-"` // short-lived user JWT, picker-only
	// pending → claimed → done | failed
	Status string `gorm:"column:status;size:16;not null;default:pending;index:idx_meintent_status,priority:1" json:"status"`
	Result string `gorm:"column:result;type:text"                                                            json:"-"` // JSON result envelope written on completion
	// Attempts counts how many times this intent has been CLAIMED, including
	// re-claims after a stale-claim re-queue. It exists to bound the retry that
	// staleClaimAfter provides: that re-queue assumes the PICKER died for reasons
	// unrelated to the intent, but an intent whose own work kills the picker
	// turns it into a perpetual motion machine — claim, crash, re-queue, claim.
	// Observed 2026-08-12: one run_loop intent for venue-link-matcher.match_cycle
	// (needs ~900MB against ~880MB of headroom) OOM-killed lumid-scheduler 13
	// times over ~2h, one kill per 10-minute reclaim, taking every other loop
	// down with it each time.
	Attempts    int        `gorm:"column:attempts;not null;default:0"                                                 json:"attempts"`
	CreatedAt   time.Time  `gorm:"column:created_at;autoCreateTime;index:idx_meintent_status,priority:3"               json:"created_at"`
	ClaimedAt   *time.Time `gorm:"column:claimed_at"                                                                   json:"claimed_at,omitempty"`
	CompletedAt *time.Time `gorm:"column:completed_at"                                                                 json:"completed_at,omitempty"`
}

func (MeAppIntent) TableName() string { return "me_app_intents" }
