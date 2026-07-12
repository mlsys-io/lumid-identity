package models

import "time"

// MeAppSpec — the DB-materialized copy of an installed app bundle's spec
// (xpcloud.yaml) plus its ui/* files, written by the scheduler install-picker
// so identity can read app files CROSS-NODE.
//
// Why: on UKS the tenant install lives on the SCHEDULER pod's PVC (compute
// tier, RWO). identity (svc tier, a different node) can't mount it. Until now
// the only cross-node fallback was the caller's PUBLISHED xp.io repo
// (fetchRepoSpecYAML / publishedRepoBlob) — which structurally excludes apps a
// user INSTALLED but never published (the ceiling the cross-node audit flagged).
// The scheduler HAS the PVC at install time, so it POSTs the spec + ui files
// here (POST /api/v1/internal/app-spec); identity reads them without a shared
// filesystem, and installed-not-published apps resolve just like self-published
// ones.
//
// ui_files is a JSON object mapping repo-relative path → file content, holding
// the small text surfaces identity needs to serve (ui/*.md + ui/*.yaml). Both
// columns are LONGTEXT — a page.yaml + several markdown surfaces can exceed 64KB.
// Keyed (user_sub, app); the scheduler upserts on every (re)install.
type MeAppSpec struct {
	UserSub string `gorm:"column:user_sub;size:36;not null;primaryKey" json:"user_sub"`
	App     string `gorm:"column:app;size:64;not null;primaryKey"      json:"app"`

	SpecYAML  string    `gorm:"column:spec_yaml;type:longtext"   json:"spec_yaml"`
	UIFiles   string    `gorm:"column:ui_files;type:longtext"    json:"ui_files"` // JSON: {rel_path: content}
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime" json:"updated_at"`
}

func (MeAppSpec) TableName() string { return "me_app_specs" }
