package models

import "time"

// MeArtifact — the DB-backed store for Studio chat artifacts (output of
// save_artifact / generate_image / text_to_speech / deep_research dumps /
// code_run listings).
//
// It replaces the old pod-local file store (~/.tenants/<userID>/.artifacts/
// <id>.json). That store lived on identity's POD-LOCAL ephemeral filesystem;
// with the DELIBERATE 2 replicas and no shared PVC, list + GET-by-id flapped
// 200/404 depending on which pod served — a generated image only appeared if
// the request happened to hit the pod that created it. The DB (identity is the
// sole DB authority) is node-agnostic so every replica sees every artifact.
//
// Content is LONGTEXT: text kinds are small (≤256 KB) but image/audio kinds
// carry a self-contained data: URL up to ~12 MB (base64 PNG / audio).
type MeArtifact struct {
	ID         string    `gorm:"column:id;size:36;primaryKey"                              json:"id"`
	UserSub    string    `gorm:"column:user_sub;size:36;not null;index:idx_meart_user,priority:1" json:"-"`
	Kind       string    `gorm:"column:kind;size:16;not null"                             json:"kind"`
	Title      string    `gorm:"column:title;size:255"                                    json:"title"`
	Language   string    `gorm:"column:language;size:32"                                  json:"language,omitempty"`
	Content    string    `gorm:"column:content;type:longtext"                             json:"content"`
	SourceTool string    `gorm:"column:source_tool;size:64"                               json:"source_tool,omitempty"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime;index:idx_meart_user,priority:2" json:"-"`
}

func (MeArtifact) TableName() string { return "me_artifacts" }
