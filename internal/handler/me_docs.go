package handler

// Shared CRUD over models.MeDoc — the DB-backed store for the per-user JSON
// documents (chats, personas, artifacts) that used to live as files under
// tenantRoot(user)/.{chats,personas,artifacts}. See models/me_doc.go for why
// the file stores had to go (2-replica HA flapping on pod-local disks).
//
// Handlers keep marshalling their own record shapes; these helpers only move
// opaque JSON strings keyed (user_sub, kind, doc_id).

import (
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// MeDoc kinds — one per legacy file store.
const (
	meDocKindChat     = "chat"
	meDocKindPersona  = "persona"
	meDocKindArtifact = "artifact"
)

// meDocGet returns the raw JSON doc. Missing row → ("", false, nil) so
// callers decide whether that's a 404 (mirrors the old os.ErrNotExist split).
func meDocGet(userSub, kind, id string) (string, bool, error) {
	var d models.MeDoc
	err := common.DB.First(&d, "user_sub = ? AND kind = ? AND doc_id = ?", userSub, kind, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return d.Doc, true, nil
}

// meDocSave upserts one doc. On conflict only doc + updated_at move so the
// row's created_at stays first-write (records carry their own created_at in
// the JSON anyway — the column is bookkeeping).
func meDocSave(userSub, kind, id, doc string) error {
	row := models.MeDoc{UserSub: userSub, Kind: kind, DocID: id, Doc: doc}
	return common.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_sub"}, {Name: "kind"}, {Name: "doc_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"doc", "updated_at"}),
	}).Create(&row).Error
}

// meDocList returns all docs for (user, kind), newest-updated first.
func meDocList(userSub, kind string) ([]models.MeDoc, error) {
	var rows []models.MeDoc
	err := common.DB.
		Where("user_sub = ? AND kind = ?", userSub, kind).
		Order("updated_at DESC").
		Find(&rows).Error
	return rows, err
}

// meDocDelete removes one doc. Missing row → (false, nil) so callers keep
// the old 404-on-nonexistent behavior.
func meDocDelete(userSub, kind, id string) (bool, error) {
	res := common.DB.
		Where("user_sub = ? AND kind = ? AND doc_id = ?", userSub, kind, id).
		Delete(&models.MeDoc{})
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

// meDocPrune deletes the oldest docs when the user has more than `keep`.
// Best-effort — errors swallowed; called in a goroutine after each save so
// the foreground request stays fast. Mirrors the old mtime-based file prune.
func meDocPrune(userSub, kind string, keep int) {
	var ids []string
	if err := common.DB.Model(&models.MeDoc{}).
		Where("user_sub = ? AND kind = ?", userSub, kind).
		Order("updated_at ASC").
		Pluck("doc_id", &ids).Error; err != nil {
		return
	}
	if len(ids) <= keep {
		return
	}
	common.DB.
		Where("user_sub = ? AND kind = ? AND doc_id IN ?", userSub, kind, ids[:len(ids)-keep]).
		Delete(&models.MeDoc{})
}
