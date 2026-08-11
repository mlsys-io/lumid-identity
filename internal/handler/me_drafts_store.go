package handler

// Draft storage — DB-backed, mirroring the chat store.
//
// Drafts live as files under tenantAppsDir(user)/<app>/… which works on one
// host and fails on UKS: a CLOUD-installed tenant app has no directory on
// identity's filesystem, so its drafts can neither be listed nor written. The
// materialised bundle cache does not help — it is read-only by design, since a
// write into a copy that gets refreshed is silent data loss.
//
// NOT YET WIRED. MeDraftsList and the write path still read files; this module
// is the prepared replacement so the swap is one reviewable change rather than
// a half-migrated state where some drafts are files and some are rows.

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// draftStoreList returns a caller's drafts, newest first, optionally narrowed
// to one app and/or state.
func draftStoreList(userSub, app, state string) ([]models.MeDraft, error) {
	q := common.DB.Where("user_sub = ?", userSub)
	if app != "" {
		q = q.Where("app = ?", app)
	}
	if state != "" {
		q = q.Where("state = ?", state)
	}
	var rows []models.MeDraft
	err := q.Order("created_at DESC").Find(&rows).Error
	return rows, err
}

// draftStoreStage records a new draft awaiting review. Staging is the default
// for anything a judge produced: an unreviewed score does not just sit there,
// it biases the retrieval shaping the next answer.
func draftStoreStage(d *models.MeDraft) error {
	if d.UserSub == "" || d.App == "" {
		return errors.New("user_sub and app are required")
	}
	if d.State == "" {
		d.State = "pending"
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	d.UpdatedAt = time.Now().UTC()
	return common.DB.Save(d).Error
}

// draftStoreAct approves or rejects one draft. Scoped by user so a draft id
// alone cannot act on someone else's queue.
func draftStoreAct(userSub, id, state string) error {
	if state != "approved" && state != "rejected" {
		return errors.New(`state must be "approved" or "rejected"`)
	}
	res := common.DB.Model(&models.MeDraft{}).
		Where("id = ? AND user_sub = ?", id, userSub).
		Updates(map[string]any{
			"state":      state,
			"acted_at":   time.Now().UTC().Format(time.RFC3339),
			"updated_at": time.Now().UTC(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// draftStoreCount is what the sidebar badge reads.
func draftStoreCount(userSub, app string) (int64, error) {
	q := common.DB.Model(&models.MeDraft{}).
		Where("user_sub = ? AND state = ?", userSub, "pending")
	if app != "" {
		q = q.Where("app = ?", app)
	}
	var n int64
	err := q.Count(&n).Error
	return n, err
}
