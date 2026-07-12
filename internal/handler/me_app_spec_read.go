package handler

// Cross-node app-spec store — the DB-materialized copy of an installed bundle's
// spec + ui files (models.MeAppSpec). See models/me_app_spec.go for why: on UKS
// identity (svc node) can't mount the scheduler's app PVC, and the previous
// cross-node fallback (the caller's PUBLISHED xp.io repo) structurally excludes
// apps a user INSTALLED but never published. The scheduler install-picker HAS
// the PVC, so it writes the spec here (POST /internal/app-spec) and identity
// reads it — closing the installed-not-published gap the audit flagged.
//
// READ PRECEDENCE for every app-file read is:
//
//	local PVC (resolveAppDir)  — misses cross-node
//	  → MeAppSpec DB           — this store (installed apps, any node)
//	    → published xp.io repo  — fetchRepoSpecYAML / publishedRepoBlob
//
// specForApp is the shared entry point for the DB→published tail of that chain
// (the local-PVC head stays in each caller, which already reads disk first).

import (
	"encoding/json"
	"os"
	"path/filepath"

	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// appInstalledForUser reports whether an app is in the caller's installed set,
// resolvable CROSS-NODE (used by the publish path — ITEM 1). Checks, cheapest
// first: local PVC disk (resolveAppDir), then a materialized spec row
// (MeAppSpec), then a DB install intent for the app. Any hit → installed. This
// replaces the old os.Stat precondition that 404'd when the bundle lived on the
// scheduler PVC identity can't see.
func appInstalledForUser(userSub, app string) bool {
	// 1. On disk (single-node / operator-shared).
	if st, err := os.Stat(filepath.Join(tenantAppsDir(userSub), app)); err == nil && st.IsDir() {
		return true
	}
	// 2. Materialized spec row (the scheduler wrote it post-install).
	var specN int64
	common.DB.Model(&models.MeAppSpec{}).
		Where("user_sub = ? AND app = ?", userSub, app).Count(&specN)
	if specN > 0 {
		return true
	}
	// 3. A DB install intent for this app (queued/claimed/done) — the
	//    node-agnostic install registry pendingInstallCards also reads.
	var rows []models.MeAppIntent
	if err := common.DB.
		Where("user_sub = ? AND action = ?", userSub, "install").
		Order("created_at desc").Limit(200).Find(&rows).Error; err == nil {
		for i := range rows {
			var payload map[string]any
			if rows[i].Payload != "" {
				_ = json.Unmarshal([]byte(rows[i].Payload), &payload)
			}
			if installAppName(payload) == app {
				return true
			}
		}
	}
	return false
}

// meAppSpecGet returns the raw spec bytes + the decoded ui-file map for an
// installed app from the DB store. (nil, nil, false) when no row exists.
func meAppSpecGet(userSub, app string) (specYAML []byte, uiFiles map[string]string, ok bool) {
	var row models.MeAppSpec
	err := common.DB.First(&row, "user_sub = ? AND app = ?", userSub, app).Error
	if err != nil {
		return nil, nil, false // includes gorm.ErrRecordNotFound
	}
	files := map[string]string{}
	if row.UIFiles != "" {
		_ = json.Unmarshal([]byte(row.UIFiles), &files)
	}
	if row.SpecYAML == "" && len(files) == 0 {
		return nil, nil, false
	}
	return []byte(row.SpecYAML), files, true
}

// meAppSpecSave upserts one app spec row (scheduler-driven, via the internal
// endpoint). uiFiles is stored as a JSON object; a nil map persists as "{}".
func meAppSpecSave(userSub, app, specYAML string, uiFiles map[string]string) error {
	if uiFiles == nil {
		uiFiles = map[string]string{}
	}
	uj, err := json.Marshal(uiFiles)
	if err != nil {
		return err
	}
	// Upsert on the (user_sub, app) PK: refresh spec + ui files + updated_at,
	// keep the original created_at.
	var existing models.MeAppSpec
	tx := common.DB.First(&existing, "user_sub = ? AND app = ?", userSub, app)
	if tx.Error == gorm.ErrRecordNotFound {
		return common.DB.Create(&models.MeAppSpec{
			UserSub: userSub, App: app, SpecYAML: specYAML, UIFiles: string(uj),
		}).Error
	}
	if tx.Error != nil {
		return tx.Error
	}
	existing.SpecYAML = specYAML
	existing.UIFiles = string(uj)
	return common.DB.Save(&existing).Error
}

// specForApp resolves an installed app's spec + a ui-file reader, trying the
// cross-node sources in precedence order: the MeAppSpec DB store FIRST (covers
// installed-not-published apps), then the caller's PUBLISHED xp.io repo. The
// on-disk PVC head is NOT tried here — callers read disk first (resolveAppDir)
// and only fall through to this helper when the bundle isn't locally visible.
//
// Returns (specBytes, blobReader, ok). blobReader(rel) returns the bytes of a
// repo-relative file (e.g. "ui/home.md") from whichever source resolved the
// spec — the DB ui-file map or a published-repo blob fetch — or nil when the
// file isn't available cross-node. ok is false only when NEITHER source has the
// spec.
func specForApp(userID, app string) ([]byte, func(rel string) []byte, bool) {
	// 1. DB store — installed apps on any node, published or not.
	if spec, files, has := meAppSpecGet(userID, app); has {
		reader := func(rel string) []byte {
			if content, ok := files[rel]; ok {
				return []byte(content)
			}
			// The DB store only carries ui/* text files; anything else falls
			// through to the published repo (best-effort) so richer trees still
			// resolve when the app was also published.
			return publishedRepoBlob(userID, app, rel)
		}
		return spec, reader, true
	}
	// 2. Published xp.io repo — self-published apps (the pre-existing fallback).
	if spec, has := fetchRepoSpecYAML(userID, app); has {
		reader := func(rel string) []byte { return publishedRepoBlob(userID, app, rel) }
		return spec, reader, true
	}
	return nil, nil, false
}
