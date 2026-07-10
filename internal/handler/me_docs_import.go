package handler

// One-shot legacy import: file stores → me_docs.
//
// Before models.MeDoc, chats/personas/artifacts lived as one file each under
//   ~/.tenants/<userSub>/.chats/<id>.json
//   ~/.tenants/<userSub>/.personas/<id>.json
//   ~/.tenants/<userSub>/.artifacts/<id>.json
// on the identity pod's LOCAL filesystem. With replicas=2 each pod holds a
// disjoint subset of the user's docs. Both replicas run this at boot with
// OnConflict DoNothing, so the union of both pods' files heals into the DB —
// whoever inserts a given (user, kind, id) first wins; the other pod skips.
//
// File mtime becomes updated_at/created_at (set explicitly — GORM's
// autoCreateTime/autoUpdateTime only fill zero values, so the explicit
// timestamps survive the insert) so list ordering matches what each pod
// showed before the migration. Files are left in place (read-only import);
// they simply stop being consulted.

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// legacyMeDocDirs — dot-dir name under tenantRoot → me_docs kind.
var legacyMeDocDirs = map[string]string{
	".chats":     meDocKindChat,
	".personas":  meDocKindPersona,
	".artifacts": meDocKindArtifact,
}

// ImportLegacyMeDocs walks every tenant dir and inserts each legacy JSON file
// into me_docs (OnConflict DoNothing). Idempotent; safe to run on every boot.
// Called from main right after AutoMigrate — non-fatal on error.
func ImportLegacyMeDocs() error {
	tenantsRoot := filepath.Join(operatorHome(), ".tenants")
	tenants, err := os.ReadDir(tenantsRoot)
	if os.IsNotExist(err) {
		return nil // fresh host — nothing to import
	}
	if err != nil {
		return err
	}
	imported, skipped := 0, 0
	for _, t := range tenants {
		if !t.IsDir() {
			continue
		}
		userSub := t.Name()
		for dirName, kind := range legacyMeDocDirs {
			dir := filepath.Join(tenantsRoot, userSub, dirName)
			files, err := os.ReadDir(dir)
			if err != nil {
				continue // no such store for this tenant
			}
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, f.Name()))
				if err != nil {
					skipped++
					continue
				}
				info, err := f.Info()
				if err != nil {
					skipped++
					continue
				}
				mtime := info.ModTime()
				row := models.MeDoc{
					UserSub:   userSub,
					Kind:      kind,
					DocID:     strings.TrimSuffix(f.Name(), ".json"),
					Doc:       string(b),
					CreatedAt: mtime,
					UpdatedAt: mtime,
				}
				res := common.DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
				switch {
				case res.Error != nil:
					skipped++
				case res.RowsAffected == 0:
					skipped++ // already in the DB (other replica got here first)
				default:
					imported++
				}
			}
		}
	}
	log.Printf("me_docs legacy import: imported %d, skipped %d", imported, skipped)
	return nil
}
