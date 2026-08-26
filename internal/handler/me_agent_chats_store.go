package handler

// Chat storage. Was per-pod JSON files, now MySQL.
//
// The files sat on the pod's own container filesystem while lumid-identity runs
// replicas: 2 behind a round-robin Service with no shared volume. A thread
// saved on one pod simply did not exist on the other, so roughly half of all
// follow-up reads 404'd — reloads lost the transcript and multi-turn threads
// only stayed coherent when consecutive requests happened to land on the same
// pod. Nothing about that failure looked like a bug from inside one pod, which
// is why it survived: each replica was internally consistent.
//
// Reads fall back to the local file and migrate it in on the way past, so
// existing transcripts are not stranded on whichever pod happens to hold them.
// That fallback is load-bearing exactly once per chat and then never again.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const chatTimeFmt = time.RFC3339

func parseChatTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	if t, err := time.Parse(chatTimeFmt, s); err == nil {
		return t
	}
	return time.Now().UTC()
}

// toRow flattens a chatRecord for storage. Messages stay JSON-as-is.
func toRow(userSub string, r *chatRecord) (*models.MeChat, error) {
	blob, err := json.Marshal(r.Messages)
	if err != nil {
		return nil, err
	}
	return &models.MeChat{
		ID: r.ID, UserSub: userSub,
		Title: r.Title, TitleSummary: r.TitleSummary,
		Model: r.Model, Mode: r.Mode, App: r.App,
		StrategyID:      r.StrategyID,
		ClaudeSessionID: r.ClaudeSessionID,
		MsgCount:        len(r.Messages),
		Messages:        string(blob),
		CreatedAt:       parseChatTime(r.CreatedAt),
		UpdatedAt:       parseChatTime(r.UpdatedAt),
	}, nil
}

func fromRow(m *models.MeChat) *chatRecord {
	r := &chatRecord{
		ID: m.ID, Title: m.Title, TitleSummary: m.TitleSummary,
		Model: m.Model, Mode: m.Mode, App: m.App,
		StrategyID:      m.StrategyID,
		ClaudeSessionID: m.ClaudeSessionID,
		CreatedAt:       m.CreatedAt.UTC().Format(chatTimeFmt),
		UpdatedAt:       m.UpdatedAt.UTC().Format(chatTimeFmt),
	}
	if m.Messages != "" {
		// A row whose blob failed to parse still lists (title, timestamps are
		// columns) — better a thread with no body than a 500 on the whole list.
		_ = json.Unmarshal([]byte(m.Messages), &r.Messages)
	}
	return r
}

// chatStoreSave upserts one transcript.
func chatStoreSave(userSub string, r *chatRecord) error {
	row, err := toRow(userSub, r)
	if err != nil {
		return err
	}
	return common.DB.Save(row).Error
}

// chatStoreGet returns one transcript, migrating a legacy file on first read.
func chatStoreGet(userSub, id string) (*chatRecord, error) {
	var m models.MeChat
	err := common.DB.Where("id = ? AND user_sub = ?", id, userSub).First(&m).Error
	if err == nil {
		return fromRow(&m), nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if rec := readLegacyChatFile(userSub, id); rec != nil {
		// Best-effort migrate; a failure here must not fail the read.
		_ = chatStoreSave(userSub, rec)
		return rec, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// chatStoreList returns the caller's transcripts, newest-updated first, with
// any legacy files on THIS pod merged in (and migrated) so nothing disappears
// mid-rollout.
func chatStoreList(userSub string) ([]*chatRecord, error) {
	var rows []models.MeChat
	if err := common.DB.Where("user_sub = ?", userSub).
		Order("updated_at DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*chatRecord, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for i := range rows {
		out = append(out, fromRow(&rows[i]))
		seen[rows[i].ID] = true
	}
	for _, rec := range readLegacyChatDir(userSub) {
		if seen[rec.ID] {
			continue
		}
		_ = chatStoreSave(userSub, rec)
		out = append(out, rec)
	}
	return out, nil
}

func chatStoreDelete(userSub, id string) error {
	// Remove the legacy file too, or the next list would migrate it straight
	// back and the delete would look like it silently failed.
	if p := chatPath(userSub, id); p != "" {
		_ = os.Remove(p)
	}
	return common.DB.Where("id = ? AND user_sub = ?", id, userSub).
		Delete(&models.MeChat{}).Error
}

// chatStorePrune keeps the newest `keep` transcripts.
func chatStorePrune(userSub string, keep int) {
	if keep <= 0 {
		return
	}
	var ids []string
	if err := common.DB.Model(&models.MeChat{}).
		Where("user_sub = ?", userSub).
		Order("updated_at DESC").Offset(keep).Pluck("id", &ids).Error; err != nil || len(ids) == 0 {
		return
	}
	common.DB.Where("user_sub = ? AND id IN ?", userSub, ids).Delete(&models.MeChat{})
}

// ─── legacy file readers (migration only) ────────────────────────────────

func readLegacyChatFile(userSub, id string) *chatRecord {
	p := chatPath(userSub, id)
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var r chatRecord
	if json.Unmarshal(b, &r) != nil || r.ID == "" {
		return nil
	}
	return &r
}

func readLegacyChatDir(userSub string) []*chatRecord {
	dir := chatsDir(userSub)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []*chatRecord
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r chatRecord
		if json.Unmarshal(b, &r) != nil || r.ID == "" {
			continue
		}
		out = append(out, &r)
	}
	return out
}
