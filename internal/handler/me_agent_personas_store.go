package handler

// Persona storage. Was per-pod JSON files, now MySQL.
//
// Same reason, and the same shape of fix, as the chat store
// (me_agent_chats_store.go): personas sat under tenantRoot(user)/.personas/ on
// the pod's own container filesystem while lumid-identity runs replicas behind
// a round-robin Service with no shared volume. A persona saved on one pod was
// missing on the other — the list showed it on alternate reloads, a chat turn
// applied it or silently ran without it depending on which pod served the
// turn, and a delete could 404 on the pod that never had it.
//
// No legacy-file fallback, unlike chats: the files were pod-local and died with
// every rollout, so there is nothing durable to migrate.

import (
	"encoding/json"
	"errors"
	"time"

	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const personaTimeFmt = time.RFC3339

func personaToRow(userSub string, p *persona) *models.MePersona {
	tools := ""
	if len(p.AllowedTools) > 0 {
		if b, err := json.Marshal(p.AllowedTools); err == nil {
			tools = string(b)
		}
	}
	return &models.MePersona{
		ID: p.ID, UserSub: userSub,
		Name: p.Name, Icon: p.Icon,
		SystemPrompt:   p.SystemPrompt,
		AllowedTools:   tools,
		PreferredModel: p.PreferredModel,
		CreatedAt:      parseChatTime(p.CreatedAt),
		UpdatedAt:      parseChatTime(p.UpdatedAt),
	}
}

func personaFromRow(m *models.MePersona) *persona {
	p := &persona{
		ID: m.ID, Name: m.Name, Icon: m.Icon,
		SystemPrompt:   m.SystemPrompt,
		PreferredModel: m.PreferredModel,
		CreatedAt:      m.CreatedAt.UTC().Format(personaTimeFmt),
		UpdatedAt:      m.UpdatedAt.UTC().Format(personaTimeFmt),
	}
	if m.AllowedTools != "" {
		_ = json.Unmarshal([]byte(m.AllowedTools), &p.AllowedTools)
	}
	return p
}

// personaStoreGet returns one persona, or (nil, nil) when it does not exist.
// Scoped by user so an id alone never reads someone else's prompt.
func personaStoreGet(userSub, id string) (*persona, error) {
	var m models.MePersona
	err := common.DB.Where("id = ? AND user_sub = ?", id, userSub).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return personaFromRow(&m), nil
}

// personaStoreList returns the caller's personas, newest-updated first.
func personaStoreList(userSub string) ([]*persona, error) {
	var rows []models.MePersona
	if err := common.DB.Where("user_sub = ?", userSub).
		Order("updated_at DESC").Limit(personasKeep * 2).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*persona, 0, len(rows))
	for i := range rows {
		out = append(out, personaFromRow(&rows[i]))
	}
	return out, nil
}

// personaStoreSave upserts one persona.
func personaStoreSave(userSub string, p *persona) error {
	return common.DB.Save(personaToRow(userSub, p)).Error
}

// personaStoreDelete removes one persona; found=false when there was none.
func personaStoreDelete(userSub, id string) (bool, error) {
	res := common.DB.Where("id = ? AND user_sub = ?", id, userSub).Delete(&models.MePersona{})
	return res.RowsAffected > 0, res.Error
}

// prunePersonas keeps only the `keep` newest personas (by updated_at) —
// the soft cap the file store enforced by mtime.
func prunePersonas(userSub string, keep int) {
	var stale []string
	if err := common.DB.Model(&models.MePersona{}).
		Where("user_sub = ?", userSub).
		Order("updated_at DESC").Offset(keep).Limit(1000).
		Pluck("id", &stale).Error; err != nil || len(stale) == 0 {
		return
	}
	common.DB.Where("user_sub = ? AND id IN ?", userSub, stale).Delete(&models.MePersona{})
}
