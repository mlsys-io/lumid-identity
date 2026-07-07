package handler

// DB-backed queue for /api/v1/me/apps intents. See models/me_app_intent.go
// for why this replaced the pod-local file queue on UKS.
//
// Producer  : insertIntent (called by writeIntent / writeIntentDirect).
// Consumer  : the scheduler-side me_intent_picker over the two X-Bridge-Secret
//             endpoints below (claim → run → result). The atomic claim uses
//             SELECT ... FOR UPDATE SKIP LOCKED so two pickers never double-run
//             a row.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// meIntentIDRe validates an intent id (UUIDs, plus legacy shapes).
var meIntentIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// actionsNeedingBearer — intents whose picker step clones/pushes the caller's
// xp.io repos, so they need a short-lived user JWT to see PRIVATE repos. Public
// installs work without one; minting is best-effort.
var actionsNeedingBearer = map[string]bool{
	"install":        true,
	"update":         true,
	"publish_app":    true,
	"subscribe_bank": true,
	"add_skill":      true,
}

const (
	claimBatchSize  = 16               // max intents claimed per picker poll
	staleClaimAfter = 10 * time.Minute // claimed-but-not-completed → re-queue (picker crash)
)

// insertIntent enqueues an intent and returns its id. `payload` may carry a
// "bearer" key (agent path pre-mints one); it's split into its own column so
// it never reaches the browser via MeIntentGet. When absent and the action
// needs xpcloud auth, we mint one here so UI-driven installs of the caller's
// PRIVATE repos can clone (this is why plain /me/apps installs of a private
// repo used to 404 even before the queue was broken).
func insertIntent(action, userSub string, payload map[string]any) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	bearer, _ := payload["bearer"].(string)
	delete(payload, "bearer")
	if bearer == "" && actionsNeedingBearer[action] {
		if tok, err := xpcloudUserJWT(userSub); err == nil {
			bearer = tok // best-effort — a miss just means private clones 404 with a clear error
		}
	}
	pj, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	row := models.MeAppIntent{
		ID:      uuid.New().String(),
		Action:  action,
		UserSub: userSub,
		Payload: string(pj),
		Bearer:  bearer,
		Status:  "pending",
	}
	if err := common.DB.Create(&row).Error; err != nil {
		return "", err
	}
	return row.ID, nil
}

type claimedIntent struct {
	IntentID string         `json:"intent_id"`
	Action   string         `json:"action"`
	UserSub  string         `json:"user_sub"`
	Payload  map[string]any `json:"payload"` // bearer merged back in for the picker
}

// InternalMeIntentsClaim — POST /api/v1/internal/me-intents/claim (X-Bridge-Secret).
// Re-queues stale claims, then atomically claims up to claimBatchSize pending
// intents (FOR UPDATE SKIP LOCKED), returning them with bearer merged into
// payload for the picker.
func InternalMeIntentsClaim(c *gin.Context) {
	// Re-queue crashed claims first (best effort, own statement).
	common.DB.Model(&models.MeAppIntent{}).
		Where("status = ? AND claimed_at < ?", "claimed", time.Now().Add(-staleClaimAfter)).
		Updates(map[string]any{"status": "pending", "claimed_at": nil})

	var claimed []claimedIntent
	err := common.DB.Transaction(func(tx *gorm.DB) error {
		var rows []models.MeAppIntent
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ?", "pending").
			Order("created_at asc").
			Limit(claimBatchSize).
			Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		ids := make([]string, 0, len(rows))
		for i := range rows {
			ids = append(ids, rows[i].ID)
		}
		if err := tx.Model(&models.MeAppIntent{}).Where("id IN ?", ids).
			Updates(map[string]any{"status": "claimed", "claimed_at": time.Now()}).Error; err != nil {
			return err
		}
		for i := range rows {
			var p map[string]any
			if rows[i].Payload != "" {
				_ = json.Unmarshal([]byte(rows[i].Payload), &p)
			}
			if p == nil {
				p = map[string]any{}
			}
			if rows[i].Bearer != "" {
				p["bearer"] = rows[i].Bearer
			}
			claimed = append(claimed, claimedIntent{
				IntentID: rows[i].ID,
				Action:   rows[i].Action,
				UserSub:  rows[i].UserSub,
				Payload:  p,
			})
		}
		return nil
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "claim: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"intents": claimed},
	})
}

// InternalMeIntentResult — POST /api/v1/internal/me-intents/:id/result
// (X-Bridge-Secret). Body is the picker's result envelope (arbitrary JSON).
// Marks the row done|failed (via installResultOK) and stores the result for
// MeIntentGet + the My-Apps pending-card status.
func InternalMeIntentResult(c *gin.Context) {
	id := c.Param("id")
	if !meIntentIDRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid intent id")
		return
	}
	var result map[string]any
	if err := c.ShouldBindJSON(&result); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid result body")
		return
	}
	rb, _ := json.Marshal(result)
	status := "failed"
	if ok, _ := installResultOK(rb); ok {
		status = "done"
	}
	res := common.DB.Model(&models.MeAppIntent{}).Where("id = ?", id).
		Updates(map[string]any{"status": status, "result": string(rb), "completed_at": time.Now()})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "result: "+res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "intent not found")
		return
	}
	ok_(c, "recorded", gin.H{"intent_id": id, "status": status})
}
