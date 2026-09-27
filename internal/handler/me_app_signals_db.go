package handler

// DB-backed trajectory control signals — see models/me_app_signal.go.
//
// Producer : MeTrajectorySignal / toolBranchRun, for an install identity cannot
//            see (ownerWriteTarget viaIntent). An on-prem identity that mounts
//            the install keeps appending to signals.jsonl directly.
// Consumer : the runner, at cycle start, over the two X-Bridge-Secret routes
//            below (claim → append to its signals.jsonl → ack).
//
// The write is immediate and durable — a row, not a queued file edit — so the
// handlers answer 200 `recorded` with a real pending count, as the direct path
// always did.
//
// Status shown to readers (MeTrajectorySignals): pending and claimed both read
// "pending" (a claimed row has been handed to a starting cycle but not acked;
// if that cycle dies it is re-delivered, so it has not steered anything yet),
// delivered reads "delivered" (appended to the install's signals.jsonl; the
// runner flips it to "consumed" there when the branch runs).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	appSignalClaimCap   = 50
	appSignalStaleClaim = 10 * time.Minute
	appSignalAckMax     = 500
)

// insertAppSignal records one pending signal for (user, app).
func insertAppSignal(userSub, app string, rec signalRecord) (string, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	row := models.MeAppSignal{
		ID:      uuid.New().String(),
		UserSub: userSub,
		App:     app,
		Loop:    rec.Loop,
		Rec:     string(b),
		Status:  "pending",
	}
	if err := common.DB.Create(&row).Error; err != nil {
		return "", err
	}
	return row.ID, nil
}

// appSignalPendingCount is the number of this user's signals for app that have
// not yet been delivered to a run (pending + claimed).
func appSignalPendingCount(userSub, app string) int64 {
	var n int64
	if common.DB == nil {
		return 0
	}
	common.DB.Model(&models.MeAppSignal{}).
		Where("user_sub = ? AND app = ? AND status IN ?", userSub, app, []string{"pending", "claimed"}).
		Count(&n)
	return n
}

// appSignalsFromDB is the DB twin of readSignals: the newest signalTailCap
// records (returned oldest-first, like the file tail), filtered by loop the
// same way — an empty query loop matches everything, a record with no loop
// matches any query loop.
func appSignalsFromDB(userSub, app, loop string) []signalRecord {
	out := []signalRecord{}
	if common.DB == nil {
		return out
	}
	q := common.DB.Where("user_sub = ? AND app = ?", userSub, app)
	if loop != "" {
		q = q.Where("(`loop` = '' OR `loop` IS NULL OR `loop` = ?)", loop) // reserved word
	}
	var rows []models.MeAppSignal
	if q.Order("created_at desc").Order("id desc").Limit(signalTailCap).Find(&rows).Error != nil {
		return out
	}
	for i := len(rows) - 1; i >= 0; i-- {
		var rec signalRecord
		if json.Unmarshal([]byte(rows[i].Rec), &rec) != nil {
			continue
		}
		rec.Status = signalDBStatus(rows[i].Status)
		out = append(out, rec)
	}
	return out
}

// signalDBStatus maps a queue state to the record status readers see.
func signalDBStatus(s string) string {
	if s == "delivered" {
		return "delivered"
	}
	return "pending"
}

type appSignalClaimReq struct {
	UserSub string `json:"user_sub"`
	App     string `json:"app"`
}

type claimedAppSignal struct {
	ID  string          `json:"id"`
	Rec json.RawMessage `json:"rec"`
}

// InternalAppSignalsClaim — POST /api/v1/internal/app-signals/claim
// (X-Bridge-Secret). Body {user_sub, app}. Atomically takes this user's+app's
// pending signals — plus claims older than appSignalStaleClaim that were never
// acked (the cycle died between claim and ack) — marks them claimed and returns
// them oldest-first, at most appSignalClaimCap.
func InternalAppSignalsClaim(c *gin.Context) {
	var req appSignalClaimReq
	if err := c.ShouldBindJSON(&req); err != nil || req.UserSub == "" || !slugRe.MatchString(req.App) {
		fail(c, http.StatusBadRequest, 1400, "user_sub and a valid app are required")
		return
	}
	out := []claimedAppSignal{}
	stale := time.Now().Add(-appSignalStaleClaim)
	err := retryTxConflict("[app-signals] claim", func() error {
		out = out[:0]
		return common.DB.Transaction(func(tx *gorm.DB) error {
			var rows []models.MeAppSignal
			if err := tx.
				Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
				Where("user_sub = ? AND app = ?", req.UserSub, req.App).
				Where("(status = ? OR (status = ? AND claimed_at < ?))", "pending", "claimed", stale).
				Order("created_at asc").Order("id asc").
				Limit(appSignalClaimCap).
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
			if err := tx.Model(&models.MeAppSignal{}).Where("id IN ?", ids).
				Updates(map[string]any{
					"status":     "claimed",
					"claimed_at": time.Now(),
					"attempts":   gorm.Expr("attempts + 1"),
				}).Error; err != nil {
				return err
			}
			for i := range rows {
				rec := json.RawMessage(rows[i].Rec)
				if !json.Valid(rec) {
					rec = json.RawMessage(`{}`)
				}
				out = append(out, claimedAppSignal{ID: rows[i].ID, Rec: rec})
			}
			return nil
		})
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "claim: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"signals": out})
}

type appSignalAckReq struct {
	UserSub string   `json:"user_sub"`
	IDs     []string `json:"ids"`
}

// InternalAppSignalsAck — POST /api/v1/internal/app-signals/ack
// (X-Bridge-Secret). Body {user_sub, ids}. Marks the given signals delivered;
// ids that are not this user's are ignored.
func InternalAppSignalsAck(c *gin.Context) {
	var req appSignalAckReq
	if err := c.ShouldBindJSON(&req); err != nil || req.UserSub == "" {
		fail(c, http.StatusBadRequest, 1400, "user_sub and ids are required")
		return
	}
	ids := make([]string, 0, len(req.IDs))
	for _, id := range req.IDs {
		if meIntentIDRe.MatchString(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) > appSignalAckMax {
		fail(c, http.StatusBadRequest, 1400, "too many ids")
		return
	}
	if len(ids) == 0 {
		ok(c, "ok", gin.H{"acked": 0})
		return
	}
	var n int64
	err := retryTxConflict("[app-signals] ack", func() error {
		res := common.DB.Model(&models.MeAppSignal{}).
			Where("user_sub = ? AND id IN ? AND status <> ?", req.UserSub, ids, "delivered").
			Updates(map[string]any{"status": "delivered", "delivered_at": time.Now()})
		n = res.RowsAffected
		return res.Error
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "ack: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"acked": n})
}
