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
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
	"run_loop":       true, // cycle's auto_publish pushes to the user's xpcloud repo
}

const (
	claimBatchSize  = 16               // max intents claimed per picker poll
	staleClaimAfter = 10 * time.Minute // claimed-but-not-completed → re-queue (picker crash)
	// maxClaimAttempts bounds that re-queue. staleClaimAfter assumes the PICKER
	// died for reasons unrelated to the intent, so retrying is free. When the
	// intent's own work is what kills the picker, that assumption inverts and
	// the retry becomes a poison pill: claim → crash → re-queue → claim, every
	// staleClaimAfter, forever, taking every other in-flight loop with it each
	// time. Observed 2026-08-12: one venue-link-matcher.match_cycle run_loop
	// intent OOM-killed lumid-scheduler 13 times over ~2h before an operator
	// killed it by hand.
	//
	// 3 is enough to ride out genuine picker crashes (pod eviction, rollout,
	// node drain) while capping a self-inflicted loop at three blast radii.
	maxClaimAttempts = 3
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
	// Burn out poison pills BEFORE re-queueing, so an intent that has already
	// had maxClaimAttempts goes to `failed` instead of round-tripping again.
	// Ordering matters: re-queue first and the offender is pending again before
	// anything counts it.
	stale := time.Now().Add(-staleClaimAfter)
	if res := common.DB.Model(&models.MeAppIntent{}).
		Where("status = ? AND claimed_at < ? AND attempts >= ?", "claimed", stale, maxClaimAttempts).
		Updates(map[string]any{
			"status": "failed",
			"result": `{"ok":false,"error":"abandoned after ` +
				strconv.Itoa(maxClaimAttempts) +
				` claims without a result — the picker died every time it ran this intent, ` +
				`so it is being treated as the cause rather than a victim"}`,
			"completed_at": time.Now(),
		}); res.Error == nil && res.RowsAffected > 0 {
		log.Printf("me-intents: abandoned %d poison-pill intent(s) after %d claims with no result",
			res.RowsAffected, maxClaimAttempts)
	}

	// Re-queue crashed claims first (best effort, own statement).
	common.DB.Model(&models.MeAppIntent{}).
		Where("status = ? AND claimed_at < ?", "claimed", stale).
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
		// attempts is incremented in the SAME statement that claims, so a picker
		// that dies before reporting still leaves the count advanced — that is
		// precisely the case the poison-pill guard needs to see.
		if err := tx.Model(&models.MeAppIntent{}).Where("id IN ?", ids).
			Updates(map[string]any{
				"status":     "claimed",
				"claimed_at": time.Now(),
				"attempts":   gorm.Expr("attempts + 1"),
			}).Error; err != nil {
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
			// An lqt-mailbox deploy needs an `lqt:strategy`-SCOPED PAT, which the
			// login JWT in `bearer` is not — see lqt_strategy_pat.go. Merged here,
			// never persisted, exactly like `bearer`.
			attachLQTStrategyPAT(rows[i].Action, rows[i].UserSub, p)
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

// ── Retryable write conflicts ────────────────────────────────────────────────
//
// MySQL 1213 (deadlock) and 1205 (lock wait timeout) are RETRYABLE BY DESIGN —
// the server's own message says "try restarting transaction". They are not
// failures of the request, they are the server picking a victim so someone can
// make progress, and the victim is expected to come back.
//
// This path had no retry, so a deadlock surfaced as a 500 and the cycle's
// result was DISCARDED. Measured 2026-08-31: a home-k3s cycle Job ran
// successfully, produced a real digest, posted its result, and got
//
//	me_intents_db.go:216 Error 1213 (40001): Deadlock found when trying to get
//	lock; try restarting transaction
//
// The intent stayed un-completed, the run never reached me_app_runs, and every
// surface that reads it (studio trajectory, experiments, the cohort-submissions
// reviewer view) showed silence. The work was done and then thrown away.
//
// The contention is structural, not incidental: InternalMeIntentsClaim holds
// `FOR UPDATE SKIP LOCKED` over me_app_intents while draining, and this handler
// updates the same rows as cycles finish. Concurrent drains and completions
// will keep meeting.
//
// Matched on the error TEXT rather than a typed *mysql.MySQLError because the
// driver is an indirect dependency here; promoting it to direct for two error
// numbers would churn go.mod/go.sum in a repo other sessions share. Both the
// numeric code and the server's wording are matched, so a driver that reformats
// one still trips the other.
const (
	meIntentTxAttempts = 4
	meIntentTxBackoff  = 25 * time.Millisecond
)

func isRetryableTxConflict(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, needle := range []string{
		"Error 1213", "Deadlock found", "try restarting transaction",
		"Error 1205", "Lock wait timeout exceeded",
	} {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

// retryTxConflict runs fn until it succeeds, fails for a non-retryable reason,
// or the attempt budget is spent. Backoff is jittered so two victims of the
// same deadlock do not retry in lockstep and deadlock again.
func retryTxConflict(what string, fn func() error) error {
	var err error
	for attempt := 1; attempt <= meIntentTxAttempts; attempt++ {
		if err = fn(); !isRetryableTxConflict(err) {
			if attempt > 1 && err == nil {
				log.Printf("[me-intents] %s succeeded on attempt %d after a retryable conflict", what, attempt)
			}
			return err
		}
		if attempt == meIntentTxAttempts {
			break
		}
		// 25ms, 50ms, 100ms — plus up to 100% jitter.
		backoff := meIntentTxBackoff << (attempt - 1)
		time.Sleep(backoff + time.Duration(rand.Int63n(int64(backoff)+1)))
	}
	log.Printf("[me-intents] %s exhausted %d attempts against a retryable conflict: %v", what, meIntentTxAttempts, err)
	return err
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
	var rowsAffected int64
	err := retryTxConflict("intent result "+id, func() error {
		res := common.DB.Model(&models.MeAppIntent{}).Where("id = ?", id).
			Updates(map[string]any{"status": status, "result": string(rb), "completed_at": time.Now()})
		rowsAffected = res.RowsAffected
		return res.Error
	})
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "result: "+err.Error())
		return
	}
	if rowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "intent not found")
		return
	}
	ok_(c, "recorded", gin.H{"intent_id": id, "status": status})
}
