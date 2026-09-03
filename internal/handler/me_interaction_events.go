package handler

// Studio surface interaction capture.
//
//   POST /me/interaction-events   — record what the caller just did
//   GET  /admin/apps/:app/interactions — read it back, cross-tenant (admin)
//
// WHY A CLOSED VOCABULARY. An events endpoint that accepts arbitrary names is a
// logging sink within a month: everything gets sent, nobody can say what any of
// it means, and the table grows past the point where anyone dares prune it.
// Rejecting an unknown action is what keeps this answerable.
//
// WHAT IT DELIBERATELY DOES NOT STORE. No form values, no strategy source, no
// free text. `target` is a NAME (a loop, an action label), never a value. The
// strategy text already has a home in the mailbox and in
// research.backtest_claims.params_json; copying it here would spread it for no
// added answer.
//
// The caller's identity is taken from the session, never from the body — a
// client cannot attribute an event to someone else.

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// interactionActions is the whole vocabulary. Add deliberately.
var interactionActions = map[string]bool{
	"surface_view": true, // a surface was opened
	"form_submit":  true, // a lumid:form was submitted (target = loop)
	"row_action":   true, // a table row action fired (target = action label)
	"nav":          true, // moved between an app's surfaces
}

const (
	interactionRetention     = 90 * 24 * time.Hour
	interactionReclaimEvery  = 12 * time.Hour
	interactionReclaimBatch  = 20000
	interactionReclaimMaxIte = 50
	// A page could emit these in a loop on a render bug. The /me rate limiter
	// is the general backstop; this is the per-payload one.
	interactionMaxBatch = 20
)

type interactionEventIn struct {
	App        string `json:"app"`
	Action     string `json:"action"`
	Surface    string `json:"surface"`
	Widget     string `json:"widget"`
	Target     string `json:"target"`
	Ok         *bool  `json:"ok"`
	DurationMs int    `json:"duration_ms"`
}

// clipCol hard-truncates to fit a column. Distinct from clip(): that one
// appends an ellipsis, which pushes a value AT the limit three bytes over it,
// and it slices by byte, which can split a UTF-8 rune and store invalid text in
// a column MySQL measures in characters.
func clipCol(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// MeInteractionEventRecord — POST /me/interaction-events.
// Body: {"events":[{app, action, surface, widget, target, ok, duration_ms}, …]}
func MeInteractionEventRecord(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		Events []interactionEventIn `json:"events"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if len(body.Events) == 0 {
		fail(c, http.StatusBadRequest, 1400, "events required")
		return
	}
	if len(body.Events) > interactionMaxBatch {
		fail(c, http.StatusBadRequest, 1400, "too many events in one call")
		return
	}

	rows := make([]models.MeInteractionEvent, 0, len(body.Events))
	for _, e := range body.Events {
		if !interactionActions[e.Action] {
			// Named, not ignored. A silently-dropped event is how a dashboard
			// ends up under-reporting with nothing to point at.
			names := make([]string, 0, len(interactionActions))
			for k := range interactionActions {
				names = append(names, k)
			}
			fail(c, http.StatusBadRequest, 1400,
				"unknown action "+e.Action+"; allowed: "+strings.Join(names, ", "))
			return
		}
		if !slugRe.MatchString(e.App) {
			fail(c, http.StatusBadRequest, 1400, "invalid app")
			return
		}
		okv := true
		if e.Ok != nil {
			okv = *e.Ok
		}
		d := e.DurationMs
		if d < 0 {
			d = 0
		}
		rows = append(rows, models.MeInteractionEvent{
			UserSub:    userID, // from the session — never from the body
			App:        e.App,
			Action:     e.Action,
			Surface:    clipCol(e.Surface, 128),
			Widget:     clipCol(e.Widget, 32),
			Target:     clipCol(e.Target, 128),
			Ok:         okv,
			DurationMs: d,
		})
	}
	// Best-effort: analytics must never break the page the person is using.
	if err := common.DB.Create(&rows).Error; err != nil {
		log.Printf("interaction events insert failed for %s: %v", userID, err)
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok",
		"data": gin.H{"recorded": len(rows)}})
}

// StartInteractionReclaimLoop bounds the table. Shipped WITH the writer, not
// after the incident — every other append-only table here (usage_events,
// audit_log, me_app_runs, me_app_intents, claude_session_turns) has no
// retention at all, and `sessions` only got one after it nearly filled the
// shared PVC that carries the auth database.
func StartInteractionReclaimLoop() {
	go func() {
		for {
			time.Sleep(interactionReclaimEvery)
			if n, err := reclaimOldInteractions(); err != nil {
				log.Printf("interaction reclaim failed: %v", err)
			} else if n > 0 {
				log.Printf("interaction reclaim: deleted %d row(s) older than %v", n, interactionRetention)
			}
		}
	}()
	log.Printf("interaction reclaim loop every %v (retention %v)", interactionReclaimEvery, interactionRetention)
}

func reclaimOldInteractions() (int64, error) {
	// Same named-lock discipline as session reclaim: identity runs replicas:2
	// and two concurrent sweeps would contend on the same rows.
	var got int
	if err := common.DB.Raw("SELECT GET_LOCK('interaction_reclaim', 2)").Scan(&got).Error; err != nil || got != 1 {
		return 0, nil
	}
	defer common.DB.Exec("DO RELEASE_LOCK('interaction_reclaim')")

	cutoff := time.Now().UTC().Add(-interactionRetention)
	var total int64
	for i := 0; i < interactionReclaimMaxIte; i++ {
		res := common.DB.Where("created_at < ?", cutoff).
			Limit(interactionReclaimBatch).
			Delete(&models.MeInteractionEvent{})
		if res.Error != nil {
			return total, res.Error
		}
		total += res.RowsAffected
		if res.RowsAffected < interactionReclaimBatch {
			break
		}
	}
	return total, nil
}
