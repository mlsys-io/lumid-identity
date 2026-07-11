package handler

// Bridge-gated READ half of the cross-node DB-backed tenant-app edits (WS-4/5).
//
// On UKS, identity (svc node) can't reach the scheduler PVC, so cross-node
// Studio edits land in me_docs: prompt overrides as kind=app_prompt, trajectory
// control signals as kind=app_signal. The WRITE half shipped with WS-4/5/7 —
// but nothing consumed those docs at cycle execution, so an override/signal
// never reached the running loop. These endpoints let the scheduler's
// app_runner pull them down to the PVC at cycle start
// (LumidOS sdk/apps/app_runner.py::_sync_identity_overlays):
//
//	POST /api/v1/internal/app-prompt-overrides/fetch {user_sub, app}
//	     → {overrides: {<name>.md: content}}   (full current set — the caller
//	       mirrors it: materialize new/changed, revert deleted)
//	POST /api/v1/internal/app-signals/claim {user_sub, app}
//	     → {signals: [{id, rec}]}               (PENDING docs only, oldest first)
//	POST /api/v1/internal/app-signals/ack {user_sub, ids}
//	     → deletes the docs once the caller has appended them to the durable
//	       PVC signals file (claim → append → ack = at-least-once delivery)
//
// All three are X-Bridge-Secret gated (RequireBridge) — service-to-service
// only, never user-facing.

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
)

type overlayReq struct {
	UserSub string `json:"user_sub" binding:"required"`
	App     string `json:"app"      binding:"required"`
}

// InternalAppPromptOverridesFetch — POST /api/v1/internal/app-prompt-overrides/fetch
func InternalAppPromptOverridesFetch(c *gin.Context) {
	var body overlayReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	ovr := promptOverridesForApp(body.UserSub, body.App)
	if ovr == nil {
		ovr = map[string]string{}
	}
	ok(c, "ok", gin.H{"overrides": ovr})
}

// claimedSignal pairs a signal record with its me_docs id so the caller can
// ack (delete) it after materializing into the PVC signals file.
type claimedSignal struct {
	ID  string       `json:"id"`
	Rec signalRecord `json:"rec"`
}

// InternalAppSignalsClaim — POST /api/v1/internal/app-signals/claim
// Returns the user's PENDING cross-node control signals for one app, oldest
// first. Does NOT delete — the caller acks after the durable file append, so
// a crash in between re-delivers rather than losing the signal.
func InternalAppSignalsClaim(c *gin.Context) {
	var body overlayReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	rows, err := meDocList(body.UserSub, meDocKindSignal)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	out := []claimedSignal{}
	for _, r := range rows {
		var d signalDoc
		if json.Unmarshal([]byte(r.Doc), &d) != nil || d.App != body.App {
			continue
		}
		if d.Rec.Status != "" && d.Rec.Status != "pending" {
			continue
		}
		out = append(out, claimedSignal{ID: r.DocID, Rec: d.Rec})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rec.Ts < out[j].Rec.Ts })
	ok(c, "ok", gin.H{"signals": out})
}

// InternalAppSignalsAck — POST /api/v1/internal/app-signals/ack
// Body {user_sub, ids[]}. Deletes the acked signal docs (idempotent — a
// missing doc is a no-op, matching meDocDelete semantics).
func InternalAppSignalsAck(c *gin.Context) {
	var body struct {
		UserSub string   `json:"user_sub" binding:"required"`
		IDs     []string `json:"ids"      binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	deleted := 0
	for _, id := range body.IDs {
		if id == "" {
			continue
		}
		if gone, err := meDocDelete(body.UserSub, meDocKindSignal, id); err == nil && gone {
			deleted++
		}
	}
	ok(c, "ok", gin.H{"deleted": deleted})
}
