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

// appSpecUpsertReq is the body the scheduler install-picker posts after it
// materializes a bundle on its PVC — the DB-backed copy identity reads
// cross-node (see models.MeAppSpec).
type appSpecUpsertReq struct {
	UserSub  string            `json:"user_sub" binding:"required"`
	App      string            `json:"app"      binding:"required"`
	SpecYAML string            `json:"spec_yaml"`
	UIFiles  map[string]string `json:"ui_files"` // repo-relative path → content (ui/*.md, ui/*.yaml)
}

// InternalAppSpecUpsert — POST /api/v1/internal/app-spec (X-Bridge-Secret).
// The scheduler calls this post-install so identity can resolve an installed
// app's spec + ui surfaces without mounting the scheduler PVC. Idempotent
// upsert on (user_sub, app).
func InternalAppSpecUpsert(c *gin.Context) {
	var body appSpecUpsertReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if err := meAppSpecSave(body.UserSub, body.App, body.SpecYAML, body.UIFiles); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save spec: "+err.Error())
		return
	}
	ok(c, "ok", gin.H{"app": body.App, "ui_files": len(body.UIFiles)})
}

// InternalAppConfigOverrideFetch — POST /api/v1/internal/app-config-override/fetch
// Body {user_sub, app}. Returns the caller's config override JSON for the app
// (me_docs kind app_config_override), or null when none exists. The scheduler
// reads this at cycle start to overlay the config on the base spec.
func InternalAppConfigOverrideFetch(c *gin.Context) {
	var body overlayReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	raw, has := appConfigOverrideGet(body.UserSub, body.App)
	if !has {
		ok(c, "ok", gin.H{"override": nil})
		return
	}
	// The stored body is a JSON string of the config map — hand it back parsed
	// so the caller gets a JSON object, not a double-encoded string.
	var parsed any
	if json.Unmarshal([]byte(raw), &parsed) != nil {
		ok(c, "ok", gin.H{"override": nil})
		return
	}
	ok(c, "ok", gin.H{"override": parsed})
}

// InternalAppLoopOverridesFetch — POST /api/v1/internal/app-loop-overrides/fetch
// Body {user_sub, app}. Returns [{loop, override}] for every loop the caller
// has an override on (me_docs kind app_loop_override). The scheduler applies
// these (schedule/model/runtime/goal/enabled) at cycle start.
func InternalAppLoopOverridesFetch(c *gin.Context) {
	var body overlayReq
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	out := []gin.H{}
	for loop, raw := range appLoopOverridesForApp(body.UserSub, body.App) {
		var parsed any
		if json.Unmarshal([]byte(raw), &parsed) != nil {
			continue
		}
		out = append(out, gin.H{"loop": loop, "override": parsed})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["loop"].(string) < out[j]["loop"].(string)
	})
	ok(c, "ok", gin.H{"overrides": out})
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
