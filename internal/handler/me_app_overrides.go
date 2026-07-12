package handler

// Cross-node app EDIT overrides — config / ui-surface / loop — stored in
// me_docs, mirroring the prompt-override store (me_app_prompts.go). On UKS the
// tenant install lives on the scheduler PVC identity can't mount, so the
// on-disk write path (os.Rename into the bundle) is unreachable; these edits
// land in me_docs instead (the same replica-safe store that fixed chats /
// personas / prompts), keyed deterministically per (app[, surface|loop]).
//
// me_docs kinds (reuse the existing MeDoc table):
//
//	app_config_override   doc_id = <app>              body = full config JSON
//	app_surface_override  doc_id = <app>/<surface>    body = markdown
//	app_loop_override     doc_id = <app>/<loop>       body = override JSON
//	                                                    {schedule?,model?,runtime?,goal?,enabled?}
//
// Reads prefer the override over the base spec (local-shadows-published), so
// GET-after-PUT round-trips. The RUNTIME application of config/loop overrides is
// the scheduler's half — it pulls them at cycle start via the internal fetch
// endpoints (InternalAppConfigOverrideFetch / InternalAppLoopOverridesFetch),
// exactly like the prompt-override sync. Surface overrides are served straight
// back to the Studio shell here.

import (
	"encoding/json"
	"strings"
)

const (
	meDocKindAppConfig  = "app_config_override"
	meDocKindAppSurface = "app_surface_override"
	meDocKindAppLoop    = "app_loop_override"
)

// ── config override (doc_id = app) ───────────────────────────────────────────

// appConfigOverrideGet returns the stored config-override JSON string for an
// app, if any. The body is the full config map serialized to JSON.
func appConfigOverrideGet(userSub, app string) (string, bool) {
	doc, found, err := meDocGet(userSub, meDocKindAppConfig, app)
	if err != nil || !found {
		return "", false
	}
	return doc, true
}

// appConfigOverrideSave upserts the config override (JSON string) for an app.
func appConfigOverrideSave(userSub, app, jsonBody string) error {
	return meDocSave(userSub, meDocKindAppConfig, app, jsonBody)
}

// ── surface override (doc_id = app/surface) ──────────────────────────────────

// surfaceOverrideID is the deterministic me_docs id for (app, surface). The
// raw "<app>/<surface>" can exceed the 64-char doc_id width, so we hash it —
// same trick as promptOverrideID.
func surfaceOverrideID(app, surface string) string {
	return contentSHA([]byte(app + "\x00ui\x00" + surface))
}

// appSurfaceOverrideDoc is the me_docs payload for one surface override. App +
// surface are carried inline so a per-app scan can filter (the id is hashed).
type appSurfaceOverrideDoc struct {
	App      string `json:"app"`
	Surface  string `json:"surface"`
	Markdown string `json:"markdown"`
}

// appSurfaceOverrideGet returns the override markdown for (app, surface).
func appSurfaceOverrideGet(userSub, app, surface string) (string, bool) {
	doc, found, err := meDocGet(userSub, meDocKindAppSurface, surfaceOverrideID(app, surface))
	if err != nil || !found {
		return "", false
	}
	var d appSurfaceOverrideDoc
	if json.Unmarshal([]byte(doc), &d) != nil {
		return "", false
	}
	return d.Markdown, true
}

// appSurfaceOverrideSave upserts the markdown override for (app, surface).
func appSurfaceOverrideSave(userSub, app, surface, markdown string) error {
	doc, err := json.Marshal(appSurfaceOverrideDoc{App: app, Surface: surface, Markdown: markdown})
	if err != nil {
		return err
	}
	return meDocSave(userSub, meDocKindAppSurface, surfaceOverrideID(app, surface), string(doc))
}

// ── loop override (doc_id = app/loop) ────────────────────────────────────────

// loopOverrideID is the deterministic me_docs id for (app, loop).
func loopOverrideID(app, loop string) string {
	return contentSHA([]byte(app + "\x00loop\x00" + loop))
}

// appLoopOverrideDoc is the me_docs payload for one loop override. App + loop
// ride inline so appLoopOverridesForApp can filter by app.
type appLoopOverrideDoc struct {
	App      string `json:"app"`
	Loop     string `json:"loop"`
	Override string `json:"override"` // JSON string: {schedule?,model?,runtime?,goal?,enabled?}
}

// appLoopOverrideSave upserts the override JSON for (app, loop).
func appLoopOverrideSave(userSub, app, loop, overrideJSON string) error {
	doc, err := json.Marshal(appLoopOverrideDoc{App: app, Loop: loop, Override: overrideJSON})
	if err != nil {
		return err
	}
	return meDocSave(userSub, meDocKindAppLoop, loopOverrideID(app, loop), string(doc))
}

// appLoopOverrideGet returns the raw override JSON string for (app, loop).
func appLoopOverrideGet(userSub, app, loop string) (string, bool) {
	doc, found, err := meDocGet(userSub, meDocKindAppLoop, loopOverrideID(app, loop))
	if err != nil || !found {
		return "", false
	}
	var d appLoopOverrideDoc
	if json.Unmarshal([]byte(doc), &d) != nil {
		return "", false
	}
	return d.Override, true
}

// appLoopOverridesForApp returns loop → override-JSON for every loop the caller
// has an override on for one app. Backs the scheduler's cycle-start fetch.
func appLoopOverridesForApp(userSub, app string) map[string]string {
	rows, err := meDocList(userSub, meDocKindAppLoop)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, r := range rows {
		var d appLoopOverrideDoc
		if json.Unmarshal([]byte(r.Doc), &d) == nil && d.App == app &&
			d.Loop != "" && !strings.ContainsAny(d.Loop, "/\\\x00") {
			out[d.Loop] = d.Override
		}
	}
	return out
}
