package handler

// /api/v1/me/drafts — the user-facing approval queue.
//
// Drafts are produced by personal-agent's email/draft and calendar/propose
// skills. Each draft lands as a JSON file under
//   <tenant>/.xp/apps/<app>/data/outbox/<ts>/drafts/<slug>.json
//
// State (pending|sent|dismissed) lives alongside in
//   <tenant>/.xp/apps/<app>/data/drafts-state.json
// keyed by an opaque draft_id (sha256[:16] of the relpath). Drafts with
// no entry default to pending.
//
// Side effects:
//   - send  → writes an intent file the picker drains; picker invokes the
//             skill that calls Gmail with the user's OAuth grant. The
//             send is quota-charged on the skill side (Stage 3 of 0.6).
//   - edit  → rewrites the draft JSON body; state resets to pending.
//   - dismiss → updates state only; no Gmail call.
//
// Optimistic concurrency: each action accepts an optional `if_state` body
// field; mismatch returns 409 with the current state so the CLI can show
// a "this draft was acted on elsewhere" toast.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	draftStateFile = "drafts-state.json"
)

// draftState is the per-draft state row in drafts-state.json.
type draftState struct {
	State    string `json:"state"`              // pending | sent | dismissed
	ActedAt  string `json:"acted_at,omitempty"`
	IntentID string `json:"intent_id,omitempty"` // when state=sent
}

// draftCard is what we serve to the UI per draft.
type draftCard struct {
	ID         string  `json:"id"`
	App        string  `json:"app"`
	CycleTS    string  `json:"cycle_ts"`
	Path       string  `json:"path"` // server-relative, debugging only
	To         string  `json:"to,omitempty"`
	Subject    string  `json:"subject,omitempty"`
	Body       string  `json:"body,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	State      string  `json:"state"`
	ActedAt    string  `json:"acted_at,omitempty"`
}

// draftID is the opaque public identifier — sha256[:16] of the relpath
// rooted at the tenant's apps/<app>/ dir. Path is never returned to clients
// (just internal debugging), so the hash is the only handle the UI gets.
func draftID(rel string) string {
	h := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(h[:])[:16]
}

func draftIDRe() string { return `^[0-9a-f]{16}$` }

// listDraftsForApp walks an app's outbox tree and returns one draftCard
// per JSON file. State joined from drafts-state.json (default pending).
func listDraftsForApp(appDir, app string, stateMap map[string]draftState) []draftCard {
	out := []draftCard{}
	// Prefer the canonical .lumid/outbox; fall back to legacy data/outbox.
	outboxRoot, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "outbox"))
	st, err := os.Stat(outboxRoot)
	if err != nil || !st.IsDir() {
		return out
	}
	// outbox/<ts>/drafts/<slug>.json
	tsDirs, _ := os.ReadDir(outboxRoot)
	for _, td := range tsDirs {
		if !td.IsDir() {
			continue
		}
		ts := td.Name()
		draftsDir := filepath.Join(outboxRoot, ts, "drafts")
		files, _ := os.ReadDir(draftsDir)
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			abs := filepath.Join(draftsDir, f.Name())
			rel, _ := filepath.Rel(appDir, abs)
			id := draftID(rel)

			b, err := os.ReadFile(abs)
			if err != nil {
				continue
			}
			var raw map[string]any
			if json.Unmarshal(b, &raw) != nil {
				continue
			}
			conf, _ := raw["confidence"].(float64)
			st := stateMap[id]
			if st.State == "" {
				st.State = "pending"
			}
			out = append(out, draftCard{
				ID:         id,
				App:        app,
				CycleTS:    ts,
				Path:       rel,
				To:         asString(raw["to"]),
				Subject:    asString(raw["subject"]),
				Body:       asString(raw["body"]),
				Confidence: conf,
				State:      st.State,
				ActedAt:    st.ActedAt,
			})
		}
	}
	return out
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// loadStateMap reads drafts-state.json (returns empty on missing or
// malformed file — defaults are "pending" everywhere).
func loadStateMap(appDir string) map[string]draftState {
	out := map[string]draftState{}
	b, err := os.ReadFile(filepath.Join(appDir, "data", draftStateFile))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

// saveStateMap atomic-writes drafts-state.json.
func saveStateMap(appDir string, m map[string]draftState) error {
	dir := filepath.Join(appDir, "data")
	if err := os.MkdirAll(dir, 0o775); err != nil {
		return err
	}
	final := filepath.Join(dir, draftStateFile)
	tmp := final + ".tmp"
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// resolveDraftByID walks the tenant's installed apps, looking for the
// draft whose hash matches. Returns the absolute path + the app slug +
// the rel-to-app path, or empty strings when not found.
//
// We only walk tenant apps (the caller's own .tenants/<sub>/). Operator
// apps aren't surfaced through /me/drafts — those are the operator's own
// state and aren't part of the user-facing approval queue.
func resolveDraftByID(userSub, wantID string) (absPath, app, rel string) {
	tenantApps := tenantAppsDir(userSub)
	apps, err := os.ReadDir(tenantApps)
	if err != nil {
		return "", "", ""
	}
	for _, a := range apps {
		if !a.IsDir() || strings.HasPrefix(a.Name(), ".") {
			continue
		}
		appDir := filepath.Join(tenantApps, a.Name())
		// Prefer the canonical .lumid/outbox; fall back to legacy data/outbox.
		outboxRoot, _ := ResolveRuntimeReadPath(appDir, filepath.Join("data", "outbox"))
		tsDirs, _ := os.ReadDir(outboxRoot)
		for _, td := range tsDirs {
			if !td.IsDir() {
				continue
			}
			draftsDir := filepath.Join(outboxRoot, td.Name(), "drafts")
			files, _ := os.ReadDir(draftsDir)
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				absJ := filepath.Join(draftsDir, f.Name())
				relJ, _ := filepath.Rel(appDir, absJ)
				if draftID(relJ) == wantID {
					return absJ, a.Name(), relJ
				}
			}
		}
	}
	return "", "", ""
}

// GET /api/v1/me/drafts?app=&state=
//
// Lists all drafts for the caller's tenant, optionally filtered by app
// or state. Returns sorted by cycle_ts desc so the freshest cycle's
// drafts surface first.
func MeDraftsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	appFilter := c.Query("app")
	stateFilter := c.Query("state")

	tenantApps := tenantAppsDir(userID)
	apps, err := os.ReadDir(tenantApps)
	if err != nil {
		// No tenant tree yet — return empty list, not 500.
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"drafts": []draftCard{}},
		})
		return
	}
	all := []draftCard{}
	for _, a := range apps {
		if !a.IsDir() || strings.HasPrefix(a.Name(), ".") {
			continue
		}
		if appFilter != "" && a.Name() != appFilter {
			continue
		}
		appDir := filepath.Join(tenantApps, a.Name())
		stateMap := loadStateMap(appDir)
		all = append(all, listDraftsForApp(appDir, a.Name(), stateMap)...)
	}
	if stateFilter != "" {
		f := all[:0]
		for _, d := range all {
			if d.State == stateFilter {
				f = append(f, d)
			}
		}
		all = f
	}
	// Freshest cycle first; deterministic tiebreak by id.
	sort.Slice(all, func(i, j int) bool {
		if all[i].CycleTS != all[j].CycleTS {
			return all[i].CycleTS > all[j].CycleTS
		}
		return all[i].ID < all[j].ID
	})
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"drafts": all, "count": len(all)},
	})
}

// concurrencyCheck honors an optional if_state body field. If the
// caller asserted a state and the current state differs, write a 409
// with the actual state and return false (handler should abort).
func concurrencyCheck(c *gin.Context, ifState string, currentState string) bool {
	if ifState == "" || ifState == currentState {
		return true
	}
	c.JSON(http.StatusConflict, gin.H{
		"ret_code": 1409, "message": "draft state changed",
		"data": gin.H{"state": currentState, "expected": ifState},
	})
	return false
}

type draftActionBody struct {
	IfState string `json:"if_state,omitempty"`
	// edit only:
	Body    string `json:"body,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// POST /api/v1/me/drafts/:id/send
//
// Updates state→sent (with intent_id) atomically, then enqueues a
// send_draft intent the picker drains. The picker will invoke the
// app's email/send skill which calls Gmail with the user's OAuth grant
// (and charges external_api gmail.send against the quota).
func MeDraftSend(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !regexpDraftID.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid draft id")
		return
	}
	var body draftActionBody
	_ = c.ShouldBindJSON(&body)

	abs, app, rel := resolveDraftByID(userID, id)
	if abs == "" {
		fail(c, http.StatusNotFound, 1404, "draft not found")
		return
	}
	appDir := filepath.Join(tenantAppsDir(userID), app)
	stateMap := loadStateMap(appDir)
	current := stateMap[id]
	if current.State == "" {
		current.State = "pending"
	}
	if !concurrencyCheck(c, body.IfState, current.State) {
		return
	}
	if current.State == "sent" {
		fail(c, http.StatusBadRequest, 1400, "draft already sent")
		return
	}

	// Enqueue the picker intent so the actual Gmail call happens with
	// HOME=<tenant root> and the per-tenant OAuth/secrets context.
	intentID := writeIntent(c, "send_draft", userID, map[string]any{
		"app":        app,
		"draft_path": rel,
		"draft_id":   id,
	})
	if intentID == "" {
		return // writeIntent already wrote the error
	}

	stateMap[id] = draftState{
		State:    "sent",
		ActedAt:  time.Now().UTC().Format(time.RFC3339),
		IntentID: intentID,
	}
	if err := saveStateMap(appDir, stateMap); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save state: "+err.Error())
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "send queued",
		"data": gin.H{
			"id":        id,
			"state":     "sent",
			"intent_id": intentID,
		},
	})
}

// POST /api/v1/me/drafts/:id/edit
//
// Rewrites the draft's subject + body in place. State resets to pending
// (the user touched it; awaiting a fresh send/dismiss). The JSON file
// keeps any other fields the skill wrote (confidence, voice_notes, etc.).
func MeDraftEdit(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !regexpDraftID.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid draft id")
		return
	}
	var body draftActionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	abs, app, _ := resolveDraftByID(userID, id)
	if abs == "" {
		fail(c, http.StatusNotFound, 1404, "draft not found")
		return
	}
	appDir := filepath.Join(tenantAppsDir(userID), app)
	stateMap := loadStateMap(appDir)
	current := stateMap[id]
	if current.State == "" {
		current.State = "pending"
	}
	if !concurrencyCheck(c, body.IfState, current.State) {
		return
	}
	if current.State == "sent" {
		fail(c, http.StatusBadRequest, 1400, "cannot edit a sent draft")
		return
	}

	b, err := os.ReadFile(abs)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "read draft: "+err.Error())
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "parse draft: "+err.Error())
		return
	}
	if body.Subject != "" {
		raw["subject"] = body.Subject
	}
	if body.Body != "" {
		raw["body"] = body.Body
	}
	raw["edited_at"] = time.Now().UTC().Format(time.RFC3339)
	out, _ := json.MarshalIndent(raw, "", "  ")
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "write tmp: "+err.Error())
		return
	}
	if err := os.Rename(tmp, abs); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rename: "+err.Error())
		return
	}
	stateMap[id] = draftState{
		State:   "pending",
		ActedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveStateMap(appDir, stateMap); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save state: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "edited",
		"data": gin.H{"id": id, "state": "pending"},
	})
}

// POST /api/v1/me/drafts/:id/dismiss
//
// State-only update. No file edit, no side effect.
func MeDraftDismiss(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	id := c.Param("id")
	if !regexpDraftID.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid draft id")
		return
	}
	var body draftActionBody
	_ = c.ShouldBindJSON(&body)

	_, app, _ := resolveDraftByID(userID, id)
	if app == "" {
		fail(c, http.StatusNotFound, 1404, "draft not found")
		return
	}
	appDir := filepath.Join(tenantAppsDir(userID), app)
	stateMap := loadStateMap(appDir)
	current := stateMap[id]
	if current.State == "" {
		current.State = "pending"
	}
	if !concurrencyCheck(c, body.IfState, current.State) {
		return
	}
	if current.State == "sent" {
		fail(c, http.StatusBadRequest, 1400, "cannot dismiss a sent draft")
		return
	}
	stateMap[id] = draftState{
		State:   "dismissed",
		ActedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveStateMap(appDir, stateMap); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save state: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "dismissed",
		"data": gin.H{"id": id, "state": "dismissed"},
	})
}

// Lazy compile keeps the regex package out of the init path of every
// handler import — small footprint, but the codebase prefers this style.
var regexpDraftID = mustCompileDraftIDRe()

func mustCompileDraftIDRe() interface {
	MatchString(string) bool
} {
	// Inline minimal alphabet+length check rather than pulling regexp.
	// 16 hex chars exactly.
	return draftIDMatcher{}
}

type draftIDMatcher struct{}

func (draftIDMatcher) MatchString(s string) bool {
	if len(s) != 16 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// Sanity-check the matcher format string is what the docstring claims.
var _ = fmt.Sprintf // keep fmt import used if other code is trimmed
var _ = draftIDRe   // referenced for documentation only
