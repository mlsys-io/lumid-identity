package handler

// Owner edits to an app's own files — prompt cards, the .xpcloud.yaml spec and
// UI surfaces — for the case where identity cannot see the file.
//
// ── Why these writes go through an INTENT ──
//
// Every one of those editors resolved the target with resolveOwnedAppDir, which
// stat()s <tenant>/.xp/{agents,apps}/<app>. Identity runs in UKS and mounts
// exactly one volume — the signing keys — so that directory NEVER EXISTS here,
// and every owner edit in Studio failed with 403 "operator-shared (read-only)"
// for an app the user installed themselves. Reads only appeared to work because
// resolveAppDir falls back to materialiseTenantApp: the PUBLISHED bundle, cached
// for five minutes, which is not the tenant's writable tree either. Writing into
// that cache would have "succeeded" into a pod-local copy nothing reads.
//
// The scheduler is the process that can see the tenant disk, so the write
// belongs there — the same route patch_loop, stop_loop and install already
// take. It applies `app_file_write` (sdk/scheduling/me_intent_picker.py
// _process_app_file_write) against the same path allowlist mirrored below, and
// enforces base_sha itself, because only it can read the current bytes.
//
// An identity that DOES mount the tenant tree (on-prem) keeps the direct write:
// ownerWriteTarget returns direct=true there and nothing below is used.
//
// ── Why reads need an overlay ──
//
// A queued write lands on the scheduler's disk; identity still reads the
// published bundle. Without the overlay a successful save would be invisible —
// the editor would reload and show the old text, and a second save would
// conflict against bytes the user never saw. So readers consult the newest
// SUCCESSFUL app_file_write for the path, unless an install/update of the app
// completed after it (that replaced the tree the write was applied to).

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const appFileWriteAction = "app_file_write"

// The picker's allowlist, verbatim. Enqueueing a path it will refuse only turns
// a clear 400 now into a failed intent later, so identity checks first.
var appFileIntentPathRes = []*regexp.Regexp{
	regexp.MustCompile(`^prompts/[A-Za-z0-9._-]+\.md$`),
	regexp.MustCompile(`^\.ui/[A-Za-z0-9._-]+\.(md|ya?ml)$`),
	regexp.MustCompile(`^ui/[A-Za-z0-9._-]+\.ya?ml$`),
	regexp.MustCompile(`^\.xpcloud\.yaml$`),
}

const (
	appFileIntentMaxBytes     = 256 * 1024 // picker cap for prompts/UI
	appFileIntentSpecMaxBytes = 64 * 1024  // picker cap for .xpcloud.yaml
	appFileSpecRel            = ".xpcloud.yaml"
)

// normAppFileRel canonicalises a bundle-relative path so the overlay key a
// reader looks up matches the one a writer enqueued ("./.ui/x.md" == ".ui/x.md").
func normAppFileRel(rel string) string {
	rel = strings.TrimSpace(strings.ReplaceAll(rel, "\\", "/"))
	if rel == "" {
		return ""
	}
	return strings.TrimPrefix(path.Clean(rel), "./")
}

// appFileIntentPathOK reports whether the scheduler will accept `rel`.
func appFileIntentPathOK(rel string) bool {
	for _, re := range appFileIntentPathRes {
		if re.MatchString(rel) {
			return true
		}
	}
	return false
}

// ownerWriteTarget decides HOW an owner write for `app` is carried out.
//
//   - direct:    identity can see the caller's tenant install (on-prem mount);
//     appDir is it, and the existing direct-write code runs unchanged.
//   - viaIntent: the caller has the app installed, but on a disk only the
//     scheduler sees — queue an app_file_write.
//   - shared:    the app exists only as an operator-shared/published bundle the
//     caller does not own — 403, as before.
//
// All three false means the app is not installed at all (404).
func ownerWriteTarget(userSub, app string) (appDir string, direct, viaIntent, shared bool) {
	dir, owned, sh := resolveOwnedAppDir(userSub, app)
	if owned {
		return dir, true, false, false
	}
	// resolveOwnedAppDir already rejected separators/traversal; re-check so a
	// crafted name can never reach the intent payload.
	if app == "" || strings.ContainsAny(app, "/\\") || strings.Contains(app, "..") || common.DB == nil {
		return "", false, false, sh
	}
	for _, n := range tenantInstalledAppNames(userSub) {
		if n == app {
			return "", false, true, false
		}
	}
	return "", false, false, sh
}

// ownerCanEdit is the `editable` flag readers report: true whenever an owner
// write would be carried out (directly or via the scheduler).
func ownerCanEdit(userSub, app string) bool {
	_, direct, viaIntent, _ := ownerWriteTarget(userSub, app)
	return direct || viaIntent
}

var (
	errAppFilePath   = errors.New("path not writable via the scheduler")
	errAppFileTooBig = errors.New("file exceeds the size limit")
)

// queueAppFileWrite validates and enqueues one app_file_write. `op` is "write"
// or "delete". Returns the intent id and the normalised path.
func queueAppFileWrite(userSub, app, rel, op, content, baseSHA string) (id, norm string, err error) {
	norm = normAppFileRel(rel)
	if !appFileIntentPathOK(norm) {
		return "", norm, errAppFilePath
	}
	if op != "write" && op != "delete" {
		return "", norm, errors.New("op must be write|delete")
	}
	limit := appFileIntentMaxBytes
	if norm == appFileSpecRel {
		limit = appFileIntentSpecMaxBytes
	}
	if op == "write" && len(content) > limit {
		return "", norm, errAppFileTooBig
	}
	payload := map[string]any{"app": app, "path": norm, "op": op, "base_sha": baseSHA}
	if op == "write" {
		payload["content"] = content
	}
	id, err = insertIntent(appFileWriteAction, userSub, payload)
	return id, norm, err
}

// appFilePathErrMsg is the 400 text for a path the scheduler would refuse.
func appFilePathErrMsg(rel string) string {
	return "cannot save " + rel + " on a cloud install: only prompts/<name>.md, .ui/<name>.md|yaml, " +
		"ui/<name>.yaml and .xpcloud.yaml are writable. Point the surface at a .ui/ file in the app config first."
}

// enqueueAppFileWrite queues the write and answers 202. Like MeLoopPatch it
// makes no claim that the write landed — `saved:false`, poll the intent. `sha`
// is what the file WILL hash to once applied, so the editor can chain its next
// base_sha without a reload.
func enqueueAppFileWrite(c *gin.Context, userSub, app, rel, op, content, baseSHA string) {
	id, norm, err := queueAppFileWrite(userSub, app, rel, op, content, baseSHA)
	if err != nil {
		if errors.Is(err, errAppFilePath) {
			fail(c, http.StatusBadRequest, 1400, appFilePathErrMsg(norm))
			return
		}
		if errors.Is(err, errAppFileTooBig) {
			fail(c, http.StatusRequestEntityTooLarge, 1413, err.Error())
			return
		}
		fail(c, http.StatusInternalServerError, 1500, "queue intent: "+err.Error())
		return
	}
	sha := ""
	if op == "write" {
		sha = contentSHA([]byte(content))
	}
	c.JSON(http.StatusAccepted, gin.H{
		"ret_code": 0, "message": "queued",
		"data": gin.H{
			"app": app, "path": norm, "intent_id": id, "status": "pending",
			"queued": true, "saved": false, "sha": sha,
		},
	})
}

// queuedToolResult is the chat-tool twin of enqueueAppFileWrite's 202. It says
// QUEUED, never "saved": the scheduler applies it, and may refuse (conflict).
func queuedToolResult(userSub, app, rel, op, content, baseSHA string, extra map[string]any) (map[string]any, bool) {
	id, norm, err := queueAppFileWrite(userSub, app, rel, op, content, baseSHA)
	if err != nil {
		if errors.Is(err, errAppFilePath) {
			return map[string]any{"error": appFilePathErrMsg(norm)}, false
		}
		return map[string]any{"error": "could not queue the write: " + err.Error()}, false
	}
	out := map[string]any{
		"app": app, "path": norm, "intent_id": id, "state": "queued",
		"queued": true, "saved": false,
		"note": "Queued for the scheduler, which applies it to your install (a few seconds). " +
			"It is rejected if the file changed since you read it.",
	}
	if op == "write" {
		out["sha"] = contentSHA([]byte(content))
	}
	for k, v := range extra {
		out[k] = v
	}
	return out, true
}

// ── read overlay ────────────────────────────────────────────────────────────

// appFileOverlayEntry is the newest applied app_file_write for one path.
type appFileOverlayEntry struct {
	Content  []byte
	Deleted  bool
	IntentID string
	At       time.Time
}

// appFileOverlayScan bounds how many recent write rows a read looks at. Each
// row carries the whole file (up to 256 KB), so this is a memory bound too.
const appFileOverlayScan = 100

// appFileOverlays loads every live overlay for (user, app): two queries, the
// app_file_write rows and the install/update rows that can supersede them.
func appFileOverlays(userSub, app string) map[string]appFileOverlayEntry {
	if common.DB == nil || userSub == "" || app == "" {
		return nil
	}
	// Prefilter on the payload text so another app's edits (and their bodies)
	// are never loaded; overlaysFromIntents still matches the app exactly —
	// LIKE treats "_" in an app name as a wildcard, which only over-selects.
	appJSON, _ := json.Marshal(app)
	var writes []models.MeAppIntent
	if err := common.DB.
		Where("user_sub = ? AND action = ? AND status = ? AND payload LIKE ?",
			userSub, appFileWriteAction, "done", `%"app":`+string(appJSON)+`%`).
		Order("completed_at desc").Limit(appFileOverlayScan).
		Find(&writes).Error; err != nil || len(writes) == 0 {
		return nil
	}
	var resets []models.MeAppIntent
	_ = common.DB.
		Where("user_sub = ? AND action IN ? AND status = ?", userSub, []string{"install", "update"}, "done").
		Order("completed_at desc").Limit(200).
		Find(&resets).Error
	return overlaysFromIntents(writes, resets, app)
}

// overlaysFromIntents is the precedence decision, split from the queries so it
// is testable without a database. Only DONE rows count (a failed write — e.g. a
// base_sha conflict — changed nothing), the newest per path wins, and a write
// is dropped when an install/update of the same app completed after it: that
// replaced the tree the write was applied to, and the published bundle is
// again the truth.
func overlaysFromIntents(writes, resets []models.MeAppIntent, app string) map[string]appFileOverlayEntry {
	var resetAt time.Time
	for i := range resets {
		r := resets[i]
		if r.Status != "done" || r.CompletedAt == nil {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal([]byte(r.Payload), &p)
		if intentAppName(p) != app {
			continue
		}
		if r.Action == "update" {
			if dry, _ := p["dry_run"].(bool); dry {
				continue // a dry run touched nothing
			}
		}
		if r.CompletedAt.After(resetAt) {
			resetAt = *r.CompletedAt
		}
	}
	out := map[string]appFileOverlayEntry{}
	for i := range writes {
		w := writes[i]
		if w.Action != appFileWriteAction || w.Status != "done" || w.CompletedAt == nil {
			continue
		}
		if !w.CompletedAt.After(resetAt) {
			continue
		}
		var p struct {
			App     string `json:"app"`
			Path    string `json:"path"`
			Op      string `json:"op"`
			Content string `json:"content"`
		}
		if json.Unmarshal([]byte(w.Payload), &p) != nil || p.App != app {
			continue
		}
		rel := normAppFileRel(p.Path)
		if rel == "" {
			continue
		}
		if cur, has := out[rel]; has && !w.CompletedAt.After(cur.At) {
			continue
		}
		out[rel] = appFileOverlayEntry{
			Content:  []byte(p.Content),
			Deleted:  p.Op == "delete",
			IntentID: w.ID,
			At:       *w.CompletedAt,
		}
	}
	return out
}

// appFileOverlay returns the applied-but-unpublished state of one file.
// found=false means "no overlay — read the bundle as usual".
func appFileOverlay(userSub, app, rel string) (content []byte, deleted, found bool) {
	e, ok := appFileOverlays(userSub, app)[normAppFileRel(rel)]
	if !ok {
		return nil, false, false
	}
	return e.Content, e.Deleted, true
}

// appFileOverlayNames returns the overlays for files directly under dirPrefix
// (e.g. "prompts"), keyed by bare filename — so a prompt CREATED through the
// scheduler shows up in a listing built from the published bundle.
func appFileOverlayNames(userSub, app, dirPrefix string) map[string]appFileOverlayEntry {
	return overlayNamesUnder(appFileOverlays(userSub, app), dirPrefix)
}

func overlayNamesUnder(all map[string]appFileOverlayEntry, dirPrefix string) map[string]appFileOverlayEntry {
	prefix := strings.TrimSuffix(normAppFileRel(dirPrefix), "/") + "/"
	out := map[string]appFileOverlayEntry{}
	for rel, e := range all {
		if !strings.HasPrefix(rel, prefix) {
			continue
		}
		name := strings.TrimPrefix(rel, prefix)
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		out[name] = e
	}
	return out
}
