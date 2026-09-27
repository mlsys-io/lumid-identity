package handler

// Improvement ledger — append-only audit log of every change to an
// intent across six axes (examples / standard / recipe / pieces /
// memory / rules). Lives at
//
//   ~/.xp/apps/<app>/data/improvements.jsonl
//
// One JSON object per line. Written by:
//   1. POST /me/feedback         — user 👍/✏️/👎 on intent outputs
//   2. xpio cycle hooks          — when bank rows are added,
//                                  metrics computed, skills swapped
//   3. SDK ops (sdk/ops/feedback.py) — used by Python-side code
//
// Read by:
//   1. GET /me/intents/:id/audit — for the detail page narrative
//                                  + timeline view
//   2. intent_audit chat tool    — for "what changed this week?"
//
// The schema is intentionally simple — flat JSON, no nested
// structures other than the optional `delta` + `effect` fields.
// New consumers (UI tiles, metrics dashboards) can fold over the
// ledger without a parser.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// improvementEvent — one row of the ledger. See me_improvements.go
// header comment for which fields are required vs optional.
type improvementEvent struct {
	ID      string `json:"id"`
	Ts      string `json:"ts"`
	App     string `json:"app"`
	Loop    string `json:"loop,omitempty"`
	CycleTs string `json:"cycle_ts,omitempty"`
	// Axis ∈ {examples, standard, recipe, pieces, memory, rules}.
	// Map to user-facing labels at render time.
	Axis string `json:"axis"`
	// Verb ∈ {added, removed, swapped, scored, distilled, tuned}.
	Verb      string `json:"verb"`
	Label     string `json:"label"`
	Rationale string `json:"rationale,omitempty"`
	// Optional measurable delta (e.g. metric before/after).
	Delta any `json:"delta,omitempty"`
	// Optional knock-on effect on another axis.
	Effect any `json:"effect,omitempty"`
	// Source ∈ {user, cycle, scheduler, agent}.
	Source string `json:"source"`
	// OutputID — when feedback ties to a specific output (cycle
	// artifact, draft message). Lets the UI link back.
	OutputID string `json:"output_id,omitempty"`
}

// validAxes — the six user-facing improvement dimensions. Reject
// arbitrary axis values to keep the ledger schema honest.
var validAxes = map[string]bool{
	"examples": true,
	"standard": true,
	"recipe":   true,
	"pieces":   true,
	"memory":   true,
	"rules":    true,
}

// validVerbs — allowed actions. Closed set so the timeline UI can
// switch on these for icons + colors.
var validVerbs = map[string]bool{
	"added":     true,
	"removed":   true,
	"swapped":   true,
	"scored":    true,
	"distilled": true,
	"tuned":     true,
	"good":      true, // user 👍
	"edit":      true, // user ✏️ (treated as positive example)
	"wrong":     true, // user 👎
}

const (
	feedbackMaxNote = 2 * 1024
)

// improvementsPath — per-app ledger path. Lives under the user's
// tenant tree so each user's improvement history is private. When the
// caller's own install is visible (on-prem mount) its directory is used —
// agents/ or apps/ — so the reader and appendImprovement agree; otherwise the
// historical tenant apps/ path, which on a cloud pod does not exist — there
// readImprovements fetches the ledger from the scheduler instead.
func improvementsPath(userID, app string) string {
	if dir, owned, _ := resolveOwnedAppDir(userID, app); owned && dir != "" {
		return filepath.Join(dir, "data", "improvements.jsonl")
	}
	// xpio apps live under tenant/.xp/apps in the per-user view —
	// matches sdk/ops/apps.py + the existing journal/cycles layout.
	return filepath.Join(tenantRoot(userID), ".xp", "apps", app, "data", "improvements.jsonl")
}

func newImprovementID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("imp-%012x", time.Now().UnixNano())
	}
	return "imp-" + hex.EncodeToString(b)
}

// prepareImprovement validates one event and fills the server-minted fields
// (id, ts, default source). Shared by the direct append and the intent path.
func prepareImprovement(e *improvementEvent) error {
	if e.Axis == "" || !validAxes[e.Axis] {
		return fmt.Errorf("invalid axis %q (must be one of examples/standard/recipe/pieces/memory/rules)", e.Axis)
	}
	if e.Verb == "" || !validVerbs[e.Verb] {
		return fmt.Errorf("invalid verb %q", e.Verb)
	}
	if e.App == "" {
		return fmt.Errorf("app required")
	}
	if e.Source == "" {
		e.Source = "user"
	}
	if e.ID == "" {
		e.ID = newImprovementID()
	}
	if e.Ts == "" {
		e.Ts = time.Now().UTC().Format(time.RFC3339)
	}
	return nil
}

var errImprovementNotOwned = errors.New("app is not installed for this user")

// appendImprovement — append one event to the caller's OWN install's ledger.
//
// It used to write a hardcoded <tenant>/.xp/apps/<app>/data path, creating it
// if missing — on a cloud pod that is a pod-local directory nothing reads.
// identity mounts no tenant volume; the scheduler can see the disk, so when
// the install is only there the row is queued as an app_file_write append and
// the intent id returned. direct: O_APPEND on POSIX is atomic up to PIPE_BUF
// (~4KB on Linux), which is more than enough for one event.
//
// Returns errImprovementNotOwned when the caller has no install of the app
// (shared or absent) — the operator-shared ledger is not the caller's to write.
func appendImprovement(userID string, e *improvementEvent) (intentID string, err error) {
	if err := prepareImprovement(e); err != nil {
		return "", err
	}
	appDir, direct, viaIntent, _ := ownerWriteTarget(userID, e.App)
	if viaIntent {
		return queueAppFileOps(userID, e.App, func() ([]map[string]any, error) {
			op, err := appendOp(improvementsRel, e)
			return []map[string]any{op}, err
		})
	}
	if !direct {
		return "", errImprovementNotOwned
	}
	path := filepath.Join(appDir, "data", "improvements.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	buf, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(buf, '\n')); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	return "", nil
}

// readImprovements walks the ledger for one app + optional loop
// filter. Returns events sorted newest-first. since may be empty
// (returns everything) or an RFC3339 / unix-seconds string.
//
// For the caller's own install that identity cannot see (a cloud install —
// ownerWriteTarget viaIntent), the ledger is on the scheduler's disk: it is
// fetched with an `app_file_read` read intent and parsed the same way. Only
// the ledger's tail comes back when it is large (the picker caps it at
// 256 KB, whole lines); `truncated` is not surfaced — the audit is a
// newest-first window already.
func readImprovements(ctx context.Context, userID, app, loop, since string, limit int) ([]improvementEvent, error) {
	if _, direct, viaIntent, _ := ownerWriteTarget(userID, app); !direct && viaIntent {
		data, err := runReadIntent(ctx, userID, "app_file_read",
			map[string]any{"app": app, "path": improvementsRel}, readIntentDefaultTimeout)
		if err != nil {
			return nil, err
		}
		if exists, _ := data["exists"].(bool); !exists {
			return nil, nil
		}
		content, _ := data["content"].(string)
		return parseImprovements(strings.NewReader(content), loop, since, limit), nil
	}
	path := improvementsPath(userID, app)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseImprovements(f, loop, since, limit), nil
}

// parseImprovements is the JSONL parser both ledger sources share.
func parseImprovements(r io.Reader, loop, since string, limit int) []improvementEvent {
	var sinceTs time.Time
	if since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			sinceTs = t
		} else if strings.HasSuffix(since, "d") {
			// "7d" → 7 days ago
			n := 0
			if _, err := fmt.Sscanf(since, "%dd", &n); err == nil && n > 0 {
				sinceTs = time.Now().Add(-time.Duration(n) * 24 * time.Hour)
			}
		}
	}

	out := []improvementEvent{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e improvementEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if loop != "" && e.Loop != loop {
			continue
		}
		if !sinceTs.IsZero() {
			if t, err := time.Parse(time.RFC3339, e.Ts); err == nil && t.Before(sinceTs) {
				continue
			}
		}
		out = append(out, e)
	}
	// Newest first.
	sort.Slice(out, func(i, j int) bool { return out[i].Ts > out[j].Ts })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// summarizeImprovements computes per-axis movement counts + deltas
// so the UI card + narrative panel can render without re-walking
// the ledger.
type axisMovement struct {
	Axis   string  `json:"axis"`
	Count  int     `json:"count"`            // # events on this axis in the window
	Net    float64 `json:"net,omitempty"`    // sum of `delta.after - delta.before` when numeric
	Latest string  `json:"latest,omitempty"` // most-recent label on this axis
}

func summarizeImprovements(events []improvementEvent) []axisMovement {
	by := map[string]*axisMovement{}
	for _, e := range events {
		am, ok := by[e.Axis]
		if !ok {
			am = &axisMovement{Axis: e.Axis}
			by[e.Axis] = am
		}
		am.Count++
		if am.Latest == "" {
			am.Latest = e.Label // first (newest, since events are newest-first) wins
		}
		// Best-effort numeric delta accumulation.
		if d, ok := e.Delta.(map[string]any); ok {
			beforeV, _ := d["before"].(float64)
			afterV, _ := d["after"].(float64)
			if beforeV != 0 || afterV != 0 {
				am.Net += afterV - beforeV
			}
		}
	}
	// Stable axis order for rendering.
	order := []string{"standard", "examples", "memory", "rules", "recipe", "pieces"}
	out := []axisMovement{}
	for _, a := range order {
		if am, ok := by[a]; ok {
			out = append(out, *am)
		}
	}
	return out
}

// ─── HTTP handlers ──────────────────────────────────────────────

// MeFeedbackSave — POST /api/v1/me/feedback
// Body: {app, loop?, cycle_ts?, output_id?, kind: good|edit|wrong,
//
//	note?, label?, ...}
//
// Maps the kind to (axis, verb): all three map to axis="examples"
// with verb=kind. The cycle hook side appends OTHER axes
// (memory/rules/standard/pieces/recipe) as separate events.
func MeFeedbackSave(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		App      string `json:"app"      binding:"required"`
		Loop     string `json:"loop"`
		CycleTs  string `json:"cycle_ts"`
		OutputID string `json:"output_id"`
		Kind     string `json:"kind"     binding:"required"`
		Note     string `json:"note"`
		Label    string `json:"label"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if !slugRe.MatchString(body.App) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if body.Loop != "" && !slugRe.MatchString(body.Loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop name")
		return
	}
	if body.Kind != "good" && body.Kind != "edit" && body.Kind != "wrong" {
		fail(c, http.StatusBadRequest, 1400, "kind must be good|edit|wrong")
		return
	}
	if len(body.Note) > feedbackMaxNote {
		fail(c, http.StatusRequestEntityTooLarge, 1413, "note too long")
		return
	}

	label := body.Label
	if label == "" {
		switch body.Kind {
		case "good":
			label = "user 👍 on output"
		case "edit":
			label = "user ✏️ — edited then accepted"
		case "wrong":
			label = "user 👎 on output"
		}
	}

	e := &improvementEvent{
		App:       body.App,
		Loop:      body.Loop,
		CycleTs:   body.CycleTs,
		OutputID:  body.OutputID,
		Axis:      "examples",
		Verb:      body.Kind,
		Label:     label,
		Rationale: body.Note,
		Source:    "user",
	}
	// Owner write — the ledger of the caller's own install. shared → 403,
	// not installed → 404, before anything is minted or queued.
	if _, direct, viaIntent, shared := ownerWriteTarget(userID, body.App); !direct && !viaIntent {
		ownerWriteFail(c, shared)
		return
	}
	intentID, err := appendImprovement(userID, e)
	if err != nil {
		if errors.Is(err, errImprovementNotOwned) {
			fail(c, http.StatusNotFound, 1404, "app not found")
			return
		}
		if errors.Is(err, errAppFileTooBig) {
			fail(c, http.StatusRequestEntityTooLarge, 1413, "feedback record exceeds 16 KB")
			return
		}
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	if intentID != "" {
		respondQueued(c, intentID, gin.H{"id": e.ID, "ts": e.Ts})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"id": e.ID, "ts": e.Ts},
	})
}

// MeIntentAudit — GET /api/v1/me/intents/:id/audit?since=&loop=
// Returns events + per-axis summary. :id is the intent id which
// for now equals the xpio app name (matches how `lumid app_list`
// surfaces intents). When loop= is passed, scopes to one loop.
func MeIntentAudit(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("id")
	if app == "" {
		fail(c, http.StatusBadRequest, 1400, "intent id (app) required")
		return
	}
	since := c.Query("since")
	loop := c.Query("loop")
	limit := 200
	events, err := readImprovements(ginReqCtx(c), userID, app, loop, since, limit)
	if err != nil {
		if errors.Is(err, errReadIntentTimeout) {
			fail(c, http.StatusGatewayTimeout, 1504, "reading the improvements ledger timed out waiting for the scheduler — try again in a moment")
			return
		}
		var rf *readIntentFailed
		if errors.As(err, &rf) {
			fail(c, http.StatusBadGateway, 1502, "reading the improvements ledger failed: "+rf.msg)
			return
		}
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	axes := summarizeImprovements(events)
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"intent_id":      app,
			"loop":           loop,
			"since":          since,
			"event_count":    len(events),
			"axis_movements": axes,
			"events":         events,
		},
	})
}
