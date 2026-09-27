package handler

// Engine-revamp integration — the human checkpoint.
//
// POST /api/v1/me/cycles/:app/:loop/:ts/review
//
// The Studio review surface (lumid_ui) renders a cycle's review queue
// (act steps held by approval_policy) + compound offers, with approve /
// edit / revamp controls. This endpoint translates those controls into
// the SAME side files the LumidOS engine (app_runner.py) consumes on the
// loop's next cycle:
//
//   approve  → data/approved_actions.json   { "<loop>:<step_id>": {approved_at} }
//              (consumed by _consume_action_approval → the held act runs)
//   revamp   → data/step_instructions_pending.json  { "<loop>": { "<step_id>": text } }
//              (consumed by _consume_step_instructions → reshapes the step)
//   dismiss  → no-op (the held action simply re-stages next cycle)
//
// Writes only within the caller's tenant tree.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type cycleReviewBody struct {
	OutboxRef        string `json:"outbox_ref"`        // "<loop>:<step_id>" — approve
	StepID           string `json:"step_id"`           // revamp target / approve fallback
	Decision         string `json:"decision"`          // approve | revamp | dismiss
	StepInstructions string `json:"step_instructions"` // revamp text
}

// MeCycleReview serves POST /api/v1/me/cycles/:app/:loop/:ts/review.
func MeCycleReview(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Param("loop")
	if !slugRe.MatchString(app) || !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or loop")
		return
	}
	var body cycleReviewBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}

	code, msg, intentID := applyCycleReview(userID, app, loop, body)
	if code != 0 {
		fail(c, code, code+1000, msg)
		return
	}
	if intentID != "" {
		respondQueued(c, intentID, gin.H{
			"app": app, "loop": loop, "ts": c.Param("ts"), "decision": body.Decision,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"app": app, "loop": loop, "ts": c.Param("ts"),
			"decision": body.Decision,
		},
	})
}

// applyCycleReview is MeCycleReview's core, shared with the chat tool
// `review_action`. Returns (0, "", intentID) on success or (httpStatus,
// message, ""). intentID is non-empty when the decision was QUEUED rather
// than written.
//
// Owner write: only the caller's own install. It used to MkdirAll
// <tenant>/.xp/apps/<app>/data whether or not the app was installed — on a
// cloud pod that is a pod-local directory the engine never reads. identity
// mounts no tenant volume; the scheduler can see the disk, so there the
// decision is queued as an app_file_write json_set, which changes only the one
// key — the engine rewrites these files itself as it consumes them, and a
// whole-file write from here would race it.
func applyCycleReview(userID, app, loop string, body cycleReviewBody) (int, string, string) {
	appDir, direct, viaIntent, shared := ownerWriteTarget(userID, app)
	if !direct && !viaIntent {
		if shared {
			return http.StatusForbidden, "this app is operator-shared (read-only) — install your own copy first", ""
		}
		return http.StatusNotFound, "app not found", ""
	}
	rel, set, code, msg := cycleReviewSet(loop, body, time.Now().UTC())
	if code != 0 {
		return code, msg, ""
	}
	if rel == "" {
		return 0, "", "" // dismiss: nothing to write either way
	}
	if viaIntent {
		id, err := queueAppFileOps(userID, app, func() ([]map[string]any, error) {
			op, err := jsonSetOp(rel, set)
			return []map[string]any{op}, err
		})
		if err != nil {
			return http.StatusInternalServerError, "queue intent: " + err.Error(), ""
		}
		return 0, "", id
	}

	dataDir := filepath.Join(appDir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return http.StatusInternalServerError, "mkdir: " + err.Error(), ""
	}
	kp := set[0].([]string)
	if err := reviewMergeJSON(filepath.Join(appDir, rel), func(m map[string]any) {
		if len(kp) == 1 {
			m[kp[0]] = set[1]
			return
		}
		inner, _ := m[kp[0]].(map[string]any)
		if inner == nil {
			inner = map[string]any{}
		}
		inner[kp[1]] = set[1]
		m[kp[0]] = inner
	}); err != nil {
		return http.StatusInternalServerError, err.Error(), ""
	}
	return 0, "", ""
}

// cycleReviewSet turns a decision into (file, one json_set pair). The direct
// write and the queued one apply the same pair, so they cannot drift:
//
//	approve       → data/approved_actions.json          [[ref], {approved_at}]
//	revamp|edit   → data/step_instructions_pending.json [[loop, step_id], text]
//	dismiss       → rel "" (no-op)
func cycleReviewSet(loop string, body cycleReviewBody, now time.Time) (rel string, set []any, code int, msg string) {
	switch body.Decision {
	case "approve":
		ref := body.OutboxRef
		if ref == "" && body.StepID != "" {
			ref = loop + ":" + body.StepID
		}
		if ref == "" {
			return "", nil, http.StatusBadRequest, "approve needs outbox_ref or step_id"
		}
		return approvedActsRel, jsonSetPair(map[string]any{"approved_at": now.Format(time.RFC3339)}, ref), 0, ""
	case "revamp", "edit":
		if body.StepID == "" || strings.TrimSpace(body.StepInstructions) == "" {
			return "", nil, http.StatusBadRequest, "revamp needs step_id and step_instructions"
		}
		return stepInstrPendRel, jsonSetPair(body.StepInstructions, loop, body.StepID), 0, ""
	case "dismiss":
		// No-op: the held action simply re-stages on the next cycle.
		return "", nil, 0, ""
	default:
		return "", nil, http.StatusBadRequest, "unknown decision: " + body.Decision
	}
}

// reviewMergeJSON reads a JSON object file (or {} if absent), applies mut,
// and writes it back.
func reviewMergeJSON(path string, mut func(map[string]any)) error {
	m := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	mut(m)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
