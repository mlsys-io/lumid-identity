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

	if code, msg := applyCycleReview(userID, app, loop, body); code != 0 {
		fail(c, code, code+1000, msg)
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
// `review_action`. Returns (0, "") on success or (httpStatus, message).
func applyCycleReview(userID, app, loop string, body cycleReviewBody) (int, string) {
	dataDir := filepath.Join(tenantAppsDir(userID), app, "data")
	// Anchor inside the tenant tree so app/loop params can't escape.
	abs, err := filepath.Abs(dataDir)
	if err != nil || !strings.HasPrefix(abs, tenantAppsDir(userID)+string(os.PathSeparator)) {
		return http.StatusBadRequest, "invalid path"
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return http.StatusInternalServerError, "mkdir: " + err.Error()
	}

	switch body.Decision {
	case "approve":
		ref := body.OutboxRef
		if ref == "" && body.StepID != "" {
			ref = loop + ":" + body.StepID
		}
		if ref == "" {
			return http.StatusBadRequest, "approve needs outbox_ref or step_id"
		}
		if err := reviewMergeJSON(filepath.Join(dataDir, "approved_actions.json"),
			func(m map[string]any) {
				m[ref] = map[string]any{"approved_at": time.Now().UTC().Format(time.RFC3339)}
			}); err != nil {
			return http.StatusInternalServerError, err.Error()
		}
	case "revamp", "edit":
		if body.StepID == "" || strings.TrimSpace(body.StepInstructions) == "" {
			return http.StatusBadRequest, "revamp needs step_id and step_instructions"
		}
		if err := reviewMergeJSON(filepath.Join(dataDir, "step_instructions_pending.json"),
			func(m map[string]any) {
				loopMap, _ := m[loop].(map[string]any)
				if loopMap == nil {
					loopMap = map[string]any{}
				}
				loopMap[body.StepID] = body.StepInstructions
				m[loop] = loopMap
			}); err != nil {
			return http.StatusInternalServerError, err.Error()
		}
	case "dismiss":
		// No-op: the held action simply re-stages on the next cycle.
	default:
		return http.StatusBadRequest, "unknown decision: " + body.Decision
	}
	return 0, ""
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
