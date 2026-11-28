package handler

// Discard results (round 10, 2026-11-28): hide an experiment's ledger rows
// without deleting them. The scheduler owns the tenant volume, so this queues
// a `discard_results` intent; LumidOS sdk/apps/discard.py appends tombstones
// (reversible, with who and why) and re-evaluates. Hidden rows still reach
// the UI, marked dims.discarded, so they can be shown and restored.

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type discardMatch struct {
	VariantID string `json:"variant_id,omitempty"`
	CycleTS   string `json:"cycle_ts,omitempty"`
	Stage     string `json:"stage,omitempty"`
	Row       string `json:"row,omitempty"`
}

func (m discardMatch) empty() bool {
	return strings.TrimSpace(m.VariantID+m.CycleTS+m.Stage+m.Row) == ""
}

// discardBodyError says what is wrong with a discard request, or "".
func discardBodyError(action, reason string, matches []discardMatch) string {
	if action != "discard" && action != "restore" {
		return "action must be discard or restore"
	}
	if len(matches) == 0 || len(matches) > 200 {
		return "name 1 to 200 sets of results (by version, run, step or row)"
	}
	for _, m := range matches {
		if m.empty() {
			return "every match needs a version, run, step or row"
		}
		for _, v := range []string{m.VariantID, m.CycleTS, m.Stage, m.Row} {
			if len(v) > 200 || strings.ContainsAny(v, "\n\r") {
				return "a match value is too long or has a line break"
			}
		}
	}
	if action == "discard" && strings.TrimSpace(reason) == "" {
		return "say why these results are discarded — it is shown beside them"
	}
	return ""
}

// MeAppExperimentDiscard: POST /me/apps/:app/experiments/:id/discard
// {action: discard|restore, reason, matches: [{variant_id?, cycle_ts?, stage?, row?}]}
func MeAppExperimentDiscard(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app, id := c.Param("app"), c.Param("id")
	if !slugRe.MatchString(app) || !slugRe.MatchString(id) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or experiment")
		return
	}
	var body struct {
		Action  string         `json:"action"`
		Reason  string         `json:"reason"`
		Matches []discardMatch `json:"matches"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Action == "" {
		body.Action = "discard"
	}
	if why := discardBodyError(body.Action, body.Reason, body.Matches); why != "" {
		fail(c, http.StatusBadRequest, 1400, why)
		return
	}
	matches := make([]map[string]any, 0, len(body.Matches))
	for _, m := range body.Matches {
		mm := map[string]any{}
		for k, v := range map[string]string{"variant_id": m.VariantID, "cycle_ts": m.CycleTS, "stage": m.Stage, "row": m.Row} {
			if v = strings.TrimSpace(v); v != "" {
				mm[k] = v
			}
		}
		matches = append(matches, mm)
	}
	iid := writeIntent(c, "discard_results", userID, map[string]any{
		"app": app, "experiment": id, "action": body.Action,
		"reason": strings.TrimSpace(body.Reason), "matches": matches,
	})
	if iid == "" {
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"ret_code": 0, "message": body.Action + " queued",
		"data": gin.H{"app": app, "experiment": id, "action": body.Action, "matches": len(matches),
			"intent_id": iid, "status": "pending"}})
}
