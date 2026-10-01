package handler

import (
	"encoding/json"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Study definitions in flight. Defining a study (POST /me/agents/:agent/studies,
// /me/apps/:app/experiments, the chat's define_experiment) answers 202 once a
// patch_experiment intent is queued; the scheduler applies it to the user's own
// install later, and can refuse it there (an unlocatable workflow, a guard).
// Until 2026-10-01 nothing read that outcome back: a refused definition looked
// exactly like one still on its way. These readers surface it on the study
// reads the UI already makes.

const studyDefinitionWindow = 7 * 24 * time.Hour

type studyDefinition struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"` // defining | failed | defined
	Error    string    `json:"error,omitempty"`
	IntentID string    `json:"intent_id"`
	At       time.Time `json:"at"`
}

// studyDefinitionStates returns, per study id, the outcome of the LATEST
// definition intent for this user's agent within studyDefinitionWindow.
func studyDefinitionStates(userID, app string) map[string]studyDefinition {
	out := map[string]studyDefinition{}
	if common.DB == nil {
		return out
	}
	var rows []models.MeAppIntent
	common.DB.Where("user_sub = ? AND action = ? AND created_at > ?",
		userID, "patch_experiment", time.Now().Add(-studyDefinitionWindow)).
		Order("created_at desc").Limit(200).Find(&rows)
	for _, r := range rows {
		var p struct {
			App        string `json:"app"`
			Experiment string `json:"experiment"`
		}
		if json.Unmarshal([]byte(r.Payload), &p) != nil || p.App != app || p.Experiment == "" {
			continue
		}
		if _, seen := out[p.Experiment]; seen {
			continue // rows are newest first: the first one is the latest
		}
		d := studyDefinition{ID: p.Experiment, IntentID: r.ID, At: r.CreatedAt}
		switch r.Status {
		case "done":
			d.Status = "defined"
		case "failed":
			d.Status = "failed"
			d.Error = intentResultError(r.Result)
		default: // pending | claimed
			d.Status = "defining"
		}
		out[p.Experiment] = d
	}
	return out
}

// intentResultError is the scheduler's own error from a failed intent's result.
func intentResultError(result string) string {
	var res struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(result), &res)
	msg := strings.TrimSpace(res.Error)
	if msg == "" {
		return "the scheduler refused the definition without a reason"
	}
	return fleetClip(msg, 600)
}

// pendingStudyDefinitions lists definitions that are not (yet) studies: still
// being defined, or refused. `declared` holds the ids the spec already has.
func pendingStudyDefinitions(userID, app string, declared map[string]bool) []studyDefinition {
	out := []studyDefinition{}
	for id, d := range studyDefinitionStates(userID, app) {
		if d.Status == "defining" || (d.Status == "failed" && !declared[id]) {
			out = append(out, d)
		}
	}
	return out
}
