package handler

// toolAppReport returns the caller's OWN scorecard for an app.
//
// Why this exists: the app's page and its procedure both tell the user to type
// "scorecard", and there was no verb behind the word. The agent, asked for
// something it had no tool for, did what a helpful model does — it produced a
// table from the conversation. That is an invented benchmark wearing the app's
// authority, which is the same failure app_judge was built to end.
//
// The data was already there and unread. recordChatCycle writes one MeAppRun per
// chat turn, keyed on user_sub, with the judge's own numbers in its metrics
// blob. This reads them back; it computes nothing the judge did not already say.
//
// Scoped by construction: appRunsFor filters on user_sub, so there is no
// parameter here through which one user could ask for another's rows.

import (
	"encoding/json"
	"sort"
)

// reportRow is one scored turn.
type reportRow struct {
	RunTs    int64   `json:"run_ts"`
	QID      string  `json:"q_id,omitempty"`
	CaseID   string  `json:"case_id,omitempty"`
	Mode     string  `json:"mode,omitempty"`
	Subject  string  `json:"subject,omitempty"`
	Grounded bool    `json:"grounded"`
	Score    float64 `json:"score"`
	Axes     any     `json:"axes,omitempty"`
	PanelN   int     `json:"panel_n,omitempty"`
	// Independent is a pointer so "the judge was the analyst" and "this turn
	// predates panel labelling" stay distinguishable. Collapsing them to false
	// would retroactively brand old rows as self-scored.
	Independent *bool `json:"independent,omitempty"`
}

func toolAppReport(userID, app string) (map[string]any, bool) {
	if app == "" {
		return map[string]any{"error": "app is required"}, false
	}
	// The trigger loop is the one whose contract is "runs when you talk", so it
	// is where chat turns are recorded. Empty means the app declares none — read
	// every loop rather than returning nothing, because a missing scorecard is
	// indistinguishable from a bad one to the person reading it.
	rows := appRunsFor(userID, app, triggerLoopFor(userID, app))

	scored := []reportRow{}
	unscored := 0
	for _, r := range rows {
		var m map[string]any
		if r.Metrics == "" || json.Unmarshal([]byte(r.Metrics), &m) != nil {
			continue
		}
		score, ok := m["score"].(float64)
		if !ok {
			// A turn that answered but was never scored. Counted, not tabled —
			// dropping it silently would make the scorecard imply every turn was
			// judged, and padding it with a zero would be a fabricated number.
			unscored++
			continue
		}
		row := reportRow{RunTs: r.RunTs, Score: score}
		row.QID, _ = m["q_id"].(string)
		row.CaseID, _ = m["case_id"].(string)
		row.Mode, _ = m["mode"].(string)
		row.Subject, _ = m["subject"].(string)
		row.Grounded, _ = m["grounded"].(bool)
		row.Axes = m["axes"]
		switch v := m["panel_n"].(type) {
		case float64:
			row.PanelN = int(v)
		case int:
			row.PanelN = v
		}
		if v, ok := m["independent"].(bool); ok {
			row.Independent = &v
		}
		scored = append(scored, row)
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].RunTs < scored[j].RunTs })

	out := map[string]any{
		"app":        app,
		"turns":      scored,
		"n_scored":   len(scored),
		"n_unscored": unscored,
	}
	if len(scored) == 0 {
		out["note"] = "no scored turns yet — answer a case question and ask for a score first"
		return out, true
	}

	// Averaged in FOUR buckets, never one.
	//
	// grounded vs open is the app's central contract: an open-mode score comes
	// from keypoints the judge invented for the occasion and runs near ceiling
	// (a session on record reads 100/100/96 against grounded casebook scores of
	// 54-65). Averaging them produces a number that is neither.
	//
	// ai vs human is the same hazard on the other axis: in interviewer mode the
	// USER is the candidate, and their score landing in the same mean as the
	// model's is the corruption commands/_session.py::summary guards against.
	buckets := map[string][]float64{}
	for _, r := range scored {
		g := "open"
		if r.Grounded {
			g = "casebook"
		}
		s := r.Subject
		if s == "" {
			s = "ai"
		}
		buckets[g+"/"+s] = append(buckets[g+"/"+s], r.Score)
	}
	avgs := map[string]any{}
	for k, vs := range buckets {
		sum := 0.0
		for _, v := range vs {
			sum += v
		}
		avgs[k] = map[string]any{"n": len(vs), "avg_score": sum / float64(len(vs))}
	}
	out["averages"] = avgs
	out["note"] = "casebook averages are ground-truth backed; open averages are indicative only " +
		"(the judge derives its own keypoints, so they run high). Never present them as one number."
	return out, true
}
