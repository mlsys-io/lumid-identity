package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"github.com/gin-gonic/gin"
	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Cohort research submissions — the reviewer's side of the progress protocol.
//
// A researcher files a fortnight with the `submit` verb of lumid-cohort-digest.
// That verb's return value is recorded as an app run against their own account,
// which is exactly right for attribution — a submission is authored under the
// researcher's own token and its measured half is re-derived from their own
// /api/v1/me/* telemetry, so nobody can file numbers for someone else, or
// inflate their own by editing a file.
//
// It is also, on its own, unreadable: every /me/* path is scoped to
// `currentUserID`, so with twenty researchers there was no way to see the
// cohort at all. The progress-protocol doc says so plainly — "there is no
// operator path that reads another tenant's runs, and that is the correct
// shape" — and it is the correct shape for the WRITE side. Review is the one
// job that genuinely needs to read across it, so it gets its own admin-gated
// door rather than widening the researcher-facing one.
//
// WHY ADMIN AND NOT SUPER_ADMIN. Reviewing a cohort's written reports is
// oversight, not privilege escalation: it moves no money, grants no scope and
// changes no state. It mirrors the LQT lane model, where `admin` already holds
// cross-tenant VIEW of any user's strategies and cycles while promotion and
// real-trade stay super_admin. Read-only by construction — this file has no
// write path.
//
// WHAT IT DELIBERATELY DOES NOT DO. It does not render or score the written
// half. Telemetry cannot tell a researcher who converged from one who merely
// ran loops; that judgement is the reviewer's, and a summariser between the two
// would quietly become the thing being read.

const cohortDigestApp = "lumid-cohort-digest"

// One researcher's filed fortnight, flattened for a reviewer's list.
type cohortSubmission struct {
	UserSub string `json:"user_sub"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`

	ForPeriod   string `json:"for_period"`
	SubmittedAt string `json:"submitted_at,omitempty"`
	RunTs       int64  `json:"run_ts"`
	Ok          bool   `json:"ok"`
	Note        string `json:"note,omitempty"`

	// The four prompts. Carried whole: they ARE the submission, and a reviewer
	// reading a truncated Evidence section is reading a different report.
	Written map[string]string `json:"written,omitempty"`

	// Lengths alongside the text so a list view can be sorted or scanned for
	// the one-word answer without reading twenty reports first.
	Answered map[string]int `json:"answered,omitempty"`

	// The measured half's LQT counts — what the written claim rests on. A
	// fortnight claiming a result with zero real backtests behind it is the
	// pair worth seeing side by side.
	LQT map[string]any `json:"lqt,omitempty"`
}

// AdminCohortSubmissions — GET /admin/cohort/submissions
//
// Query: app (default lumid-cohort-digest), period (exact, e.g. 2026-08-29),
//
//	user (sub), limit (default 200, max 1000), loop (default "submit").
//
// `loop` exists because me_app_runs had NO reader that could list it. The
// trajectory and /me/runs surfaces both reconstruct history from the tenant
// tree on disk — which identity cannot mount — and merely OVERLAY the run
// store onto what they find there. So a row could be written correctly and
// still be invisible everywhere, and on 2026-08-31 that turned a four-layer
// scheduler bug into a hunt: every reader answered "nothing" whether the
// write had worked or not.
//
// Defaulting to "submit" keeps this endpoint's own contract unchanged; naming
// another loop turns it into the direct read of the run store that was
// missing. Same admin gate, same tenant-resolution, one more WHERE.
func AdminCohortSubmissions(c *gin.Context) {
	app := c.DefaultQuery("app", cohortDigestApp)
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	loop := c.DefaultQuery("loop", "submit")
	if !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	limit := 200
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			fail(c, http.StatusBadRequest, 1400, "limit must be a positive integer")
			return
		}
		if n > 1000 {
			n = 1000
		}
		limit = n
	}

	q := common.DB.Where("app IN ? AND `loop` = ?", appAliases(app), loop)
	if u := c.Query("user"); u != "" {
		q = q.Where("user_sub = ?", u)
	}
	var rows []models.MeAppRun
	// Newest first: a reviewer opens this to see what has landed since they
	// last looked, not to read the cohort's history from the beginning.
	if err := q.Order("run_ts DESC").Limit(limit).Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "could not read submissions")
		return
	}

	// Resolve identities in one query rather than per row. A reviewer needs a
	// name against each report; twenty round-trips to render one page is the
	// kind of thing that only shows up once the cohort is full.
	subs := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, r := range rows {
		if !seen[r.UserSub] {
			seen[r.UserSub] = true
			subs = append(subs, r.UserSub)
		}
	}
	type ident struct{ email, name string }
	who := map[string]ident{}
	if len(subs) > 0 {
		var users []models.User
		if common.DB.Where("id IN ?", subs).Find(&users).Error == nil {
			for _, u := range users {
				who[u.ID] = ident{u.Email, u.Name}
			}
		}
	}

	period := c.Query("period")
	out := make([]cohortSubmission, 0, len(rows))
	for _, r := range rows {
		sub := extractSubmission(r.Metrics)
		forPeriod, _ := sub["for_period"].(string)
		// Filter AFTER extraction: the period lives inside the run's metrics
		// blob, not in a column, so it cannot be pushed into the query.
		if period != "" && forPeriod != period {
			continue
		}
		item := cohortSubmission{
			UserSub: r.UserSub, ForPeriod: forPeriod, RunTs: r.RunTs, Ok: r.Ok,
			Email: who[r.UserSub].email, Name: who[r.UserSub].name,
		}
		if v, okk := sub["submitted_at"].(string); okk {
			item.SubmittedAt = v
		}
		if v, okk := sub["note"].(string); okk {
			item.Note = v
		}
		if w, okk := sub["written"].(map[string]any); okk {
			item.Written = map[string]string{}
			item.Answered = map[string]int{}
			for k, v := range w {
				s, _ := v.(string)
				item.Written[k] = s
				item.Answered[k] = len(s)
			}
		}
		if l, okk := sub["lqt"].(map[string]any); okk {
			item.LQT = l
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RunTs > out[j].RunTs })

	// `researchers` is the number a reviewer actually acts on — twelve reports
	// from four people is a different week from twelve people filing once.
	filed := map[string]bool{}
	for _, s := range out {
		filed[s.UserSub] = true
	}
	ok(c, "ok", gin.H{
		"app":         app,
		"submissions": out,
		"count":       len(out),
		"researchers": len(filed),
	})
}

// extractSubmission pulls the `submission` object out of a run's metrics blob.
//
// The submit verb returns it at the top level of its result, but a run's
// metrics is an opaque per-app JSON document and the engine may nest a
// command's return under its own key — so look one level down too rather than
// silently rendering an empty row for a submission that is present.
func extractSubmission(metrics string) map[string]any {
	if metrics == "" {
		return nil
	}
	var doc map[string]any
	if json.Unmarshal([]byte(metrics), &doc) != nil {
		return nil
	}
	if s, okk := doc["submission"].(map[string]any); okk {
		return s
	}
	for _, v := range doc {
		if m, okk := v.(map[string]any); okk {
			if s, okk2 := m["submission"].(map[string]any); okk2 {
				return s
			}
		}
	}
	return nil
}
