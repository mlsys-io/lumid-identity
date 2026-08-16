package handler

// Phase S6c — agent tool implementations for the Studio chat surface.
// Each function maps a chat tool call (dispatched from me_agent.go)
// onto the same logic the /me/* HTTP routes use. The thin wrappers
// here exist so the chat agent can act on Studio surfaces without
// going through HTTP round-trips back to itself.

import (
	"encoding/json"
	"fmt"
	"lumid_identity/models"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// toolTodaySummary — same shape as MeToday returns, callable in-
// process so the chat doesn't need to round-trip. Builds the
// headlines + cycles + drafts-pending payload the user expects when
// they ask "what's pending" or "what's new".
func toolTodaySummary(userID string) map[string]any {
	headlines := []map[string]any{}
	cycles := []map[string]any{}
	quotaSurfaced := false

	pending := countPendingDraftsForUser(userID)
	if pending > 0 {
		headlines = append(headlines, map[string]any{
			"kind":    "drafts",
			"summary": pluralize(pending, "draft is waiting for you.", "drafts are waiting for you."),
			"count":   pending,
		})
	}

	tenantApps := tenantAppsDir(userID)
	dirs, _ := os.ReadDir(tenantApps)
	startOfDay := todayBoundary()
	for _, d := range dirs {
		if !d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			continue
		}
		appName := d.Name()
		journal := filepath.Join(tenantApps, appName, "data", "journal.jsonl")
		rows := readTodayJournal(journal, startOfDay)
		latest := map[string]map[string]any{}
		for _, r := range rows {
			loop, _ := r["loop"].(string)
			if loop == "" {
				continue
			}
			latest[loop] = r
		}
		for loop, r := range latest {
			ok, _ := r["ok"].(bool)
			skipped, _ := r["skipped"].(bool)
			reason, _ := r["reason"].(string)
			ts, _ := r["iso"].(string)
			cycles = append(cycles, map[string]any{
				"app": appName, "loop": loop, "ok": ok, "skipped": skipped,
				"reason": reason, "ts": ts,
			})
			if skipped && strings.HasPrefix(reason, "quota_exceeded") && !quotaSurfaced {
				headlines = append(headlines, map[string]any{
					"kind":    "quota_paused",
					"summary": "Free tier reached today.",
					"detail":  "Your AI resumes at midnight UTC, or add ANTHROPIC_API_KEY in Settings to upgrade.",
				})
				quotaSurfaced = true
			} else if ok && isBriefLoop(loop) {
				headlines = append(headlines, map[string]any{
					"kind":    "brief",
					"summary": "Your " + humanizeLoop(loop) + " is ready.",
					"app":     appName, "loop": loop, "ts": ts,
				})
			} else if !ok && !skipped {
				headlines = append(headlines, map[string]any{
					"kind":    "cycle_failed",
					"summary": humanizeLoop(loop) + " didn't run cleanly.",
					"app":     appName, "loop": loop, "ts": ts,
				})
			}
		}
	}

	sort.SliceStable(headlines, func(i, j int) bool {
		return todayKindOrder(headlines[i]["kind"].(string)) < todayKindOrder(headlines[j]["kind"].(string))
	})
	return map[string]any{
		"headlines":      headlines,
		"cycles":         cycles,
		"drafts_pending": pending,
		"as_of":          time.Now().UTC().Format(time.RFC3339),
	}
}

// todayBoundary returns midnight-UTC. Free-standing wrapper so the
// agent tool file doesn't need to drag in the common package alias
// dance — it just calls the same time.Time the quota module uses.
func todayBoundary() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
}

// toolListDrafts — pending drafts, optionally scoped to one app.
// Same disk layout MeDraftsList walks; the agent sees only what
// the user could see in /studio/inbox.
func toolListDrafts(userID, appFilter string) map[string]any {
	tenantApps := tenantAppsDir(userID)
	apps, err := os.ReadDir(tenantApps)
	if err != nil {
		return map[string]any{"drafts": []any{}, "count": 0}
	}
	out := []map[string]any{}
	for _, a := range apps {
		if !a.IsDir() || strings.HasPrefix(a.Name(), ".") {
			continue
		}
		if appFilter != "" && a.Name() != appFilter {
			continue
		}
		appDir := filepath.Join(tenantApps, a.Name())
		stateMap := loadStateMap(appDir)
		for _, card := range listDraftsForApp(appDir, a.Name(), stateMap) {
			if card.State != "pending" {
				continue
			}
			out = append(out, map[string]any{
				"id":      card.ID,
				"app":     card.App,
				"to":      card.To,
				"subject": card.Subject,
				"body":    card.Body,
			})
		}
	}
	// Union the DB-backed store, exactly as MeDraftsList does. Without this the
	// chat sees a strictly smaller set than the Review table it is meant to
	// operate on: app_feedback stages into the DB, and a CLOUD-installed app
	// (or any kind=agent app, which lives under .xp/agents/ rather than the
	// .xp/apps/ tree walked above) has nothing on disk here at all. Observed
	// live — the user pressed Open on a visible pending row and the agent
	// correctly reported 0 drafts and no such id, because the row it was
	// looking at came from a store this tool could not see.
	if rows, err := draftStoreList(userID, appFilter, "pending"); err == nil {
		for _, r := range rows {
			out = append(out, map[string]any{
				"id": r.ID, "app": r.App, "agent": r.Agent,
				"subject": r.Subject, "body": r.Body,
			})
		}
	}
	return map[string]any{"drafts": out, "count": len(out)}
}

// toolDraftAction — send / dismiss / edit. Uses the same path
// MeDraftSend/Edit/Dismiss exercise, minus the HTTP envelope.
func toolDraftAction(userID, id, action string, patch map[string]any) map[string]any {
	abs, app, rel := resolveDraftByID(userID, id)
	if abs == "" {
		// Not on disk — try the DB store. The filesystem path below is the
		// EMAIL pipeline: "send" enqueues an intent the scheduler drains through
		// the app's skills/email/send.py under the tenant's Gmail grant. A
		// feedback draft has no such file and no recipient, so routing it there
		// fails deep in the scheduler rather than here. Dismiss is the same
		// gesture for both, so it is honoured; approval is not, because for a
		// feedback draft "approve" means ingest into the knowledge graph, which
		// is not this path and does not yet exist.
		return dbDraftAction(userID, id, action)
	}
	appDir := filepath.Join(tenantAppsDir(userID), app)
	stateMap := loadStateMap(appDir)
	current := stateMap[id]
	if current.State == "" {
		current.State = "pending"
	}
	if current.State == "sent" && action != "edit" {
		return map[string]any{"error": "draft already sent"}
	}

	switch action {
	case "send":
		intentID := writeIntentDirect(userID, "send_draft", map[string]any{
			"app":        app,
			"draft_path": rel,
			"draft_id":   id,
		})
		if intentID == "" {
			return map[string]any{"error": "intent write failed"}
		}
		stateMap[id] = draftState{
			State:    "sent",
			ActedAt:  time.Now().UTC().Format(time.RFC3339),
			IntentID: intentID,
		}
		if err := saveStateMap(appDir, stateMap); err != nil {
			return map[string]any{"error": "save state: " + err.Error()}
		}
		return map[string]any{
			"sent":      true,
			"intent_id": intentID,
			"note":      "Gmail send queued; result lands in audit within a few seconds.",
		}

	case "dismiss":
		stateMap[id] = draftState{
			State:   "dismissed",
			ActedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := saveStateMap(appDir, stateMap); err != nil {
			return map[string]any{"error": "save state: " + err.Error()}
		}
		return map[string]any{"dismissed": true}

	case "edit":
		// Rewrite the on-disk JSON; resets state to pending.
		b, err := os.ReadFile(abs)
		if err != nil {
			return map[string]any{"error": "read draft: " + err.Error()}
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			return map[string]any{"error": "parse: " + err.Error()}
		}
		if v, ok := patch["subject"].(string); ok && v != "" {
			raw["subject"] = v
		}
		if v, ok := patch["body"].(string); ok && v != "" {
			raw["body"] = v
		}
		raw["edited_at"] = time.Now().UTC().Format(time.RFC3339)
		out, _ := json.MarshalIndent(raw, "", "  ")
		tmp := abs + ".tmp"
		if err := os.WriteFile(tmp, out, 0o644); err != nil {
			return map[string]any{"error": "write: " + err.Error()}
		}
		if err := os.Rename(tmp, abs); err != nil {
			return map[string]any{"error": "rename: " + err.Error()}
		}
		stateMap[id] = draftState{
			State:   "pending",
			ActedAt: time.Now().UTC().Format(time.RFC3339),
		}
		_ = saveStateMap(appDir, stateMap)
		return map[string]any{"edited": true, "id": id, "state": "pending"}
	}
	return map[string]any{"error": "unknown action: " + action}
}

// toolPatchLoop — write a per-loop override (schedule, enabled).
// Mirrors MeLoopPatch but in-process. The picker / scheduler honor
// .user-overrides.yaml the moment it lands.
func toolPatchLoop(userID, app, loop string, patch map[string]any) map[string]any {
	appDir := filepath.Join(tenantAppsDir(userID), app)
	if st, err := os.Stat(appDir); err != nil || !st.IsDir() {
		// Tenant doesn't have the app — try the operator-shared tree
		// for the override file (mirrors MeLoopPatch's fallback).
		shared := filepath.Join(operatorHome(), ".xp", "apps", app)
		if st2, err2 := os.Stat(shared); err2 != nil || !st2.IsDir() {
			return map[string]any{"error": fmt.Sprintf("app %q not installed", app)}
		}
		if err := os.MkdirAll(appDir, 0o775); err != nil {
			return map[string]any{"error": "tenant mkdir: " + err.Error()}
		}
	}
	overridesPath := filepath.Join(appDir, ".user-overrides.yaml")
	overrides := readSimpleOverrides(overridesPath)
	if overrides["loops"] == nil {
		overrides["loops"] = map[string]any{}
	}
	loopsMap, _ := overrides["loops"].(map[string]any)
	loopOver, _ := loopsMap[loop].(map[string]any)
	if loopOver == nil {
		loopOver = map[string]any{}
	}
	if v, ok := patch["schedule"].(string); ok && v != "" {
		loopOver["schedule"] = v
	}
	if v, ok := patch["enabled"].(bool); ok {
		loopOver["enabled"] = v
	}
	loopsMap[loop] = loopOver
	overrides["loops"] = loopsMap
	overrides["_meta"] = map[string]any{
		"last_modified_at": time.Now().UTC().Format(time.RFC3339),
		"last_modified_by": "agent:" + userID,
	}
	if err := writeSimpleOverrides(overridesPath, overrides); err != nil {
		return map[string]any{"error": "write overrides: " + err.Error()}
	}
	return map[string]any{
		"app":       app,
		"loop":      loop,
		"overrides": loopOver,
		"note":      "Override saved. Scheduler picks it up on next refresh tick (≤60s).",
	}
}

// dbDraftAction handles the DB-backed drafts app_feedback stages. Dismiss is
// real. Approval deliberately refuses rather than flipping a state nothing
// consumes: a button that reports success and changes nothing is worse than one
// that says it is not wired yet, because the user stops watching for the effect.
func dbDraftAction(userID, id, action string) map[string]any {
	rows, err := draftStoreList(userID, "", "")
	if err != nil {
		return map[string]any{"error": "draft not found"}
	}
	var found *models.MeDraft
	for i := range rows {
		if rows[i].ID == id {
			found = &rows[i]
			break
		}
	}
	if found == nil {
		return map[string]any{"error": "draft not found"}
	}
	switch action {
	case "dismiss":
		if err := draftStoreAct(userID, id, "rejected"); err != nil {
			return map[string]any{"error": "dismiss: " + err.Error()}
		}
		return map[string]any{"ok": true, "id": id, "state": "rejected",
			"note": "dropped from the review queue; nothing was ingested"}
	case "send":
		return dbDraftApprove(userID, found)
	}
	return map[string]any{"error": "unsupported action for this draft: " + action}
}

// skillFromDraftBody reads the card name out of the marker line skillCardNote
// writes ("Proposed edit to prompts/analyst_skill_<card>.md"). Parsing the body
// rather than the subject keeps the machine-readable fact in one place, and the
// allowlist is re-checked here because this value chooses a file path on the
// other side of an intent boundary.
var skillMarkerRe = regexp.MustCompile(`Proposed edit to prompts/analyst_skill_([a-z][a-z0-9_]{2,40})\.md`)

func skillFromDraftBody(body string) string {
	m := skillMarkerRe.FindStringSubmatch(body)
	if len(m) != 2 || !knownSkillCards[m[1]] {
		return ""
	}
	return m[1]
}

// dbDraftApprove is the last hop: mark the draft approved and hand the work to
// the scheduler, which is the only side that can write the tenant tree (identity
// runs on the service tier; the app PVC is RWO on compute).
//
// The state flip and the intent are deliberately ordered approve-then-enqueue,
// and the flip is rolled back if the enqueue fails. The opposite order can leave
// work queued against a draft the queue still shows as pending, which on a retry
// ingests the same correction twice.
func dbDraftApprove(userID string, d *models.MeDraft) map[string]any {
	skill := skillFromDraftBody(d.Body)
	if d.Agent == "" && skill == "" {
		return map[string]any{"error": "draft names neither a memory agent nor a skill card; nothing to apply"}
	}
	if err := draftStoreAct(userID, d.ID, "approved"); err != nil {
		return map[string]any{"error": "approve: " + err.Error()}
	}
	intentID := writeIntentDirect(userID, "ingest_draft", map[string]any{
		"app":      d.App,
		"draft_id": d.ID,
		"agent":    d.Agent,
		"subject":  d.Subject,
		"body":     d.Body,
		"skill":    skill,
	})
	if intentID == "" {
		// Put it back so the user sees it still needs approving, rather than an
		// approved row whose effect silently never happened.
		_ = draftStoreAct(userID, d.ID, "pending")
		return map[string]any{"error": "could not queue the work; draft left pending"}
	}
	out := map[string]any{"ok": true, "id": d.ID, "state": "approved", "intent_id": intentID}
	if skill != "" {
		out["applies"] = "appends the correction to prompts/analyst_skill_" + skill + ".md, so it shapes every future answer that uses that card"
	} else {
		out["applies"] = "ingests the correction into " + d.Agent + ", so it can be recalled in later answers"
	}
	out["next"] = "queued for the scheduler; it lands within a minute or two, not instantly"
	return out
}
