package handler

import (
	"testing"
	"time"

	"lumid_identity/models"
)

// A refused study definition must read as refused, with the scheduler's reason,
// and a later definition of the same study must supersede an earlier one.
func TestStudyDefinitionStates(t *testing.T) {
	db := setupIntentDB(t)
	user := "u-studydef-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { db.Where("user_sub = ?", user).Delete(&models.MeAppIntent{}) })
	now := time.Now()
	add := func(id, exp, status, result string, age time.Duration) {
		t.Helper()
		row := models.MeAppIntent{
			ID: id, Action: "patch_experiment", UserSub: user, Status: status, Result: result,
			Payload: `{"app":"python-study-e2e","experiment":"` + exp + `"}`,
		}
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
		db.Model(&models.MeAppIntent{}).Where("id = ?", id).Update("created_at", now.Add(-age))
	}
	add("11111111-0000-4000-8000-000000000001", "scale", "failed",
		`{"ok":false,"error":"loop 'score_graph' not locatable — refusing"}`, 3*time.Minute)
	add("11111111-0000-4000-8000-000000000002", "scale", "pending", "", time.Minute)
	add("11111111-0000-4000-8000-000000000003", "refused", "failed",
		`{"ok":false,"error":"loop 'score_graph' not locatable — refusing"}`, time.Minute)
	add("11111111-0000-4000-8000-000000000004", "fine", "done", `{"ok":true}`, time.Minute)
	add("11111111-0000-4000-8000-000000000005", "old", "failed", `{"ok":false,"error":"x"}`, 30*24*time.Hour)

	st := studyDefinitionStates(user, "python-study-e2e")
	if st["scale"].Status != "defining" {
		t.Errorf("scale = %+v: the later pending definition supersedes the earlier failure", st["scale"])
	}
	if d := st["refused"]; d.Status != "failed" || d.Error != "loop 'score_graph' not locatable — refusing" {
		t.Errorf("refused = %+v, want failed with the scheduler's reason", d)
	}
	if st["fine"].Status != "defined" {
		t.Errorf("fine = %+v", st["fine"])
	}
	if _, ok := st["old"]; ok {
		t.Error("a definition older than the window is still reported")
	}
	if got := studyDefinitionStates(user, "another-agent"); len(got) != 0 {
		t.Errorf("another agent's definitions leaked: %v", got)
	}

	pending := pendingStudyDefinitions(user, "python-study-e2e", map[string]bool{"fine": true})
	ids := map[string]string{}
	for _, d := range pending {
		ids[d.ID] = d.Status
	}
	if len(ids) != 2 || ids["scale"] != "defining" || ids["refused"] != "failed" {
		t.Errorf("pending = %v, want scale defining + refused failed", ids)
	}
}

func TestIntentResultError(t *testing.T) {
	if got := intentResultError(`{"ok":false,"error":"  boom  "}`); got != "boom" {
		t.Errorf("got %q", got)
	}
	if got := intentResultError(""); got == "" {
		t.Error("an empty result must still say something")
	}
}
