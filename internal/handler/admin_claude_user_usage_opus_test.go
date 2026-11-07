package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"lumid_identity/models"
)

// TEST_MYSQL_DSN=... go test ./internal/handler -run UserUsageOpus
func TestAdminClaudeUserUsageOpusFields(t *testing.T) {
	db := setupAdminClaudeUsageDB(t)
	now := time.Now().UTC()
	adm, sup := "00000000-0000-4000-8000-00000000a0a1", "00000000-0000-4000-8000-00000000a0a2"
	for _, id := range []string{adm, sup} {
		db.Where("id = ?", id).Delete(&models.User{})
		db.Where("user_sub = ?", id).Delete(&models.UsageEvent{})
		db.Where("user_sub = ?", id).Delete(&models.ClaudePoolWindow{})
	}
	db.Create(&models.User{ID: adm, Email: "opus-ui-admin@test.local", Role: "admin", Status: "active"})
	db.Create(&models.User{ID: sup, Email: "opus-ui-super@test.local", Role: "super_admin", Status: "active"})
	for _, id := range []string{adm, sup} {
		db.Create(&models.ClaudePoolWindow{UserSub: id, FiveHourAnchor: now.Add(-time.Hour), SevenDayAnchor: now.Add(-72 * time.Hour)})
		db.Create(&models.UsageEvent{UserSub: id, Ts: now.Add(-48 * time.Hour), Kind: "claude_proxy", Model: "claude-opus-5-5", InputTokens: 151_000_000})
		db.Create(&models.UsageEvent{UserSub: id, Ts: now.Add(-30 * time.Minute), Kind: "claude_proxy", Model: "claude-opus-5-5", InputTokens: 2_000_000})
		db.Create(&models.UsageEvent{UserSub: id, Ts: now.Add(-20 * time.Minute), Kind: "claude_proxy", Model: "claude-sonnet-5", InputTokens: 5_000_000})
	}
	w := httptest.NewRecorder()
	adminClaudeUsageRouter().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/admin/claude-user-usage", nil))
	var resp struct {
		Data struct {
			Users     []map[string]any `json:"users"`
			OpusAdmin float64          `json:"opus_admin_seven_day_tokens"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if resp.Data.OpusAdmin != 150_000_000 {
		t.Errorf("opus_admin_seven_day_tokens = %v", resp.Data.OpusAdmin)
	}
	found := 0
	for _, u := range resp.Data.Users {
		switch u["email"] {
		case "opus-ui-admin@test.local":
			found++
			if u["opus_seven_day_tokens"] != float64(153_000_000) || u["opus_five_hour_tokens"] != float64(2_000_000) ||
				u["opus_seven_day_limit"] != float64(150_000_000) || u["opus_exhausted"] != true {
				t.Errorf("admin opus fields: %v %v %v %v", u["opus_seven_day_tokens"], u["opus_five_hour_tokens"], u["opus_seven_day_limit"], u["opus_exhausted"])
			}
		case "opus-ui-super@test.local":
			found++
			if u["opus_seven_day_limit"] != float64(0) || u["opus_exhausted"] != false {
				t.Errorf("super_admin must be uncapped: %v %v", u["opus_seven_day_limit"], u["opus_exhausted"])
			}
		}
	}
	if found != 2 {
		t.Fatalf("users not in response: %s", w.Body.String()[:400])
	}
	for _, id := range []string{adm, sup} {
		db.Where("id = ?", id).Delete(&models.User{})
		db.Where("user_sub = ?", id).Delete(&models.UsageEvent{})
		db.Where("user_sub = ?", id).Delete(&models.ClaudePoolWindow{})
	}
}
