package handler

// Regression test for the AdminClaudePoolAddMember primary-demotion bug
// caught in code review: re-invoking the endpoint as an idempotent "ensure
// member" call (no is_primary in the body) used to unconditionally write
// is_primary=false via the upsert's OnConflict, silently demoting an
// already-primary membership. Runs only when TEST_MYSQL_DSN is set, matching
// this package's existing convention.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func claudePoolMemberRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/v1/admin/claude-pools/:id/members", AdminClaudePoolAddMember)
	return r
}

func postAddMember(t *testing.T, router *gin.Engine, poolID string, body map[string]any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/claude-pools/"+poolID+"/members", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST members: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	return resp.Data
}

func TestAdminClaudePoolAddMember_ReinvokeDoesNotDemotePrimary(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	router := claudePoolMemberRouter()

	poolA := "cptest-addmember-a"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'A', 'distributed')`, poolA)
	cleanupClaudePool(t, db, poolA)

	sub := claudePoolTestUser(t, db, "addmem")

	// First add: no is_primary specified, but this is the user's first-ever
	// membership, so it must be forced primary.
	out := postAddMember(t, router, poolA, map[string]any{"user_sub": sub})
	if out["is_primary"] != true {
		t.Fatalf("first-ever membership must be forced primary, got %v", out["is_primary"])
	}

	// Re-invoke as an idempotent "ensure member" call — still no is_primary
	// in the body. Must NOT demote the existing primary.
	out = postAddMember(t, router, poolA, map[string]any{"user_sub": sub})
	if out["is_primary"] != true {
		t.Fatalf("re-invoking add-member with no is_primary opinion demoted an existing primary: %v", out["is_primary"])
	}

	var row models.ClaudePoolMember
	if err := common.DB.Where("pool_id = ? AND user_sub = ?", poolA, sub).First(&row).Error; err != nil {
		t.Fatalf("member row missing: %v", err)
	}
	if !row.IsPrimary {
		t.Fatalf("DB row is_primary=false after re-invoke, want true (demoted)")
	}
}

// An explicit is_primary=false IS honored — this is deliberate caller intent,
// not an omission, and must still take effect.
func TestAdminClaudePoolAddMember_ExplicitFalseIsHonored(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	router := claudePoolMemberRouter()

	poolA, poolB := "cptest-addmember-b1", "cptest-addmember-b2"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'B1', 'distributed')`, poolA)
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'B2', 'distributed')`, poolB)
	cleanupClaudePool(t, db, poolA)
	cleanupClaudePool(t, db, poolB)

	sub := claudePoolTestUser(t, db, "addmem2")
	postAddMember(t, router, poolA, map[string]any{"user_sub": sub}) // primary via first-ever
	out := postAddMember(t, router, poolB, map[string]any{"user_sub": sub, "is_primary": true})
	if out["is_primary"] != true {
		t.Fatalf("explicit is_primary=true not honored: %v", out)
	}
	var a models.ClaudePoolMember
	common.DB.Where("pool_id = ? AND user_sub = ?", poolA, sub).First(&a)
	if a.IsPrimary {
		t.Fatalf("pool A should have been demoted when B became primary")
	}
}
