package handler

// Regression test for the orphaned-placement bug found in the 2026-09-06
// isolation audit: removing a pool membership deleted the membership row but
// left the user's ClaudeUserAssignment for that pool behind forever.
//
// "Forever" is the load-bearing word. pruneIdleAssignments — whose own comment
// calls it "the only code path that deletes a ClaudeUserAssignment" — evicts on
// IDLENESS and reads usage_events globally, with no notion of membership. A
// user still active in their NEW pool therefore looks active, so the orphan in
// the OLD pool is never reclaimed.
//
// Runs only when TEST_MYSQL_DSN is set, matching this package's convention.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func removeMemberRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.DELETE("/api/v1/admin/claude-pools/:id/members/:user_sub", AdminClaudePoolRemoveMember)
	return r
}

func countAssignments(t *testing.T, poolID, sub string) int64 {
	t.Helper()
	var n int64
	common.DB.Model(&models.ClaudeUserAssignment{}).
		Where("pool_id = ? AND user_sub = ?", poolID, sub).Count(&n)
	return n
}

func TestRemoveMemberDropsThatPoolsPlacement(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	router := removeMemberRouter()

	poolA := "cptest-orphan-a"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'A', 'distributed')`, poolA)
	cleanupClaudePool(t, db, poolA)

	sub := claudePoolTestUser(t, db, "orphan")

	// Member of BOTH pools, primary in A — mirrors the live shape: a user who
	// moved to a new pool while still carrying a placement in the old one.
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at) VALUES (?, ?, TRUE, NOW())`, poolA, sub)
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at) VALUES (?, ?, FALSE, NOW())`, models.DefaultClaudePoolID, sub)
	db.Exec(`INSERT INTO claude_user_assignments (pool_id, user_sub, account, load_7d, assigned_at, reason)
	         VALUES (?, ?, 'stale@acct', 0, NOW(), 'test')`, models.DefaultClaudePoolID, sub)
	db.Exec(`INSERT INTO claude_user_assignments (pool_id, user_sub, account, load_7d, assigned_at, reason)
	         VALUES (?, ?, 'live@acct', 0, NOW(), 'test')`, poolA, sub)

	if got := countAssignments(t, models.DefaultClaudePoolID, sub); got != 1 {
		t.Fatalf("setup: default placement count = %d, want 1", got)
	}

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/claude-pools/"+models.DefaultClaudePoolID+"/members/"+sub, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("remove member: status=%d body=%s", w.Code, w.Body.String())
	}

	if got := countAssignments(t, models.DefaultClaudePoolID, sub); got != 0 {
		t.Fatalf("placement in the LEFT pool survived removal (count=%d) — the orphan bug is back", got)
	}
	// The pool they are still in must be untouched: this cleanup is scoped to
	// the membership being removed, not a wipe of the user's placements.
	if got := countAssignments(t, poolA, sub); got != 1 {
		t.Fatalf("placement in the RETAINED pool was collateral damage (count=%d, want 1)", got)
	}
	var still models.ClaudePoolMember
	if err := common.DB.Where("pool_id = ? AND user_sub = ?", poolA, sub).First(&still).Error; err != nil {
		t.Fatalf("membership in the retained pool was removed too: %v", err)
	}
}
