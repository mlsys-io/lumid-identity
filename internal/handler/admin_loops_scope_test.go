package handler

import (
	"testing"

	"github.com/gin-gonic/gin"
)

// The /me/loops/health leak: any authenticated caller was served every
// tenant's loops. These cover the filter that fixes it, including the
// fail-closed path — the case where "return everything" is the bug.
func TestScopeLoopRows(t *testing.T) {
	rows := []loopRow{
		{App: "lqt-mailbox", Loop: "harvest_outbox", TenantSub: "user-a"},
		{App: "lqt-mailbox", Loop: "harvest_outbox", TenantSub: "user-b"},
		{App: "personal-agent", Loop: "watch", TenantSub: ""}, // operator-shared
		{App: "qa-sentinel", Loop: "pulse", TenantSub: "user-a"},
	}

	t.Run("no scope set — admin keeps the fleet view", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		got := scopeLoopRows(c, rows)
		if len(got) != 4 {
			t.Fatalf("admin must see all 4 rows, got %d", len(got))
		}
	})

	t.Run("scoped caller sees only their own", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(loopsTenantScopeKey, "user-a")
		got := scopeLoopRows(c, rows)
		if len(got) != 2 {
			t.Fatalf("want 2 rows for user-a, got %d", len(got))
		}
		for _, r := range got {
			if r.TenantSub != "user-a" {
				t.Fatalf("leaked a row belonging to %q", r.TenantSub)
			}
		}
	})

	t.Run("operator-shared loops are NOT visible to a tenant", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(loopsTenantScopeKey, "user-a")
		for _, r := range scopeLoopRows(c, rows) {
			if r.TenantSub == "" {
				t.Fatalf("operator-shared loop %q/%q exposed to a tenant", r.App, r.Loop)
			}
		}
	})

	t.Run("empty scope value fails CLOSED, not open", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(loopsTenantScopeKey, "")
		got := scopeLoopRows(c, rows)
		if len(got) != 0 {
			t.Fatalf("a broken scope must return nothing, got %d rows", len(got))
		}
	})

	t.Run("unknown tenant sees nothing", func(t *testing.T) {
		c, _ := gin.CreateTestContext(nil)
		c.Set(loopsTenantScopeKey, "nobody")
		if got := scopeLoopRows(c, rows); len(got) != 0 {
			t.Fatalf("want 0 rows, got %d", len(got))
		}
	})
}

func TestLoopRowApps(t *testing.T) {
	got := loopRowApps([]loopRow{
		{App: "a"}, {App: "b"}, {App: "a"},
	})
	if len(got) != 2 {
		t.Fatalf("want 2 distinct apps, got %d", len(got))
	}
}
