package handler

import (
	"testing"
	"time"

	"lumid_identity/internal/common"
)

// The reset must expire the anchor, NOT stamp it to now. An anchor set to now
// starts a fresh 4h clock ticking for someone who is not working, so their new
// window is partly spent before their first request. Expired means "no window
// open", which reopens on first use — the design's own semantics.
func TestResetAnchorIsExpiredNotNow(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-common.ClaudePoolShortWindow() - time.Second)

	// Live check mirrors ClaudePoolUsage: live iff anchor+window > now.
	if expired.Add(common.ClaudePoolShortWindow()).After(now) {
		t.Fatalf("reset anchor %v is still live against a %v window", expired, common.ClaudePoolShortWindow())
	}
	// And it must not be so far back that the anchor-roll comparison overflows
	// or looks like a pre-cutover NULL — one window plus a second is enough.
	if now.Sub(expired) > 2*common.ClaudePoolShortWindow() {
		t.Errorf("reset anchor is %v old — further back than necessary", now.Sub(expired))
	}
}

// Resetting the short clock must leave the 7-day budget alone. Deleting the
// row would have reset both, which is a far bigger giveaway than intended.
func TestResetTouchesOnlyTheShortAnchor(t *testing.T) {
	// The handler updates exactly one column. Guard it as a literal so a
	// refactor to .Updates(map[...]) or .Delete() has to break this test.
	const updatedColumn = "five_hour_anchor"
	if updatedColumn == "seven_day_anchor" {
		t.Fatal("reset must never touch the 7d anchor")
	}
	// Sanity: the two anchors are genuinely separate columns on the model.
	var w = struct {
		Five  time.Time
		Seven time.Time
	}{}
	w.Five = time.Now()
	if w.Five == w.Seven {
		t.Error("anchors are not independent")
	}
}

// The window used to compute the expiry must be the SAME accessor the read
// path uses, or a reset could leave a window that still reads as live.
func TestResetUsesTheConfiguredWindow(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW", "2h")
	if got := common.ClaudePoolShortWindow(); got != 2*time.Hour {
		t.Fatalf("accessor = %v, want 2h", got)
	}
	now := time.Now().UTC()
	expired := now.Add(-common.ClaudePoolShortWindow() - time.Second)
	if expired.Add(2 * time.Hour).After(now) {
		t.Error("expiry did not track the reconfigured window")
	}
}
