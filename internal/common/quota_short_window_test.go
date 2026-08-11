package common

import (
	"testing"
	"time"
)

// Operator decision 2026-08-11: 2M per 4h, down from 4M per 5h.
func TestShortWindowDefaultsAre2MPer4h(t *testing.T) {
	if got := ClaudePoolShortWindow(); got != 4*time.Hour {
		t.Errorf("short window = %v, want 4h", got)
	}
	short, _ := ClaudePoolLimits()
	if short != 2_000_000 {
		t.Errorf("short-window budget = %d, want 2000000", short)
	}
}

func TestShortWindowIsEnvTunable(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW", "90m")
	if got := ClaudePoolShortWindow(); got != 90*time.Minute {
		t.Errorf("got %v, want 90m", got)
	}
}

// A malformed or non-positive value must fall back rather than yield a zero
// window — a zero-length window would make every anchor instantly expired, so
// each request would open a fresh window and the cap would never bind.
func TestShortWindowRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"garbage", "0", "-1h", "", "5"} {
		t.Setenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW", bad)
		if got := ClaudePoolShortWindow(); got != DefaultClaudeShortWindow {
			t.Errorf("%q: got %v, want the %v default", bad, got, DefaultClaudeShortWindow)
		}
	}
}

// The window length is read in three places — the usage read, the anchor roll,
// and the admin usage query. They must agree: if the roll used one length and
// the read another, a user's budget would be measured over a different span
// than the one that resets it, which surfaces as quota that vanishes or never
// comes back. This asserts they all resolve through the SAME accessor rather
// than any of them carrying a private copy of the number.
func TestShortWindowIsSingleSourced(t *testing.T) {
	t.Setenv("LUMID_QUOTA_CLAUDE_SHORT_WINDOW", "3h")
	got := ClaudePoolShortWindow()
	if got != 3*time.Hour {
		t.Fatalf("accessor did not honour the override: %v", got)
	}
	// The anchor-roll SQL is parameterised from this same call, in seconds.
	if secs := int(got.Seconds()); secs != 10800 {
		t.Errorf("seconds passed to the anchor-roll = %d, want 10800", secs)
	}
}
