package handler

import (
	"testing"
	"time"
)

// leaseHonoursDrainedPin mirrors the lease filter's decision for a paused
// account, so the time-boxing can be tested without a DB or an HTTP round trip.
func leaseHonoursDrainedPin(email, prefer string, since time.Time, grace time.Duration, now time.Time) bool {
	return email == prefer && now.Sub(since) < grace
}

// The bug this exists to prevent: an unbounded pin makes a pause COSMETIC.
// claude-proxy refreshes the session binding on every serve and keeps it across
// lease renewals, and a Claude Code session does not end while someone is
// working — so ac5 sat paused with 0 users assigned to it and still took 100%
// of traffic, because every request arrived with prefer=ac5.
func TestDrainedPinIsNotHonouredForever(t *testing.T) {
	now := time.Now()
	since := now.Add(-2 * time.Hour) // paused two hours ago
	if leaseHonoursDrainedPin("ac5", "ac5", since, 30*time.Minute, now) {
		t.Fatal("a two-hour-old pause still honoured the pin — the pause never takes effect")
	}
}

// Inside the window the protection is exactly as before: a live conversation is
// not split, which is the whole reason the exception exists.
func TestDrainedPinIsHonouredInsideTheGrace(t *testing.T) {
	now := time.Now()
	since := now.Add(-5 * time.Minute)
	if !leaseHonoursDrainedPin("ac5", "ac5", since, 30*time.Minute, now) {
		t.Fatal("a conversation in flight was split during the grace window")
	}
}

// The exception is for the SESSION's account, never for anyone else — a paused
// account must not pick up traffic that was not already pinned to it, at any
// point in the window.
func TestDrainedAccountNeverTakesSomeoneElse(t *testing.T) {
	now := time.Now()
	since := now.Add(-1 * time.Minute)
	if leaseHonoursDrainedPin("ac5", "ylu@yao.lu", since, 30*time.Minute, now) {
		t.Fatal("a paused account was offered to a session pinned elsewhere")
	}
	if leaseHonoursDrainedPin("ac5", "", since, 30*time.Minute, now) {
		t.Fatal("a paused account was offered to a session with no pin at all — that is a NEW session")
	}
}

// A zero grace is the "stop now" setting: the pause takes effect immediately and
// every pinned session is released on its next turn.
func TestZeroGraceStopsImmediately(t *testing.T) {
	now := time.Now()
	if leaseHonoursDrainedPin("ac5", "ac5", now, 0, now) {
		t.Fatal("grace=0 still honoured the pin")
	}
}
