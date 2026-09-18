package handler

// Plan mode: the allowlist that guards an argv flag, and the instrument that
// makes a CLI vocabulary change visible instead of silent.

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// permission_mode decides a `claude` command-line flag in the sandbox. Anything
// we do not recognise must collapse to "" (today's behaviour) rather than being
// forwarded for the sandbox to interpret — the bridge secret is shared across
// identity pods, so neither side may assume the other validated.
func TestPlanOnlyForwardsNothingButPlan(t *testing.T) {
	for _, in := range []string{"plan"} {
		if got := planOnly(in); got != "plan" {
			t.Fatalf("planOnly(%q) = %q, want %q", in, got, "plan")
		}
	}
	// Case variants and near-misses matter more than nonsense here: "Plan" is
	// what a hand-written client sends, and it must NOT quietly become a
	// read-only turn's worth of trust.
	for _, in := range []string{"", "Plan", "PLAN", " plan", "plan ", "planning",
		"bypassPermissions", "acceptEdits", "dontAsk", "../plan", "plan\x00"} {
		if got := planOnly(in); got != "" {
			t.Fatalf("planOnly(%q) = %q, want \"\" — unrecognised input must not reach argv", in, got)
		}
	}
}

// An unknown event must be logged once per turn, not once per event: a chatty
// new type should cost one line, or the next CLI bump drowns the log and the
// instrument gets turned off.
func TestUnknownEventsAreLoggedOncePerKind(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	tr := newClaudeTranslator("u1", func(map[string]any) bool { return true })
	for i := 0; i < 5; i++ {
		tr.handle(map[string]any{"type": "control_request"})
		tr.handle(map[string]any{"type": "hook_callback"})
	}

	out := buf.String()
	if n := strings.Count(out, `"control_request"`); n != 1 {
		t.Fatalf("control_request logged %d times, want exactly 1:\n%s", n, out)
	}
	if n := strings.Count(out, `"hook_callback"`); n != 1 {
		t.Fatalf("hook_callback logged %d times, want exactly 1:\n%s", n, out)
	}
}

// The events the translator deliberately drops are not "unknown" and must stay
// silent, or every turn logs noise and the real signal stops being read.
func TestDeliberatelyDroppedEventsAreNotReportedAsUnknown(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	tr := newClaudeTranslator("u1", func(map[string]any) bool { return true })
	for _, inner := range []string{"message_start", "message_delta", "message_stop"} {
		tr.handle(map[string]any{
			"type":  "stream_event",
			"event": map[string]any{"type": inner},
		})
	}
	if out := buf.String(); strings.Contains(out, "unhandled") {
		t.Fatalf("message_* are dropped on purpose, not unknown:\n%s", out)
	}
}

// A known event must never be misreported as unknown — the guard against
// wiring the default branch above a case rather than below it.
func TestKnownEventsDoNotLogUnknown(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	tr := newClaudeTranslator("u1", func(map[string]any) bool { return true })
	tr.handle(map[string]any{"type": "system", "subtype": "status", "status": "ok"})
	tr.handle(map[string]any{
		"type":  "stream_event",
		"event": map[string]any{"type": "content_block_stop", "index": float64(0)},
	})
	if out := buf.String(); strings.Contains(out, "unhandled") {
		t.Fatalf("known events logged as unhandled:\n%s", out)
	}
}
