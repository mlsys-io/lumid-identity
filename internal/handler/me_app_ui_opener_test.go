package handler

// ui.opener lets an app own the chat's first turn. The default opener is
// operator-shaped ("N workflows, last run 1h ago" + "run a workflow"), which is
// right for an app you OPERATE and wrong for one you USE — someone opening
// mbb-consultant to practise a case was greeted with workflow telemetry.
//
// Opt-in by design: an app that declares none keeps the live-state default.

import "testing"

func TestParseAppUI_Opener(t *testing.T) {
	ui := parseAppUI([]byte(`
ui:
  sidebar: {label: MBB Consultant}
  opener:
    line: "Pick a mode above, or tell me what you want to practise."
    chips:
      - {label: "interview me", prompt: "Interview me on an easy case."}
      - {label: "ask a question", prompt: "I have my own consulting question."}
`))
	if ui == nil || ui.Opener == nil {
		t.Fatal("opener not parsed")
	}
	if ui.Opener.Line == "" {
		t.Fatal("opener line missing")
	}
	if len(ui.Opener.Chips) != 2 || ui.Opener.Chips[0].Label != "interview me" {
		t.Fatalf("chips = %+v", ui.Opener.Chips)
	}
}

func TestParseAppUI_NoOpenerKeepsDefault(t *testing.T) {
	// The ops apps the default was written for must be untouched.
	ui := parseAppUI([]byte("ui:\n  sidebar: {label: Venue Link Matcher}\n"))
	if ui == nil {
		t.Fatal("ui not parsed")
	}
	if ui.Opener != nil {
		t.Fatal("an app declaring no opener must fall through to the live-state default")
	}
}
