package handler

// app_read must be able to read an app's OWN declared surfaces.
//
// `me://app-data?app=<app>&tool=<tool>` is how every app exposes its domain
// data — casebook, runs, report, workflows, proposals. The HTTP endpoint
// served it and surfaces rendered from it, but app_read had no case for the
// scheme at all: it fell through to "source not allowed" while
// GET /me/apps/<app>/data?tool=proposals returned 200 for the same caller.
//
// So the assistant could not read any app's own data. That bites hardest on
// Proposals, which is where planners stage suggestions for a human to judge —
// the assistant helping that human was the one party that could not see them.
//
// These tests pin the CONTRACT rather than any one app: the allowlist is
// shared with MeAppData, and an unknown tool must name it.

import (
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// readSource calls app_read and reports whether the call REACHED the tool.
//
// The tools query the database, and these are pure unit tests with no gorm
// handle, so a real tool call panics on a nil DB. That panic is not noise to
// be suppressed — it is the evidence: execution got past the source switch and
// the allowlist and into the tool body, which is exactly the routing under
// test. Asserting membership in readOnlyAppDataTools instead would be
// tautological, since that map is what the code consults.
func readSource(src string) (err error, reachedTool bool) {
	defer func() {
		if r := recover(); r != nil {
			err, reachedTool = nil, true
		}
	}()
	_, err = appReadSource(&gin.Context{}, "sub-1", src)
	return err, false
}

func TestAppReadRoutesAppDataToEveryAllowlistedTool(t *testing.T) {
	// Iterating the map rather than naming tools is the point: a tool added to
	// the surface allowlist but unreachable from app_read recreates the exact
	// split this fixes, and this fails the moment that happens.
	for tool := range readOnlyAppDataTools {
		err, reached := readSource("me://app-data?app=quant-research&tool=" + tool)
		if reached {
			continue // got into the tool — routing works
		}
		if err != nil && strings.Contains(err.Error(), "source not allowed") {
			t.Fatalf("tool %q: app_read rejected the source outright: %v", tool, err)
		}
		if err != nil && strings.Contains(err.Error(), "tool not readable") {
			t.Fatalf("tool %q is in readOnlyAppDataTools but app_read calls it unreadable", tool)
		}
	}
}

func TestAppReadNamesTheAllowlistForAnUnknownTool(t *testing.T) {
	_, err := appReadSource(&gin.Context{}, "sub-1",
		"me://app-data?app=quant-research&tool=definitely-not-a-tool")
	if err == nil {
		t.Fatal("an unknown tool must be refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, "tool not readable") {
		t.Fatalf("wrong refusal: %s", msg)
	}
	// Naming the allowlist is the whole reason MeAppData does it: an author
	// pointing at the wrong tool otherwise gets a refusal with no cause.
	//
	// Checked against the map rather than against literal tool names. The
	// deployed binary serves five tools where this checkout's map literal
	// declares three, so hard-coding "proposals" here asserts the build I
	// happened to curl rather than the contract.
	for tool := range readOnlyAppDataTools {
		if !strings.Contains(msg, tool) {
			t.Fatalf("refusal omits %q from the allowlist it names: %s", tool, msg)
		}
	}
}

func TestAppReadRejectsAnEmptyAppName(t *testing.T) {
	// slugRe is `^[A-Za-z0-9._/-]{1,128}$`, so it rejects only the EMPTY name —
	// dots and slashes are permitted and traversal is stopped downstream in
	// resolveAppDir, which rejects ".." and "/". Asserting a "../etc" refusal
	// here would be asserting a guard that lives somewhere else, and would go
	// green for the wrong reason.
	err, reached := readSource("me://app-data?app=&tool=runs")
	if reached || err == nil {
		t.Fatal("an empty app name was accepted")
	}
	if !strings.Contains(err.Error(), "invalid app") {
		t.Fatalf("wrong refusal for an empty app: %v", err)
	}
}
