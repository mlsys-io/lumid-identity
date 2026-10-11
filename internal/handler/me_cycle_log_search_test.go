package handler

// Regression tests for the Defect: GET .../search returned 200 with
// {matches:[], count:0} for a cycle this pod cannot see at all (one that
// lives only on the home/office scheduler's PVC) — identical to the honest
// answer "your term is not in this transcript". cycleArtifactsReachable /
// unavailableReasonForCycle scope that check to the ONE (loop, ts) cycle
// being asked about, and searchCycleViaScheduler gives MeCycleLogSearch the
// same cycle_read bridge MeCycleLog already uses before it gives up.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCycleArtifactsReachable_ScopedToOneCycleNotTheWholeApp(t *testing.T) {
	appDir := t.TempDir()
	// A different loop/ts is visible on this pod...
	if err := os.MkdirAll(filepath.Join(appDir, "data", "cycles", "other-loop", "20260101T000000Z"), 0o755); err != nil {
		t.Fatal(err)
	}
	// ...but the one being asked about is not. The app-wide check
	// (runtimeArtifactsReachable) would call this "reachable" because
	// data/cycles exists; the cycle-scoped one must not.
	if cycleArtifactsReachable(appDir, "qa-sentinel", "20261010T000000Z") {
		t.Fatal("a sibling cycle's presence made an absent cycle report reachable")
	}
	if runtimeArtifactsReachable(appDir); !runtimeArtifactsReachable(appDir) {
		t.Fatal("sanity: the app-wide check should see the sibling cycle")
	}

	// Once THIS cycle's own dir exists, it is reachable.
	if err := os.MkdirAll(filepath.Join(appDir, "data", "cycles", "qa-sentinel", "20261010T000000Z"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !cycleArtifactsReachable(appDir, "qa-sentinel", "20261010T000000Z") {
		t.Fatal("a cycle dir that now exists reported itself unreachable")
	}

	if cycleArtifactsReachable("", "l", "t") || cycleArtifactsReachable(appDir, "", "t") || cycleArtifactsReachable(appDir, "l", "") {
		t.Fatal("empty app/loop/ts must never report reachable")
	}
}

func TestUnavailableReasonForCycle_SilentOnlyForThatCycle(t *testing.T) {
	appDir := t.TempDir()
	os.MkdirAll(filepath.Join(appDir, "data", "cycles", "other-loop", "20260101T000000Z"), 0o755)

	// The sibling cycle existing must not silence the reason for THIS one —
	// this is exactly the bug: "the app has some cycles visible" used to be
	// read as "so this run's absence must mean nothing happened".
	why := unavailableReasonForCycle(appDir, "qa-sentinel", "20261010T000000Z", "the cycle transcript this searches")
	if why == "" {
		t.Fatal("a cycle this pod cannot see was called genuinely empty because a sibling cycle exists")
	}
	if !strings.Contains(why, "the cycle transcript this searches") {
		t.Errorf("reason does not name the artifact: %q", why)
	}

	os.MkdirAll(filepath.Join(appDir, "data", "cycles", "qa-sentinel", "20261010T000000Z"), 0o755)
	if why := unavailableReasonForCycle(appDir, "qa-sentinel", "20261010T000000Z", "the cycle transcript this searches"); why != "" {
		t.Fatalf("a cycle dir that exists must be silent, got %q", why)
	}
}

// searchCycleFiles / scanCycleFilesJSONL / parseStepErrorsForSearch — the
// in-memory counterparts of searchCycleLog's disk sources, exercised on bytes
// shaped exactly like a cycle_read response (patternACycle from
// me_cycle_read_intent_test.go: .llm_conversation.jsonl is absent there, so
// add one here for the "llm" source).
func TestSearchCycleFiles_LLMAndErrorSourcesOverSchedulerBytes(t *testing.T) {
	files := cycleFiles{}
	for n, c := range patternACycle {
		files[n] = []byte(c)
	}
	files[".llm_conversation.jsonl"] = []byte(
		`{"ts":"2026-10-10T00:00:00Z","event":"turn","prompt":"what is the answer","response":"42"}` + "\n")

	m, capped := searchCycleFiles(files, "answer", "")
	if capped {
		t.Fatal("5 bytes of input should never cap")
	}
	if len(m) != 1 || m[0].Field != "prompt" || m[0].Event != "turn" {
		t.Fatalf("llm match = %v", m)
	}

	m, _ = searchCycleFiles(files, "boom", "error")
	if len(m) != 1 || m[0].Event != "error" || !strings.Contains(m[0].Snippet, "boom") {
		t.Fatalf("error match = %v", m)
	}

	// type=llm must not see the error source and vice versa.
	m, _ = searchCycleFiles(files, "boom", "llm")
	if len(m) != 0 {
		t.Fatalf("llm-only search matched the error source: %v", m)
	}
}

// ── via the scheduler (DB-backed) ────────────────────────────────────────────

func TestSearchCycleViaScheduler_FindsMatchesOverTheBridge(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "user-search-ok", "search-app")
	got := fakePicker(t, db, "user-search-ok", cycleReadAction, "done", cycleReadEnvelope(t, map[string]any{
		"ok": true, "exists": true, "running": false, "files": patternACycle,
	}))

	m, capped, err, tried := searchCycleViaScheduler(context.Background(), "user-search-ok", "search-app", "l", "20260928T010203Z", "boom", "")
	if p := <-got; p["app"] != "search-app" || p["transcript"] != true {
		t.Fatalf("picker payload = %v (want transcript requested)", p)
	}
	if !tried || err != nil {
		t.Fatalf("tried=%v err=%v, want tried with no error", tried, err)
	}
	if capped {
		t.Fatal("unexpected cap")
	}
	if len(m) != 1 || m[0].Event != "error" {
		t.Fatalf("matches = %v", m)
	}
}

// A cycle the scheduler confirms does not exist must come back as "nothing to
// report" (tried=true, err=nil), not as an error — MeCycleLogSearch's
// errCycleNotOnScheduler branch turns this into a plain empty result, exactly
// like a cycle that is genuinely empty.
func TestSearchCycleViaScheduler_CycleGenuinelyAbsent(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "u-miss", "app-miss")
	fakePicker(t, db, "u-miss", cycleReadAction, "done", cycleReadEnvelope(t, map[string]any{
		"ok": true, "exists": false, "files": map[string]any{},
	}))

	m, _, err, tried := searchCycleViaScheduler(context.Background(), "u-miss", "app-miss", "l", "20200101T000000Z", "x", "")
	if !tried {
		t.Fatal("want tried=true: the app is the caller's own install")
	}
	if err != errCycleNotOnScheduler {
		t.Fatalf("err = %v, want errCycleNotOnScheduler", err)
	}
	if len(m) != 0 {
		t.Fatalf("matches = %v, want none", m)
	}
}

// This is THE fix: the old code reported 200/0-matches for a run that lived
// only on the scheduler. Now, when the scheduler can't even be asked
// (operator-shared app, not an intent-backed install), searchCycleViaScheduler
// must say "not tried" so the caller keeps the honest "unavailable" message
// instead of silently returning zero matches.
func TestSearchCycleViaScheduler_NotTriedForANonOwnedApp(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	// No installFor: this user has not installed "unowned-app" anywhere, so
	// ownerWriteTarget reports neither direct nor viaIntent.
	_, _, _, tried := searchCycleViaScheduler(context.Background(), "user-search-stranger", "unowned-app", "l", "20260928T010203Z", "x", "")
	if tried {
		t.Fatal("tried a scheduler read for an app the caller never installed")
	}
	if n := countIntents(db, cycleReadAction); n != 0 {
		t.Fatalf("%d cycle_read intents queued for a non-owner", n)
	}
}

// An older scheduler without cycle_read support answers "unknown action" —
// that must surface as a real error (so MeCycleLogSearch's "could not be read
// from the scheduler" branch fires), never as a silent empty result.
func TestSearchCycleViaScheduler_SchedulerFailed(t *testing.T) {
	db := setupStaleReadsDB(t)
	resetCycleReadCache()
	installFor(t, db, "u-fail2", "app-fail2")
	fakePicker(t, db, "u-fail2", cycleReadAction, "failed", `{"ok":false,"error":"unknown action: cycle_read"}`)

	_, _, err, tried := searchCycleViaScheduler(context.Background(), "u-fail2", "app-fail2", "l", "20260928T010203Z", "x", "")
	if !tried {
		t.Fatal("want tried=true")
	}
	if err == nil || !strings.Contains(err.Error(), "unknown action: cycle_read") {
		t.Fatalf("err = %v, want the scheduler's own error", err)
	}
}

// Regression guard: MeCycleLogSearch must keep calling the scheduler bridge
// before giving up, scoped per-cycle rather than app-wide.
func TestMeCycleLogSearch_RoutesThroughTheSchedulerPerCycle(t *testing.T) {
	src := uncommentedGo(fnBlock(t, "me_cycle_log_search.go", "MeCycleLogSearch"))
	for _, marker := range []string{"unavailableReasonForCycle(", "searchCycleViaScheduler("} {
		if !strings.Contains(src, marker) {
			t.Errorf("MeCycleLogSearch no longer calls %s", marker)
		}
	}
	if strings.Contains(src, "unavailableReason(appDir") {
		t.Error("MeCycleLogSearch reverted to the app-wide (non-cycle-scoped) unavailable check")
	}
}

// parseStepErrorsForSearch must parse both shapes readStepErrorsForSearch
// reads off disk, since it is now also used on bytes from the scheduler.
func TestParseStepErrorsForSearch_BothShapes(t *testing.T) {
	arr := parseStepErrorsForSearch([]byte(`[{"step":"s2","error":"boom"}]`))
	if len(arr) != 1 || arr[0].Error != "boom" {
		t.Fatalf("array shape = %v", arr)
	}
	wrapped := parseStepErrorsForSearch([]byte(`{"errors":[{"step":"s2","error":"boom"}]}`))
	if len(wrapped) != 1 || wrapped[0].Error != "boom" {
		t.Fatalf("wrapped shape = %v", wrapped)
	}
	if arr := parseStepErrorsForSearch(nil); arr != nil {
		t.Fatalf("nil input = %v, want nil", arr)
	}
}
