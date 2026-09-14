package handler

// Pause, resume, reschedule, goal-save and the chat's patch_loop all wrote
// .user-overrides.yaml directly, and identity cannot reach that file: the pod
// mounts exactly one volume, the signing keys. MeLoopPatch stat()'d
// <tenant>/.xp/apps/<app> and then the operator-shared path and 404'd when
// neither existed — which is always — so every one of those controls failed for
// every user, with a red toast naming a path nobody could create.
//
// toolPatchLoop was worse: on the branch where the operator-shared directory
// did exist it reported "Override saved." having written to a pod-local path
// that nothing reads and that dies with the pod.
//
// These are source-level assertions on purpose. The handlers need a live DB to
// exercise, and what actually regressed here is a CHOICE — "write it yourself"
// vs "queue it for the process that can" — which a reader can reintroduce in
// one line.

import (
	"os"
	"strings"
	"testing"
)

func loopPatchSrc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func TestLoopControlsGoThroughAnIntent(t *testing.T) {
	for _, c := range []struct{ file, fn, marker string }{
		{"me_loops.go", "MeLoopPatch", `writeIntent(c, "patch_loop"`},
		{"me_agent_tools.go", "toolPatchLoop", `writeIntentDirect(userID, "patch_loop"`},
		// MeLoopStop never 404'd — resolveAppDir hands it the materialised
		// bundle cache — so it wrote the stop signal, the journal line and the
		// interrupted cycle.json into a pod-local copy of the PUBLISHED tree
		// and returned 200 "stop requested". A control that reports success
		// without acting is worse than one that errors.
		{"me_loops.go", "MeLoopStop", `writeIntent(c, "stop_loop"`},
	} {
		src := loopPatchSrc(t, c.file)
		i := strings.Index(src, "func "+c.fn+"(")
		if i < 0 {
			t.Fatalf("%s not found in %s", c.fn, c.file)
		}
		block := src[i:]
		if j := strings.Index(block[1:], "\nfunc "); j > 0 {
			block = block[:j]
		}
		if !strings.Contains(block, c.marker) {
			t.Errorf("%s does not queue a patch_loop intent; if it has gone back to "+
				"writing the file itself it will fail for every user, because identity "+
				"mounts no tenant volume", c.fn)
		}
		for _, forbidden := range []string{"tenantAppsDir(", "writeSimpleOverrides(",
			"os.MkdirAll(", "os.WriteFile(", "resolveAppDir("} {
			if strings.Contains(block, forbidden) {
				t.Errorf("%s reaches for %s — that disk does not exist in this pod", c.fn, forbidden)
			}
		}
	}
}

// The format now has ONE writer, in the scheduler. Two writers is how the
// emitter drifted from its reader.
func TestIdentityNoLongerWritesTheOverridesFormat(t *testing.T) {
	for _, f := range []string{"me_loops.go", "me_agent_tools.go", "me_workflows.go"} {
		src := loopPatchSrc(t, f)
		for _, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if strings.Contains(line, "writeSimpleOverrides(") {
				t.Errorf("%s still writes the overrides format: %s", f, strings.TrimSpace(line))
			}
		}
	}
}

// A queued write must not claim it landed. The old note said "Override saved."
// unconditionally, on every path it could reach.
func TestPatchLoopReportsTheQueueNotTheOutcome(t *testing.T) {
	src := loopPatchSrc(t, "me_agent_tools.go")
	i := strings.Index(src, "func toolPatchLoop(")
	block := src[i : i+3000]
	if strings.Contains(block, "Override saved") {
		t.Error("toolPatchLoop still claims the override was saved; it is queued, not applied")
	}
	if !strings.Contains(block, `"state":     "queued"`) && !strings.Contains(block, `"state": "queued"`) {
		t.Error("toolPatchLoop does not report the queued state")
	}
}

// 202, not 200 — the same contract install and patch_experiment use.
func TestLoopWritesReturn202(t *testing.T) {
	src := loopPatchSrc(t, "me_loops.go")
	for _, fn := range []string{"MeLoopPatch", "MeLoopStop"} {
		i := strings.Index(src, "func "+fn+"(")
		if i < 0 {
			t.Fatalf("%s not found", fn)
		}
		block := src[i:]
		if j := strings.Index(block[1:], "\nfunc "); j > 0 {
			block = block[:j]
		}
		if !strings.Contains(block, "http.StatusAccepted") {
			t.Errorf("%s does not return 202; identity queues, the scheduler applies", fn)
		}
		if strings.Contains(block, "http.StatusOK") {
			t.Errorf("%s still returns 200 somewhere — that would claim the write landed", fn)
		}
	}
}
