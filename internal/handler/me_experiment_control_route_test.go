package handler

// The UI's control menu calls this endpoint. It shipped in the bundle one
// release before the route did — the menu was live against a 404 — because the
// handler and its registration were written after the commit that got tagged.
// A live probe caught it; this test is so a build catches it next time.

import (
	"strings"
	"testing"
)

func TestExperimentControlRouteIsRegistered(t *testing.T) {
	router := loopPatchSrc(t, "router.go")
	if !strings.Contains(router, `me.POST("/apps/:app/experiments/:id/control", MeAppExperimentControl)`) {
		t.Fatal("the control route is not registered; the card's overflow menu 404s")
	}
	// Registered AFTER the :id GET, so gin's tree has the wildcard before the
	// literal segment — a conflict here is a startup panic, not a 404.
	if strings.Index(router, `/apps/:app/experiments/:id/control`) < strings.Index(router, `me.GET("/apps/:app/experiments/:id"`) {
		t.Error("control is registered before the :id GET; keep the literal-segment route after it")
	}
	if !strings.Contains(loopPatchSrc(t, "me_experiment_write.go"), "func MeAppExperimentControl(") {
		t.Fatal("MeAppExperimentControl is missing")
	}
}

// The three refusals the chat tool makes, made here too — a surface that can
// queue a checkpoint without a reason is a surface that produces unreadable
// fences.
func TestControlEndpointRefusesTheSameThingsTheToolDoes(t *testing.T) {
	src := loopPatchSrc(t, "me_experiment_write.go")
	i := strings.Index(src, "func MeAppExperimentControl(")
	block := src[i:]
	for _, guard := range []string{
		`body.Op == "checkpoint" && strings.TrimSpace(body.Reason) == ""`,
		`body.Op == "fork" && !slugRe.MatchString(body.NewID)`,
		`body.Op == "remove_arm" && strings.TrimSpace(body.Arm) == ""`,
	} {
		if !strings.Contains(block, guard) {
			t.Errorf("missing guard: %s", guard)
		}
	}
	if !strings.Contains(block, `writeIntent(c, "experiment_control"`) {
		t.Error("the endpoint does not queue an intent; identity cannot write that spec")
	}
}
