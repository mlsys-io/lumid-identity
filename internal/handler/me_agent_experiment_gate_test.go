package handler

import "testing"

// 2026-09-27: a chat turn asked to RUN an undeclared arm instead invented one,
// added it to the owner's live experiment and queued paid runs — none of the
// experiment-writing tools needed approval. Pin the boundary: writes to an
// experiment's definition/lifecycle are gated; running a declared arm is not.
func TestExperimentWritesNeedApprovalButDispatchDoesNot(t *testing.T) {
	for _, name := range []string{"define_experiment", "add_experiment_arm", "experiment_control"} {
		if !destructiveTools[name] {
			t.Errorf("%s changes what an experiment is and must require approval", name)
		}
	}
	if destructiveTools["dispatch_experiment_arm"] {
		t.Error("dispatch_experiment_arm runs an already-declared arm; gating it would break the ordinary run path")
	}
}
