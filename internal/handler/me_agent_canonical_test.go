package handler

import (
	"reflect"
	"testing"
)

func TestResolveCanonicalTool(t *testing.T) {
	cases := []struct {
		name     string
		args     map[string]any
		wantTool string
		wantArgs map[string]any
	}{
		{"workflow_run", map[string]any{"agent": "qr", "workflow": "backtest", "args": map[string]any{"symbol": "X"}},
			"run_loop_now", map[string]any{"app": "qr", "loop": "backtest", "args": map[string]any{"symbol": "X"}}},
		{"workflow_run", map[string]any{"agent": "qr", "mode": "queue", "study": "s", "experiment": "warm", "samples": 3.0},
			"dispatch_experiment_arm", map[string]any{"app": "qr", "experiment": "s", "arm": "warm", "samples": 3.0}},
		{"workflow_get", map[string]any{"agent": "qr", "workflow": "backtest"},
			"workflow_detail", map[string]any{"slug": "qr:backtest"}},
		{"workflow_get", map[string]any{"view": "health"}, "loops_health", map[string]any{}},
		{"workflow_get", map[string]any{"kind": "scheduled"}, "list_workflows", map[string]any{"kind": "scheduled"}},
		{"workflow_define", map[string]any{"agent": "qr", "workflow": "b", "enabled": false},
			"patch_loop", map[string]any{"app": "qr", "loop": "b", "enabled": false}},
		{"workflow_cancel", map[string]any{"agent": "qr", "workflow": "b"},
			"stop_loop", map[string]any{"app": "qr", "loop": "b"}},
		{"run_get", map[string]any{"state": "failed"}, "list_runs", map[string]any{"state": "failed"}},
		{"run_get", map[string]any{"id": "scheduled:qr:b:20260930T010203Z"},
			"run_detail", map[string]any{"run_id": "scheduled:qr:b:20260930T010203Z"}},
		{"run_get", map[string]any{"id": "0b6c1f7e-1111-4222-8333-944445555666"},
			"run_result", map[string]any{"job_id": "0b6c1f7e-1111-4222-8333-944445555666"}},
		{"run_feedback", map[string]any{"id": "scheduled:qr:b:20260930T010203Z", "verdict": "promote"},
			"run_promote", map[string]any{"app": "qr", "loop": "b", "ts": "20260930T010203Z"}},
		{"list_apps", map[string]any{"x": 1}, "list_apps", map[string]any{"x": 1}}, // other names pass through
	}
	for _, tc := range cases {
		got, args, err := resolveCanonicalTool(tc.name, tc.args)
		if err != nil || got != tc.wantTool || !reflect.DeepEqual(args, tc.wantArgs) {
			t.Errorf("%s %v -> %s %v %v; want %s %v", tc.name, tc.args, got, args, err, tc.wantTool, tc.wantArgs)
		}
	}
}

func TestResolveCanonicalToolRejectsMalformedCalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"workflow_run", map[string]any{"agent": "qr"}},
		{"workflow_run", map[string]any{"agent": "qr", "mode": "queue", "study": "s"}},
		{"run_feedback", map[string]any{"id": "scheduled:qr:b:ts", "verdict": "succeeded"}},
		{"run_feedback", map[string]any{"id": "not-a-run", "verdict": "discard"}},
	} {
		if _, _, err := resolveCanonicalTool(tc.name, tc.args); err == nil {
			t.Errorf("%s %v resolved; want an error", tc.name, tc.args)
		}
	}
}

// The property the design rests on: a canonical call is gated exactly like the
// tool it resolves to, because gating reads the RESOLVED name.
func TestCanonicalToolsInheritGating(t *testing.T) {
	name, _, _ := resolveCanonicalTool("run_feedback", map[string]any{"id": "scheduled:a:b:c", "verdict": "discard"})
	if !destructiveTools[name] {
		t.Errorf("run_feedback resolves to %s, which is not approval-gated", name)
	}
	name, _, _ = resolveCanonicalTool("workflow_run", map[string]any{"agent": "a", "workflow": "b"})
	if !runDispatchTools[name] {
		t.Errorf("workflow_run resolves to %s, which is not run-gated", name)
	}
	name, _, _ = resolveCanonicalTool("workflow_run", map[string]any{"agent": "a", "mode": "queue", "study": "s", "experiment": "e"})
	if !runDispatchTools[name] {
		t.Errorf("workflow_run(queue) resolves to %s, which is not run-gated", name)
	}
	for _, n := range []string{"workflow_define", "workflow_cancel"} {
		resolved, _, _ := resolveCanonicalTool(n, map[string]any{"agent": "a", "workflow": "b"})
		if len(toolDataScopes[resolved]) == 0 {
			t.Errorf("%s resolves to %s, which refreshes no UI data", n, resolved)
		}
	}
}

func TestCatalogShowsCanonicalNotSuperseded(t *testing.T) {
	for _, role := range []string{"user", "admin", "super_admin"} {
		names := toolNames(buildToolDefsForRole(role))
		for old, canonical := range supersededChatTools {
			if names[old] {
				t.Errorf("role %s: superseded %q is advertised", role, old)
			}
			if !names[canonical] {
				t.Errorf("role %s: canonical %q is not advertised", role, canonical)
			}
		}
	}
	// Hidden is not removed: every superseded tool still has its implementation.
	builtin := toolNames(append(buildToolDefs(), appOpsToolDefs()...))
	for old := range supersededChatTools {
		if !builtin[old] {
			t.Errorf("superseded %q lost its implementation", old)
		}
	}
}
