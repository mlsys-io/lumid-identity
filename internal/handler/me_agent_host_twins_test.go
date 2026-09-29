package handler

import "testing"

func toolNames(defs []map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, d := range defs {
		if n, _ := d["name"].(string); n != "" {
			out[n] = true
		}
	}
	return out
}

// A non-operator must see the tenant-scoped tool, never its operator-host twin,
// and every hidden twin must still have its tenant replacement advertised —
// hiding a tool with no replacement would silently remove a capability.
func TestHostScopeTwinsHiddenForNonOperators(t *testing.T) {
	for _, role := range []string{"user", "admin"} {
		names := toolNames(buildToolDefsForRole(role))
		for twin, tenant := range hostScopeTwins {
			if names[twin] {
				t.Errorf("role %s: host-scope %q is advertised", role, twin)
			}
			if !names[tenant] {
				t.Errorf("role %s: %q hidden but its tenant replacement %q is not advertised", role, twin, tenant)
			}
		}
	}
}

func TestHostScopeTwinsKeptForSuperAdmin(t *testing.T) {
	names := toolNames(buildToolDefsForRole("super_admin"))
	for twin := range hostScopeTwins {
		if !names[twin] {
			t.Errorf("super_admin lost operator tool %q", twin)
		}
	}
}

// Hidden is not removed: an in-flight prompt that names a twin still dispatches.
// A twin is either a built-in tool (it stays in buildToolDefs, whose dispatch
// cases are unchanged) or a LumidOS-bridge tool.
func TestHostScopeTwinsStillDispatch(t *testing.T) {
	builtin := toolNames(buildToolDefs())
	for twin := range hostScopeTwins {
		if !builtin[twin] && !lumidosToolNames[twin] {
			t.Errorf("%q is neither a built-in tool nor a LumidOS bridge tool", twin)
		}
	}
}
