// Scope vocabulary helpers — keep service-level shortcuts compatible
// with downstream services' finer-grained vocab.
//
// Lumid's PAT mint UI builds scopes from a (service × level) matrix:
// e.g. picking flowmesh / write emits `flowmesh:write`. Downstream
// services have their own vocabularies that may be more granular. For
// FlowMesh's lumid-flowmesh-plugin v0.2.0+, the PermissionChecker only
// recognizes the admin aliases (`*`, `flowmesh:*`, `flowmesh:admin`)
// plus per-resource scopes:
//
//   flowmesh:workflows:{read,write}
//   flowmesh:tasks:read
//   flowmesh:results:{read,write}
//   flowmesh:nodes:{read,write}
//   flowmesh:workers:{read,write}
//   flowmesh:system:read
//
// `flowmesh:read` / `flowmesh:write` (which the UI mints today) match
// none of those and would fail closed at the plugin. So we expand
// service-level shortcuts here, on introspect — existing PATs benefit
// without re-mint.
package common

const (
	flowmeshReadShortcut  = "flowmesh:read"
	flowmeshWriteShortcut = "flowmesh:write"
)

// All flowmesh resources that have a *:read scope under the v0.2.0 vocab.
var flowmeshReadResources = []string{
	"workflows", "tasks", "results", "nodes", "workers", "system",
}

// Resources that also have a *:write scope. ("tasks" + "system" are
// read-only at the plugin; "results" gets the worker-side write.)
var flowmeshWriteResources = []string{
	"workflows", "results", "nodes", "workers",
}

// ExpandFlowmeshScopes returns the input list with service-level
// flowmesh shortcuts replaced by the fine-grained scopes the v0.2.0
// plugin expects. Non-flowmesh and already-fine-grained scopes pass
// through unchanged. `flowmesh:admin` stays as-is (it's the plugin's
// admin alias). Duplicates are collapsed.
func ExpandFlowmeshScopes(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in)*2)
	out := make([]string, 0, len(in))
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range in {
		switch s {
		case flowmeshReadShortcut:
			for _, r := range flowmeshReadResources {
				add("flowmesh:" + r + ":read")
			}
		case flowmeshWriteShortcut:
			// write implies read across the same surfaces.
			for _, r := range flowmeshReadResources {
				add("flowmesh:" + r + ":read")
			}
			for _, r := range flowmeshWriteResources {
				add("flowmesh:" + r + ":write")
			}
		default:
			add(s)
		}
	}
	return out
}
