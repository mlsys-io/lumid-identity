package handler

// Deleting one workflow from an app spec, as a yaml.Node edit.
//
// A spec names its workflows in one of two lists:
//
//   - `workflows:` (the simple scheme, spec_v2.go) — entries keyed by `id`;
//   - `loops:` (legacy) — entries keyed by `name`.
//
// A file may mix both, so the target is looked up in each. Deleting a
// workflow from the simple scheme also has to keep the rest of the graph
// consistent, because other entries point at it by id:
//
//   - `experiments[].workflow` — refused (409) unless forced; forced, those
//     experiments are dropped from the spec too (their ledgers stay on disk);
//   - a chain's `steps.workflows` (or a translated `engine: {type: chain}`)
//     — always refused, naming the chain: dropping a stage silently changes
//     what the chain measures;
//   - `nodes[].parent` and `workflows[].parent` — re-parented to the deleted
//     workflow's own `parent`, or the key is removed when it had none.
//
// Nothing else is touched. The edit is done on the yaml.Node tree, like
// appendToSkillImports, so comments and key order survive (a map round trip
// drops every comment in the owner's spec).

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"
)

// workflowDeleteForceHint is how a refusal tells the caller about the flag.
const workflowDeleteForceHint = "?force=1"

// workflowDeletePlan is the rewritten spec plus what changed besides the
// workflow itself.
type workflowDeletePlan struct {
	Out                 []byte
	Lists               []string // which lists held it: "workflows", "loops"
	Remaining           int
	DroppedExperiments  []string
	ReparentedNodes     []string
	ReparentedWorkflows []string
}

// onlyRemovesLegacyLoop: the edit is exactly "drop one loops[] entry" — what
// even a scheduler older than the simple-scheme remove_loop does (and it
// archives the history). See schedulerRemovesWorkflows.
func (p *workflowDeletePlan) onlyRemovesLegacyLoop() bool {
	return len(p.Lists) == 1 && p.Lists[0] == "loops" &&
		len(p.DroppedExperiments) == 0 && len(p.ReparentedNodes) == 0 && len(p.ReparentedWorkflows) == 0
}

// ── yaml.Node helpers ──────────────────────────────────────────────────────

func ynDeref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

// ynGet returns the value node of `key` in mapping m, or nil.
func ynGet(m *yaml.Node, key string) *yaml.Node {
	m = ynDeref(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return ynDeref(m.Content[i+1])
		}
	}
	return nil
}

// ynDel removes `key` from mapping m.
func ynDel(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// ynStr is a scalar's text ("" for null, non-scalars and nil).
func ynStr(n *yaml.Node) string {
	n = ynDeref(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

// ynItems is a sequence's entries (nil when n is not a sequence).
func ynItems(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// workflowEntryKey is an entry's workflow id: `id` first in `workflows:`,
// `name` first in `loops:` (each falls back to the other key).
func workflowEntryKey(list string, e *yaml.Node) string {
	e = ynDeref(e)
	if e == nil || e.Kind != yaml.MappingNode {
		return ""
	}
	first, second := "id", "name"
	if list == "loops" {
		first, second = "name", "id"
	}
	if k := ynStr(ynGet(e, first)); k != "" {
		return k
	}
	return ynStr(ynGet(e, second))
}

// chainNamesWorkflow reports whether workflow entry e runs `wf` as a chain
// stage: `steps.workflows: [wf | {use: wf}]`, or a translated
// `engine: {type: chain, stages: [{loop: wf}]}`.
func chainNamesWorkflow(e *yaml.Node, wf string) bool {
	for _, st := range ynItems(ynGet(ynGet(e, "steps"), "workflows")) {
		st = ynDeref(st)
		if ynStr(st) == wf || ynStr(ynGet(st, "use")) == wf {
			return true
		}
	}
	if eng := ynGet(e, "engine"); ynStr(ynGet(eng, "type")) == "chain" {
		for _, st := range ynItems(ynGet(eng, "stages")) {
			if ynStr(ynGet(st, "loop")) == wf {
				return true
			}
		}
	}
	return false
}

// reparent points mapping e's `parent: wf` at newParent, or drops the key
// when newParent is "". Reports whether e pointed at wf.
func reparent(e *yaml.Node, wf, newParent string) bool {
	e = ynDeref(e)
	v := ynGet(e, "parent")
	if v == nil || ynStr(v) != wf {
		return false
	}
	if newParent == "" {
		ynDel(e, "parent")
		return true
	}
	// Edit in place so a trailing comment on the line stays.
	v.Kind, v.Tag, v.Value, v.Alias = yaml.ScalarNode, "!!str", newParent, nil
	return true
}

func quoteList(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = "'" + id + "'"
	}
	return strings.Join(q, ", ")
}

// planWorkflowDelete removes workflow `wf` from the spec bytes. Returns
// (plan, httpStatus, retCode, message); status 200 means plan is set.
//
// Refusals, in order: 404 unknown workflow; 409 the app's last workflow;
// 409 a chain runs it; 409 an experiment runs on it (unless force, which
// drops those experiments).
func planWorkflowDelete(spec []byte, app, wf string, force bool) (*workflowDeletePlan, int, int, string) {
	notFound := func() (*workflowDeletePlan, int, int, string) {
		return nil, http.StatusNotFound, 1404, "workflow '" + wf + "' not found in " + app
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, http.StatusInternalServerError, 1500, "parse xpcloud.yaml: " + err.Error()
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return notFound()
	}
	root := doc.Content[0]

	plan := &workflowDeletePlan{}
	var removed []*yaml.Node
	total := 0
	for _, list := range []string{"workflows", "loops"} {
		seq := ynGet(root, list)
		items := ynItems(seq)
		kept := make([]*yaml.Node, 0, len(items))
		hit := false
		for _, e := range items {
			if workflowEntryKey(list, e) == wf {
				removed = append(removed, ynDeref(e))
				hit = true
				continue
			}
			kept = append(kept, e)
		}
		total += len(items)
		if hit {
			seq.Content = kept
			plan.Lists = append(plan.Lists, list)
		}
	}
	if len(removed) == 0 {
		return notFound()
	}
	plan.Remaining = total - len(removed)
	if plan.Remaining == 0 {
		return nil, http.StatusConflict, 1409,
			"can't remove the last workflow — delete the app instead"
	}

	// The remaining workflows, for the chain check and re-parenting.
	var others []*yaml.Node
	for _, list := range []string{"workflows", "loops"} {
		for _, e := range ynItems(ynGet(root, list)) {
			if e = ynDeref(e); e != nil && e.Kind == yaml.MappingNode {
				others = append(others, e)
			}
		}
	}

	var chains []string
	for _, e := range others {
		if chainNamesWorkflow(e, wf) {
			id := ynStr(ynGet(e, "id"))
			if id == "" {
				id = ynStr(ynGet(e, "name"))
			}
			chains = append(chains, id)
		}
	}
	if len(chains) > 0 {
		subj := "Chain " + quoteList(chains) + " runs"
		if len(chains) > 1 {
			subj = "Chains " + quoteList(chains) + " run"
		}
		return nil, http.StatusConflict, 1409,
			subj + " this workflow as a stage; remove it from the chain first"
	}

	expSeq := ynGet(root, "experiments")
	var exps []string
	keptExps := make([]*yaml.Node, 0, len(ynItems(expSeq)))
	for _, e := range ynItems(expSeq) {
		if ynStr(ynGet(e, "workflow")) == wf {
			id := ynStr(ynGet(e, "id"))
			if id == "" {
				id = ynStr(ynGet(e, "name"))
			}
			exps = append(exps, id)
			continue
		}
		keptExps = append(keptExps, e)
	}
	if len(exps) > 0 {
		if !force {
			subj := "Experiment " + quoteList(exps) + " runs"
			if len(exps) > 1 {
				subj = "Experiments " + quoteList(exps) + " run"
			}
			return nil, http.StatusConflict, 1409, subj +
				" on this workflow; archive or move it first (or delete with " +
				workflowDeleteForceHint + " to drop it too)"
		}
		expSeq.Content = keptExps
		plan.DroppedExperiments = exps
	}

	// Children move up one level: to the deleted workflow's own parent.
	newParent := ynStr(ynGet(removed[0], "parent"))
	if newParent == wf {
		newParent = ""
	}
	for _, n := range ynItems(ynGet(root, "nodes")) {
		if reparent(n, wf, newParent) {
			plan.ReparentedNodes = append(plan.ReparentedNodes, ynStr(ynGet(n, "id")))
		}
	}
	for _, e := range others {
		if reparent(e, wf, newParent) {
			id := ynStr(ynGet(e, "id"))
			if id == "" {
				id = ynStr(ynGet(e, "name"))
			}
			plan.ReparentedWorkflows = append(plan.ReparentedWorkflows, id)
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, http.StatusInternalServerError, 1500, fmt.Sprintf("marshal: %v", err)
	}
	_ = enc.Close()
	plan.Out = buf.Bytes()
	return plan, http.StatusOK, 0, ""
}
