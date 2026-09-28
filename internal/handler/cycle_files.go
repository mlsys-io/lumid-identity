package handler

// One cycle dir, parsed the same way wherever its bytes came from.
//
// The cycle inspector (MeCycleDetail, the chat tool `cycle_detail`, the run
// drill-down) used to read the cycle dir straight off disk. identity mounts no
// tenant volume, so for every tenant install that read found nothing and the
// inspector said "per-step detail is not available on this deployment". The
// scheduler can read the dir; it now hands identity the same files through the
// `cycle_read` read intent (me_cycle_read_intent.go). Both sources feed
// cycleDetailFromFiles, so the drill-down cannot differ by where it was read.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

// cycleFiles is a cycle dir's top-level files, name → content.
type cycleFiles map[string][]byte

// cycleSidecarMax is the per-file cap for a sidecar artifact (and the picker's
// per-file cap for cycle_read).
const cycleSidecarMax = 256 * 1024

// cycleSidecarNames are the standalone per-stage artifacts some apps write
// instead of folding them into cycle.json (auto-sysresearch: observations.json
// for observe, proposal.json for hypothesize, …).
var cycleSidecarNames = []string{
	"observations", "proposal", "result", "results", "patterns",
	"analysis", "improvement", "plan", "variant", "benchmark",
}

// readCycleDirFiles reads what the inspector renders from a cycle dir on this
// pod's disk: every top-level `*.json` and `prompt_audit.jsonl`. It is the disk
// twin of the picker's `cycle_read` — same selection, so the two sources give
// the builder the same input.
func readCycleDirFiles(dir string) cycleFiles {
	out := cycleFiles{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".json") && name != "prompt_audit.jsonl" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		out[name] = b
	}
	return out
}

// cycleOutcomeOK is whether a cycle succeeded, by the SAME rule the runtime
// uses when it reports the run to the run store (app_runner._self_report_run:
// `not step_errors and summary.get("ok", True) is not False`) and writes the
// journal (`ok: not step_errors`).
//
// cycle.json's own `ok` is not that. A Pattern-A cycle initialises
// summary["ok"] = True and never lowers it when a step fails — the failure is
// recorded in summary["step_errors"] — so cycle.json says `ok: true` beside a
// list of step errors, while the run list (built from the store) says the same
// cycle failed. The two surfaces disagreed about one run. The runner's `ok` is
// also what the scheduler counts consecutive failures on, so it is not changed
// at the source; every identity reader derives the outcome here instead.
func cycleOutcomeOK(summary map[string]any, stepErrorsSidecar []byte) bool {
	if v, has := summary["ok"].(bool); has && !v {
		return false
	}
	if arr, _ := summary["step_errors"].([]any); len(arr) > 0 {
		return false
	}
	if len(stepErrorsSidecar) > 0 {
		var arr []any
		if json.Unmarshal(stepErrorsSidecar, &arr) == nil && len(arr) > 0 {
			return false
		}
	}
	return true
}

// normalizeCycleOK sets summary["ok"] to the derived outcome. When cycle.json
// said otherwise, the written value is kept as `ok_as_written` so nothing the
// file said is lost — only which field a reader should trust.
func normalizeCycleOK(summary map[string]any, stepErrorsSidecar []byte) bool {
	ok := cycleOutcomeOK(summary, stepErrorsSidecar)
	if v, has := summary["ok"].(bool); has && v != ok {
		summary["ok_as_written"] = v
	}
	summary["ok"] = ok
	return ok
}

// cycleDetailFromFiles builds the inspector's view — summary, steps with the
// prompt-audit join, sidecar artifacts — from a cycle dir's files.
func cycleDetailFromFiles(app, loop, ts string, files cycleFiles) gin.H {
	// Headline cycle.json
	cycleSummary := map[string]any{}
	if b, has := files["cycle.json"]; has {
		_ = json.Unmarshal(b, &cycleSummary)
	}
	ok := normalizeCycleOK(cycleSummary, files["step_errors.json"])

	// Prompt audit — per-step sha + preview.
	prompts := map[string]map[string]string{} // step_id → {sha, preview}
	if b, has := files["prompt_audit.jsonl"]; has {
		scanner := bufio.NewScanner(bytes.NewReader(b))
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			var row map[string]any
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				continue
			}
			sid, _ := row["step_id"].(string)
			if sid == "" {
				continue
			}
			sha, _ := row["prompt_sha256"].(string)
			preview, _ := row["instructions_preview"].(string)
			prompts[sid] = map[string]string{"sha": sha, "preview": preview}
		}
	}

	// Steps — each <stepID>.json
	steps := []cycleStep{}
	for name, b := range files {
		if !strings.HasSuffix(name, ".json") || name == "cycle.json" {
			continue
		}
		var raw map[string]any
		if json.Unmarshal(b, &raw) != nil {
			continue
		}
		sid := strings.TrimSuffix(name, ".json")
		step := cycleStep{StepID: sid, OK: true}
		if skill, has := raw["skill"].(string); has {
			step.Skill = skill
		}
		if stage, has := raw["stage"].(string); has {
			step.Stage = stage
		}
		if okv, has := raw["ok"].(bool); has {
			step.OK = okv
		}
		if errv, has := raw["error"].(string); has {
			step.Error = errv
		}
		if d, has := raw["duration_s"].(float64); has {
			step.Duration = d
		}
		// Output: include the full dict for the UI, plus a short
		// summary line for the collapsed view.
		if out, has := raw["output"].(map[string]any); has {
			step.Output = out
			step.OutputSummary = summarizeOutput(out)
		}
		// Some skills return a flat shape — use raw as the output.
		if step.Output == nil {
			step.Output = raw
			step.OutputSummary = summarizeOutput(raw)
		}
		if pa, has := prompts[sid]; has {
			step.PromptSHA = pa["sha"]
			step.PromptPreview = pa["preview"]
		}
		steps = append(steps, step)
	}
	// Sort steps by id (skill convention uses lexicographic order).
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].StepID < steps[j].StepID
	})

	// Sidecar artifacts — some apps (e.g. auto-sysresearch) write the real
	// per-stage content as standalone files instead of into cycle.json. Surface
	// them as a map so the per-stage inspector can render the actual artifact.
	sidecars := map[string]any{}
	for _, name := range cycleSidecarNames {
		if b, has := files[name+".json"]; has && len(b) < cycleSidecarMax {
			var v any
			if json.Unmarshal(b, &v) == nil {
				sidecars[name] = v
			}
		}
	}

	return gin.H{
		"app":     app,
		"loop":    loop,
		"ts":      ts,
		"ok":      ok,
		"summary": cycleSummary,
		"steps":   steps,
		"files":   sidecars,
	}
}
