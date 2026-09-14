package handler

import (
	"encoding/json"
	"strings"
	"time"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// experimentCarryKeys — the experiments[] keys a partial write must put back.
//
// `patch_experiment` REPLACES the whole experiments[] entry; there is no merge
// on the scheduler side, deliberately (a textual edit that spliced one key into
// an existing block is how comments get eaten). So every verb that rewrites an
// experiment has to resend the fields it did not mean to change, and the list of
// those fields lives here — once — because the two verbs that need it drifted
// apart within a day of each other being written.
//
// Measured 2026-09-13: define_experiment, called by this platform's own agent to
// re-bind a loop, erased both arms of a finished 52-row experiment.
// Measured 2026-09-14 by audit: add_experiment_arm carried neither `dispatch`
// (so adding an arm to quant-research's backtest_evidence deleted the
// `dispatch.ask` that makes its arms dispatchable at all) nor `status`,
// `benchmark_id`, `cases`, `description` or `min_samples` — the last four
// because the row those verbs read did not even expose them.
//
// `arms` is in the list because define_experiment cannot express it. A verb that
// computes arms itself (add_experiment_arm) skips that one key and carries the
// rest; see experimentCarryOnto.
var experimentCarryKeys = []string{
	"arms", "dispatch", "baseline", "kind", "benchmark_id", "status",
}

// experimentRewriteKeys — every key a FULL rewrite has to resend, which is the
// carry set plus the ones define_experiment's own schema can express.
//
// The distinction matters and is not cosmetic. define_experiment keeps its
// expressible fields caller-authoritative on purpose ("omitting `cases` still
// clears them, because the caller can see and resend that"), so it carries only
// experimentCarryKeys. add_experiment_arm expresses nothing but the arm, so for
// it EVERY other key is a field the caller had no way to preserve.
var experimentRewriteKeys = append(append([]string{}, experimentCarryKeys...),
	"cases", "description", "min_samples", "dataset_id",
	"success_criteria", "hypothesis", "metric",
)

// experimentCarryOnto copies every carry-forward key present in `decl` onto
// `payload`, without overwriting anything the caller has already set — so a verb
// states what it is changing and this fills in the rest.
//
// Two shapes need care:
//   - `status` defaults to "active" in the row even when the spec never declared
//     it, so writing it back unconditionally would inject a key the app did not
//     author. Only a non-default status (concluded/archived) is worth carrying.
//   - `min_samples` is an int on expDecl but arrives as float64 when the row has
//     been through JSON. Accept both; the old code tested only float64, so it
//     dropped min_samples on every single arm add.
func experimentCarryOnto(payload map[string]any, decl map[string]any, skip ...string) {
	skipped := map[string]bool{}
	for _, k := range skip {
		skipped[k] = true
	}
	for _, k := range experimentRewriteKeys {
		if skipped[k] {
			continue
		}
		if _, already := payload[k]; already {
			continue
		}
		v, ok := decl[k]
		if !ok || v == nil {
			continue
		}
		switch k {
		case "status":
			if sv, _ := v.(string); sv != "" && sv != "active" {
				payload[k] = sv
			}
		case "min_samples":
			switch n := v.(type) {
			case int:
				if n > 0 {
					payload[k] = n
				}
			case float64:
				if n > 0 {
					payload[k] = int(n)
				}
			}
		default:
			switch tv := v.(type) {
			case string:
				if tv != "" {
					payload[k] = tv
				}
			case []string:
				if len(tv) > 0 {
					payload[k] = tv
				}
			case []any:
				if len(tv) > 0 {
					payload[k] = tv
				}
			case map[string]any:
				if len(tv) > 0 {
					payload[k] = tv
				}
			default:
				payload[k] = v
			}
		}
	}
}

// declLoop resolves the loop an existing experiment is attached to.
//
// TWO linkage conventions exist and both are legitimate:
// loops[].engine.experiment (what expLoops reads, surfaced as `loops`) and
// experiments[].dispatch.loop (what an app declares when several loops feed one
// experiment and only one of them is dispatchable). Knowing only the first made
// add_experiment_arm refuse analyst_local_gpu — an experiment with 52 rows and a
// published verdict — as "attached to no loop".
func declLoop(decl map[string]any) string {
	if decl == nil {
		return ""
	}
	switch ls := decl["loops"].(type) {
	case []string:
		if len(ls) > 0 {
			return ls[0]
		}
	case []any:
		if len(ls) > 0 {
			s, _ := ls[0].(string)
			return s
		}
	}
	if dsp, ok := decl["dispatch"].(map[string]any); ok {
		s, _ := dsp["loop"].(string)
		return s
	}
	return ""
}

// hydratePatchBody fills a PATCH body's empty fields from the existing
// declaration, so a partial write means what it says.
//
// Without this, "partial" was a lie in two directions at once. The shape guard
// requires `loop`, `metric.name` and a scope on EVERY write, so a PATCH changing
// only success_criteria was rejected 422 — while a PATCH that did satisfy the
// guard and omitted `arms` silently erased them. Merging first makes the guard
// judge the resulting experiment rather than the request, which is the thing it
// is actually there to protect.
func hydratePatchBody(b *experimentWriteBody, decl map[string]any) {
	if b == nil || decl == nil {
		return
	}
	if b.Loop == "" {
		b.Loop = declLoop(decl)
	}
	for _, f := range []struct {
		dst *string
		key string
	}{
		{&b.Kind, "kind"}, {&b.Description, "description"}, {&b.Hypothesis, "hypothesis"},
		{&b.DatasetID, "dataset_id"}, {&b.Criteria, "success_criteria"},
	} {
		if *f.dst == "" {
			if s, _ := decl[f.key].(string); s != "" {
				*f.dst = s
			}
		}
	}
	if b.Metric == nil || strings.TrimSpace(b.Metric.Name) == "" {
		if m, ok := decl["metric"].(map[string]any); ok {
			if name, _ := m["name"].(string); name != "" {
				hib := true
				if v, ok := m["higher_is_better"].(bool); ok {
					hib = v
				}
				b.Metric = &experimentMetric{Name: name, HigherIsBetter: &hib}
			}
		}
	}
	if len(b.Cases) == 0 {
		switch cs := decl["cases"].(type) {
		case []string:
			b.Cases = cs
		case []any:
			for _, c := range cs {
				if s, _ := c.(string); s != "" {
					b.Cases = append(b.Cases, s)
				}
			}
		}
	}
	if len(b.Arms) == 0 {
		if arms, ok := decl["arms"].([]map[string]any); ok {
			b.Arms = arms
		}
	}
	if b.MinSamples == nil {
		switch n := decl["min_samples"].(type) {
		case int:
			if n > 0 {
				b.MinSamples = &n
			}
		case float64:
			if n > 0 {
				v := int(n)
				b.MinSamples = &v
			}
		}
	}
	if len(b.Baseline) == 0 {
		if bl, ok := decl["baseline"].(map[string]any); ok {
			b.Baseline = bl
		}
	}
	if len(b.Dispatch) == 0 {
		if d, ok := decl["dispatch"].(map[string]any); ok {
			b.Dispatch = d
		}
	}
}

// waitIntentWarnings polls one intent briefly and returns the warnings its
// result carries, plus whether it completed.
//
// WHY A CHAT TOOL WAITS AT ALL. The model guard is the whole reason
// define_experiment has a guard: a model name that resolves nowhere does not
// error, it ABSTAINS, and a "median of three" panel quietly becomes a panel of
// one while every number on screen still looks healthy. The scheduler produces
// that warning — and produces it AFTER writing the spec, returned in the intent
// result. The tool's answer said "poll the intent for the result and any model
// warnings", and nothing polls: the assistant reports success and the warning
// is never spoken.
//
// Bounded hard. A chat turn cannot stall on a queue, so this waits seconds, not
// the 90 the UI can afford, and says plainly when it gave up rather than
// implying there was nothing to report.
func waitIntentWarnings(userSub, intentID string, budget time.Duration) ([]string, bool) {
	if intentID == "" || common.DB == nil {
		return nil, false
	}
	deadline := time.Now().Add(budget)
	for {
		var row models.MeAppIntent
		if err := common.DB.Where("id = ? AND user_sub = ?", intentID, userSub).
			First(&row).Error; err != nil {
			return nil, false
		}
		if row.Status == "completed" || row.Status == "failed" {
			var res struct {
				Warnings []string `json:"warnings"`
				Error    string   `json:"error"`
			}
			if row.Result != "" {
				_ = json.Unmarshal([]byte(row.Result), &res)
			}
			out := res.Warnings
			if res.Error != "" {
				out = append(out, res.Error)
			}
			return out, true
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(400 * time.Millisecond)
	}
}
