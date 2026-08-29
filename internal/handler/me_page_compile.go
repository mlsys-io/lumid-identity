package handler

// Deterministic page-spec → Lumid markdown compiler.
//
// A structured page spec (ui/page.yaml) compiles straight to the lumid:
// directive markdown — NO LLM in the loop. This is the reliable path for
// pages whose form keys must EXACTLY bind to live backend actions (e.g.
// gpu_rental.create): the spec is the source of truth, the output is
// deterministic, every time. The kvrun LLM path stays only for approximate
// pages where exactness doesn't matter.
//
// Spec shape:
//   title: GPU Rentals
//   intro: "one-line description (markdown)"
//   sections:
//     - heading: "New rental"          # optional
//       prose: "**Hardware** — …"      # optional markdown
//       widgets:
//         - { type: stat, source: me://gpu-rentals, path: count, label: "…" }
//         - { type: form, action: gpu_rental.create, submit_label: "…",
//             fields: [ {key,label,type,default,options,placeholder,required} ],
//             cost_estimate: { gpu_field, cpu_field, ttl_field, gpu_rate, cpu_rate } }
//         - { type: table, source: me://gpu-rentals, path: rentals,
//             columns: [ {key,label} ] }

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// allowedWidgets — the directive types the compiler will emit. lumid:native is
// intentionally absent (abandoned).
var allowedWidgets = map[string]bool{
	"stat": true, "table": true, "chart": true, "list": true,
	"action": true, "tabs": true, "form": true, "search-table": true,
}

type pageSpecDoc struct {
	Title    string `yaml:"title"`
	Intro    string `yaml:"intro"`
	Sections []struct {
		Heading string           `yaml:"heading"`
		Prose   string           `yaml:"prose"`
		Columns int              `yaml:"columns"` // >1 → lay this section's widgets side by side
		Widgets []map[string]any `yaml:"widgets"`
	} `yaml:"sections"`
}

// compilePageSpec turns a structured page.yaml into lumid markdown. Each
// widget's config is re-serialized as YAML verbatim into a ```lumid:<type>```
// fence — so the binding-critical bits (action keys, field keys, sources)
// pass through unchanged. Returns an error on unparseable spec or an empty
// result; unknown widget types are skipped (never emitted as native).
func compilePageSpec(b []byte) (string, error) {
	var doc pageSpecDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse page.yaml: %w", err)
	}
	var sb strings.Builder
	if t := strings.TrimSpace(doc.Title); t != "" {
		sb.WriteString("# " + t + "\n\n")
	}
	if in := strings.TrimSpace(doc.Intro); in != "" {
		sb.WriteString(in + "\n\n")
	}
	emitted := 0
	for _, sec := range doc.Sections {
		if h := strings.TrimSpace(sec.Heading); h != "" {
			sb.WriteString("## " + h + "\n\n")
		}
		if p := strings.TrimSpace(sec.Prose); p != "" {
			sb.WriteString(p + "\n\n")
		}
		// Collect this section's allowed widgets (dropping unknown/native).
		var widgets []map[string]any
		for _, w := range sec.Widgets {
			wtype, _ := w["type"].(string)
			if !allowedWidgets[strings.TrimSpace(wtype)] {
				continue
			}
			widgets = append(widgets, w)
		}
		if len(widgets) == 0 {
			continue
		}
		// Multi-column section → wrap the widgets in one lumid:columns block so
		// they render side by side; otherwise emit each widget as its own fence.
		if sec.Columns > 1 {
			blocks := make([]map[string]any, 0, len(widgets))
			for _, w := range widgets {
				blocks = append(blocks, w) // keep `type` — lumid:columns reads it per block
			}
			yb, err := yaml.Marshal(map[string]any{"columns": sec.Columns, "blocks": blocks})
			if err == nil {
				sb.WriteString("```lumid:columns\n")
				sb.Write(yb)
				if !strings.HasSuffix(string(yb), "\n") {
					sb.WriteString("\n")
				}
				sb.WriteString("```\n\n")
				emitted += len(widgets)
				continue
			}
		}
		// A RUN of consecutive `stat` widgets lays out side by side even when
		// the author declared no `columns`.
		//
		// A stat renders as a small fixed-width badge (inline-flex, min-w
		// 120px) — it is built to sit in a row. Emitted as its own fence it
		// becomes a block-level element, so four of them stacked into four
		// lines of number-over-label and pushed the real content off the fold.
		// Reported from the live Strategies page, whose Overview is exactly
		// four stats.
		//
		// An explicit `columns:` still wins (handled above), and ONLY stats
		// group: a table or form beside them keeps its own full-width fence. A
		// lone stat is left alone — a one-cell grid is a stat with extra markup.
		for i := 0; i < len(widgets); {
			run := statRunLength(widgets[i:])
			if run < 2 {
				if emitWidgetFence(&sb, widgets[i]) {
					emitted++
				}
				i++
				continue
			}
			// LumidColumns clamps to 4; a bigger number silently collapses
			// there and the extras wrap. Clamp here, where the intent is
			// readable, and still pass every widget in the run.
			cols := run
			if cols > 4 {
				cols = 4
			}
			yb, err := yaml.Marshal(map[string]any{"columns": cols, "blocks": widgets[i : i+run]})
			if err != nil {
				// Fall back to one fence each rather than dropping the row.
				for _, w := range widgets[i : i+run] {
					if emitWidgetFence(&sb, w) {
						emitted++
					}
				}
				i += run
				continue
			}
			sb.WriteString("```lumid:columns\n")
			sb.Write(yb)
			if !strings.HasSuffix(string(yb), "\n") {
				sb.WriteString("\n")
			}
			sb.WriteString("```\n\n")
			emitted += run
			i += run
		}
	}
	out := strings.TrimRight(sb.String(), "\n") + "\n"
	if emitted == 0 {
		return "", fmt.Errorf("page.yaml produced no widgets")
	}
	return out, nil
}

// statRunLength counts the leading consecutive `stat` widgets in ws.
func statRunLength(ws []map[string]any) int {
	n := 0
	for _, w := range ws {
		t, _ := w["type"].(string)
		if strings.TrimSpace(t) != "stat" {
			break
		}
		n++
	}
	return n
}

// emitWidgetFence writes one widget as its own ```lumid:<type>``` fence.
// Reports whether anything was written, so the caller's count stays honest
// when a widget fails to marshal.
func emitWidgetFence(sb *strings.Builder, w map[string]any) bool {
	wtype, _ := w["type"].(string)
	wtype = strings.TrimSpace(wtype)
	body := make(map[string]any, len(w))
	for k, v := range w {
		if k != "type" {
			body[k] = v
		}
	}
	yb, err := yaml.Marshal(body)
	if err != nil {
		return false
	}
	sb.WriteString("```lumid:" + wtype + "\n")
	sb.Write(yb)
	if !strings.HasSuffix(string(yb), "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("```\n\n")
	return true
}
