package handler

// POST /me/apps/:app/ui/generate
//
// Reads the app's xpcloud.yaml + procedure.md (if present) and calls
// Gemma4 on kv.run to generate a Lumid markdown UI surface (ui/home.md).
// Always updates xpcloud.yaml to point at the generated file.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const gemma4Model = "unsloth/gemma-4-26B-A4B-it-GGUF:UD-Q4_K_XL"
const gemma4Endpoint = "https://kv.run:5000/v1/messages"

const generateUISysPrompt = `You are generating a Lumid markdown UI surface file (ui/home.md) for an xpio app.

Output ONLY raw markdown — no wrapper code fence, no preamble, no trailing explanation.

If a "Current UI" or "Current page" section is provided below, REPRODUCE it and improve on it — keep what works, preserve intent, enhance layout/expressiveness. Never throw the current UI away in favor of a generic dashboard. A native component (lumid:native) given as the Current UI MUST be kept as the primary widget.

## Directive Reference

Interactive widgets are fenced blocks tagged ` + "`" + `lumid:<type>` + "`" + ` containing YAML config.

` + "```" + `lumid:stat
source: me://today
path: cycles.length
label: "Cycles Run Today"
` + "```" + `

` + "```" + `lumid:table
source: me://today
path: cycles
columns:
  - key: app
    label: App
  - key: loop
    label: Loop
  - key: ok
    label: OK
  - key: ts
    label: Time
  - key: duration_s
    label: Duration (s)
` + "```" + `

` + "```" + `lumid:table
source: me://drafts
path: drafts
columns:
  - key: app
    label: App
  - key: subject
    label: Subject
  - key: state
    label: State
  - key: cycle_ts
    label: Cycle
` + "```" + `

` + "```" + `lumid:chart
source: findata://ohlc/AAPL?interval=1d
path: bars
kind: line
x: ts
y: close
` + "```" + `

` + "```" + `lumid:chart
source: me://today
path: cycles
kind: bar
x: loop
y: duration_s
` + "```" + `

` + "```" + `lumid:list
source: me://today
path: headlines
title_key: summary
subtitle_key: app
` + "```" + `

` + "```" + `lumid:action
label: "Run Now"
action: run_loop
app: my-app
loop: my-loop
` + "```" + `

` + "```" + `lumid:tabs
tabs:
  - label: Overview
    blocks:
      - type: table
        source: me://today
        path: cycles
        columns:
          - key: app
            label: App
          - key: loop
            label: Loop
          - key: ok
            label: OK
` + "```" + `

` + "```" + `lumid:form
action: gpu_rental.create
submit_label: "Create rental"
fields:
  - { key: gpu, label: "GPU count", type: number, default: 1 }
  - { key: gpu_memory_gb, label: "GPU memory (GB)", type: number, default: 16 }
  - { key: ttl_minutes, label: "TTL (minutes)", type: number, default: 60 }
  - { key: mode, label: "Access mode", type: select, options: [proxy, direct, forward], default: proxy }
` + "```" + `
(A parameter form that submits to a backend action. ` + "`action`" + ` MUST be one of the allowlisted action keys given in the page description — never invent one. Field types: text | number | select | textarea. Use this for the API/parameter forms described in the Current page section.)

## Allowed Data Sources — use ONLY these

| Source | Response shape | Useful path |
|---|---|---|
| me://today | { cycles: [{app,loop,ok,ts,duration_s,outcome}], headlines: [{kind,app,loop,summary}] } | cycles, headlines |
| me://drafts | { drafts: [{id,app,subject,body,state,cycle_ts}], count } | drafts |
| me://workflows | { workflows: [{id,name,schedule,kind,status}] } | workflows |
| me://loops/health | { apps: [{app,kind,version,status}] } | apps |
| me://apps | { apps: [{name,version,kind}] } | apps |
| findata://ohlc/SYMBOL?interval=1d | { bars: [{ts,open,high,low,close,volume}] } | bars (for a price chart: x=ts, y=close) |
| findata://quotes?symbols=SYMBOL | [{symbol,price,ts,volume}] | (root — current price snapshot) |
| findata://news/SYMBOL | [{title,published_at,source}] | (root — no path needed) |

## Widget types — use the full set for an expressive page
- ` + "`lumid:stat`" + ` — single KPI number (source + path → a value)
- ` + "`lumid:chart`" + ` — line or bar chart over a time-series / numeric rows (kind: line|bar, x, y). y may be a list for multiple series. PREFER a chart over a table for numeric/time data — it reads better.
- ` + "`lumid:table`" + ` — rows × columns for record data
- ` + "`lumid:list`" + ` — title/subtitle feed (good for headlines, drafts, news)
- ` + "`lumid:action`" + ` — a button that runs a loop (@trigger loops)
- ` + "`lumid:tabs`" + ` — group related widgets under labeled tabs

## Design rules
- 4–6 widgets — be expressive; lead with a ` + "`lumid:stat`" + ` row or a ` + "`lumid:chart`" + `, not a bare table
- Match content to the app's actual purpose AND its skills (see the Skills section below) — do NOT just dump all loops or all installed apps
- For a trading/finance app: lead with a findata:// ` + "`lumid:chart`" + ` + key ` + "`lumid:stat`" + `s, then a recent-cycle table
- For an ops/health app: use me://loops/health or me://workflows, a ` + "`lumid:chart`" + ` of cycle durations, and a ` + "`lumid:list`" + ` of headlines
- For any app with @trigger loops: add a ` + "`lumid:action`" + ` button per @trigger loop
- Use ## headers to label sections; group secondary widgets under ` + "`lumid:tabs`" + `
- For apps with no loops (pure tools/skills): show me://today cycles + a me://drafts ` + "`lumid:list`" + ` if relevant
`

// pageYamlSysPrompt instructs the model to emit a STRUCTURED page.yaml — the
// reliable surface format (validated + deterministically compiled on serve).
const pageYamlSysPrompt = `You generate a STRUCTURED page spec (page.yaml) for an xpio app's Studio UI.

Output ONLY a valid YAML document — no code fences, no prose, no explanation.

Schema:
  title: <app title>
  intro: <one-line description>
  sections:
    - heading: <optional section heading>
      prose: <optional markdown paragraph>
      widgets:
        - <widget>

Widget types:
  - { type: stat, source: <src>, path: <dotpath to value>, label: "..." }
  - { type: chart, source: <src>, path: <dotpath to array>, kind: line|bar, x: <key>, y: <key> }
  - { type: table, source: <src>, path: <dotpath to array>, columns: [ { key: <k>, label: "..." } ] }
  - { type: list, source: <src>, path: <dotpath to array>, title_key: <k>, subtitle_key: <k> }
  - { type: action, label: "Run now", action: run_loop, app: <app>, loop: <loop> }
  - { type: form, action: <ALLOWLISTED action key>, submit_label: "...", field_columns: 1|2|3,
      fields: [ { key, label, type: text|number|select|textarea, options: [..], default, placeholder, required, group: "<group heading>", full_width: true } ],
      cost_estimate: { gpu_field, cpu_field, ttl_field, gpu_rate, cpu_rate } }

Allowed data sources (reads) — use ONLY these:
  me://today | me://drafts | me://workflows | me://loops/health | me://apps | me://gpu-rentals
  findata://ohlc/SYMBOL?interval=1d (path: bars; x: ts; y: close) | findata://quotes?symbols=SYMBOL | findata://news/SYMBOL

Form actions (submit targets): use ONLY an action key named in the page description below (e.g. gpu_rental.create). NEVER invent an action key.

Rules:
  - Use form group + field_columns: 2 to cluster related fields into grouped, multi-column cards (mirrors a native wizard). Mark textareas full_width: true.
  - Lead with a stat row or chart; reorder/group for clarity.
  - If a "Current page.yaml" is given below, IMPROVE it (reorder, group, multi-column) but keep its action keys, field keys, and sources EXACTLY.
  - Match content to the app's purpose + skills. Quote any label containing a comma or colon.
`

// buildPageYamlPrompt assembles the user message for page.yaml generation.
func buildPageYamlPrompt(appName, xpcloudYAML, pageSpec, currentPage, skillsBlock string) string {
	var sb strings.Builder
	sb.WriteString("Generate ui/page.yaml for the app **" + appName + "**.\n\n## xpcloud.yaml\n\n```yaml\n")
	sb.WriteString(xpcloudYAML)
	sb.WriteString("\n```\n")
	if strings.TrimSpace(currentPage) != "" {
		sb.WriteString("\n## Current page.yaml — improve this (keep actions/keys/sources exact)\n\n```yaml\n")
		sb.WriteString(truncateStr(currentPage, 6000))
		sb.WriteString("\n```\n")
	}
	if strings.TrimSpace(pageSpec) != "" {
		sb.WriteString("\n## Page description (names the allowlisted action keys + intended layout)\n\n")
		sb.WriteString(truncateStr(pageSpec, 6000))
		sb.WriteString("\n")
	}
	if skillsBlock != "" {
		sb.WriteString(skillsBlock)
	}
	return sb.String()
}

// MeGenerateAppUI generates a Lumid markdown surface from the app's config.
func MeGenerateAppUI(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}

	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	specPath, _ := ResolveSpecPath(appDir)
	yamlBytes, err := os.ReadFile(specPath)
	if err != nil {
		fail(c, http.StatusUnprocessableEntity, 1422, "xpcloud.yaml not found in app bundle")
		return
	}

	// "Generate UI" now produces a STRUCTURED page.yaml (validated + compiled
	// on serve), not freeform markdown. Context: improve the CURRENT page.yaml
	// if present; else seed from the NL page-spec (which names allowlisted
	// action keys) + the app's skills.
	currentPage := ""
	if pb, e := os.ReadFile(filepath.Join(appDir, "ui", "page.yaml")); e == nil {
		currentPage = string(pb)
	}
	pageSpec := ""
	if pb, e := os.ReadFile(filepath.Join(appDir, "ui", "page-spec.md")); e == nil {
		pageSpec = string(pb)
	}
	skills := resolveAppSkills(appDir, userID)
	uiSkills := resolveUISkills(userID)
	userMsg := buildPageYamlPrompt(app, string(yamlBytes), pageSpec, currentPage, renderSkillsBlock(skills)+renderUISkillsBlock(uiSkills))

	ctx, cancel := context.WithTimeout(c.Request.Context(), 90*time.Second)
	defer cancel()

	generated, err := callGemmaBlocking(ctx, userMsg, pageYamlSysPrompt)
	if err != nil {
		fail(c, http.StatusServiceUnavailable, 1503, "gen error: "+err.Error())
		return
	}
	generated = stripOuterFence(generated) // strip any ```yaml wrapper

	// Validate: the generated page.yaml MUST compile, or we don't persist a
	// broken page. (LLMs drift on structured output — this guard makes a bad
	// generation a clean error, not a broken surface.)
	md, cerr := compilePageSpec([]byte(generated))
	if cerr != nil {
		fail(c, http.StatusUnprocessableEntity, 1422, "generated page.yaml invalid: "+cerr.Error())
		return
	}

	// Persist page.yaml as the source of truth + point the surface at it.
	uiDir := filepath.Join(appDir, "ui")
	if err := os.MkdirAll(uiDir, 0755); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot create ui directory")
		return
	}
	target := filepath.Join(uiDir, "page.yaml")
	tmp := target + ".tmp"
	if werr := os.WriteFile(tmp, []byte(generated), 0644); werr != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot write page.yaml")
		return
	}
	if rerr := os.Rename(tmp, target); rerr != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "cannot save page.yaml")
		return
	}
	_ = patchXpcloudUISurfacePage(appDir, "ui/page.yaml")
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"markdown": md, "path": "ui/page.yaml", "source": "generated"},
	})
}

// writeSurfaceAndRespond persists the surface markdown to ui/home.md (atomic),
// patches xpcloud.yaml to point at it, and returns the standard JSON. Shared by
// the LLM path and the deterministic compiler path.
func writeSurfaceAndRespond(c *gin.Context, appDir, md, source string) {
	uiDir := filepath.Join(appDir, "ui")
	if err := os.MkdirAll(uiDir, 0755); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot create ui directory")
		return
	}
	target := filepath.Join(uiDir, "home.md")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(md), 0644); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "cannot write surface file")
		return
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		fail(c, http.StatusInternalServerError, 1500, "cannot save surface file")
		return
	}
	_ = patchXpcloudUISurface(appDir, "home", "ui/home.md")
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"markdown": md, "path": "ui/home.md", "source": source},
	})
}

// callGemmaBlocking calls Gemma4 on kv.run synchronously and returns the full text.
func callGemmaBlocking(ctx context.Context, userMsg, systemPrompt string) (string, error) {
	pat, err := kvrunPAT()
	if err != nil {
		return "", fmt.Errorf("kvrun PAT: %w", err)
	}

	model := gemma4Model
	if m := strings.TrimSpace(os.Getenv("LUMID_UI_GEN_MODEL")); m != "" {
		model = m
	}
	reqBody, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 4096,
		"system":     systemPrompt,
		"messages":   []map[string]any{{"role": "user", "content": userMsg}},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gemma4Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", pat)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("kv.run unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kv.run %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}

	var msg struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	var sb strings.Builder
	for _, b := range msg.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	return sb.String(), nil
}

// buildGeneratePrompt formats the user message sent to the model.
func buildGeneratePrompt(appName, xpcloudYAML, procedureMD, skillsBlock string) string {
	var sb strings.Builder
	sb.WriteString("Generate a ui/home.md surface for the app **")
	sb.WriteString(appName)
	sb.WriteString("**.\n\n## xpcloud.yaml\n\n```yaml\n")
	sb.WriteString(xpcloudYAML)
	sb.WriteString("\n```\n")
	if skillsBlock != "" {
		sb.WriteString(skillsBlock)
	}
	if procedureMD != "" {
		sb.WriteString("\n## procedure.md\n\n")
		sb.WriteString(procedureMD)
		sb.WriteString("\n")
	}
	return sb.String()
}

// nativeSurfaceKey returns the app's declared native UI key (ui.surface.native),
// or "" if it has none. A native app's generated page must EMBED that component
// (via lumid:native) so generation realizes the current UI instead of replacing
// the interactive surface with a generic dashboard.
func nativeSurfaceKey(yamlBytes []byte) string {
	var doc struct {
		UI struct {
			Surface struct {
				Native string `yaml:"native"`
			} `yaml:"surface"`
		} `yaml:"ui"`
	}
	if yaml.Unmarshal(yamlBytes, &doc) != nil {
		return ""
	}
	return strings.TrimSpace(doc.UI.Surface.Native)
}

// renderCurrentUIBlock tells the model what the app's CURRENT UI is, so a
// (re)generation reproduces + improves it rather than starting from scratch.
func renderCurrentUIBlock(nativeKey, currentMD, pageSpec string) string {
	// An authored page description wins — it's the parse→describe→regenerate
	// source of truth. Reproduce it faithfully, turning described forms into
	// lumid:form widgets bound to the action keys it names.
	if strings.TrimSpace(pageSpec) != "" {
		return "\n## Current page — DESCRIPTION (reproduce faithfully)\n" +
			"This describes the app's real UI: its sections, the data each shows, and any forms (with the allowlisted action key + fields). Rebuild a page that matches it. Render described forms as `lumid:form` blocks bound to the named action key. Keep the structure and intent; you may refine layout/wording.\n\n" +
			truncateStr(pageSpec, 6000) + "\n"
	}
	// (lumid:native is abandoned — generation never embeds an opaque native
	// component. A native app is reproduced from its page-spec as real widgets
	// + lumid:form, so every path of the page is editable/configurable.)
	_ = nativeKey
	if strings.TrimSpace(currentMD) != "" {
		return "\n## Current page — reproduce and improve this\n" +
			"Here is the app's current page. Keep the widgets that fit, preserve its intent, and improve layout/clarity/expressiveness. Do NOT discard working content:\n\n" +
			"```markdown\n" + truncateStr(currentMD, 4000) + "\n```\n"
	}
	return ""
}

// skillInfo is the slice of a skill manifest relevant to UI generation.
type skillInfo struct {
	Name        string
	Description string
	Tags        []string
}

// resolveAppSkills reads the app's xpcloud.yaml::skill_imports[] and resolves
// each to its skill manifest (tenant skills dir first, then operator-shared),
// returning name + description + tags to ground UI generation. Best-effort:
// an unresolved skill still surfaces by repo name so the model knows the
// capability exists.
func resolveAppSkills(appDir, userSub string) []skillInfo {
	specPath, _ := ResolveSpecPath(appDir)
	yb, err := os.ReadFile(specPath)
	if err != nil {
		return nil
	}
	var doc struct {
		SkillImports []struct {
			Repo string `yaml:"repo"`
		} `yaml:"skill_imports"`
	}
	if yaml.Unmarshal(yb, &doc) != nil {
		return nil
	}
	roots := []string{
		filepath.Join(tenantRoot(userSub), ".xp", "skills"),
		filepath.Join(operatorHome(), ".xp", "skills"),
	}
	var out []skillInfo
	seen := map[string]bool{}
	for _, si := range doc.SkillImports {
		repo := strings.TrimSpace(si.Repo)
		if repo == "" || seen[repo] {
			continue
		}
		seen[repo] = true
		if info := readSkillManifest(roots, repo); info != nil {
			out = append(out, *info)
		}
	}
	return out
}

// readSkillManifest finds <root>/<owner>/<name>/manifest.{json,yaml,yml} for
// the given "owner/name" repo across the candidate roots.
func readSkillManifest(roots []string, repo string) *skillInfo {
	for _, root := range roots {
		base := filepath.Join(root, filepath.FromSlash(repo))
		for _, fn := range []string{"manifest.json", "manifest.yaml", "manifest.yml"} {
			b, err := os.ReadFile(filepath.Join(base, fn))
			if err != nil {
				continue
			}
			var m struct {
				Name        string   `json:"name" yaml:"name"`
				DisplayName string   `json:"display_name" yaml:"display_name"`
				Description string   `json:"description" yaml:"description"`
				Tags        []string `json:"tags" yaml:"tags"`
			}
			ok := false
			if strings.HasSuffix(fn, ".json") {
				ok = json.Unmarshal(b, &m) == nil
			} else {
				ok = yaml.Unmarshal(b, &m) == nil
			}
			if !ok {
				continue
			}
			name := m.DisplayName
			if name == "" {
				name = m.Name
			}
			if name == "" {
				name = repo
			}
			return &skillInfo{Name: name, Description: m.Description, Tags: m.Tags}
		}
	}
	// Unresolved — surface the repo's last segment so the capability still shows.
	parts := strings.Split(repo, "/")
	return &skillInfo{Name: parts[len(parts)-1]}
}

// uiSkill is a UI-tagged skill contributing extra widget recipes (markdown
// directive exemplars) to the generate prompt. The recipes are DATA — few-shot
// examples the model can emit — never executable code. Interactive components
// remain allowlisted in the frontend's native-registry.ts.
type uiSkill struct {
	Name        string
	Description string
	Recipes     string // contents of the skill's ui_recipes.md, if present
}

var uiSkillTags = map[string]bool{
	"ui": true, "widget": true, "widgets": true, "viz": true,
	"dashboard": true, "chart": true, "charts": true,
}

// resolveUISkills discovers UI-tagged skills across the caller's tenant skills
// dir, the operator-shared skills dir, and the community owner tree, returning
// their name/description + any ui_recipes.md so the generator can use a richer,
// extensible widget vocabulary. Best-effort + capped; degrades to empty when
// no UI skills are published yet (the built-in vocabulary still applies).
func resolveUISkills(userSub string) []uiSkill {
	roots := []string{
		filepath.Join(tenantRoot(userSub), ".xp", "skills"),
		filepath.Join(operatorHome(), ".xp", "skills"),
	}
	var out []uiSkill
	seen := map[string]bool{}
	const cap = 8
	for _, root := range roots {
		owners, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, owner := range owners {
			if !owner.IsDir() {
				continue
			}
			ownerDir := filepath.Join(root, owner.Name())
			repos, err := os.ReadDir(ownerDir)
			if err != nil {
				continue
			}
			for _, repo := range repos {
				if !repo.IsDir() || len(out) >= cap {
					continue
				}
				key := owner.Name() + "/" + repo.Name()
				if seen[key] {
					continue
				}
				skillDir := filepath.Join(ownerDir, repo.Name())
				info := readSkillManifest([]string{root}, key)
				if info == nil {
					continue
				}
				isUI := false
				for _, t := range info.Tags {
					if uiSkillTags[strings.ToLower(strings.TrimSpace(t))] {
						isUI = true
						break
					}
				}
				if !isUI {
					continue
				}
				seen[key] = true
				recipes := ""
				if rb, err := os.ReadFile(filepath.Join(skillDir, "ui_recipes.md")); err == nil {
					recipes = string(rb)
				}
				out = append(out, uiSkill{Name: info.Name, Description: info.Description, Recipes: recipes})
			}
		}
	}
	return out
}

// renderUISkillsBlock formats discovered UI skills' recipes as a prompt
// section. The recipes are injected verbatim as few-shot exemplars.
func renderUISkillsBlock(skills []uiSkill) string {
	if len(skills) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n## Extra widget recipes from UI skills\n\n")
	sb.WriteString("These community UI skills provide additional layout patterns. Use them as inspiration for a more expressive page (they use the same lumid: directive set):\n\n")
	for _, s := range skills {
		sb.WriteString("### " + s.Name)
		if s.Description != "" {
			sb.WriteString(" — " + truncateStr(s.Description, 160))
		}
		sb.WriteString("\n")
		if s.Recipes != "" {
			sb.WriteString(truncateStr(s.Recipes, 1500))
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// renderSkillsBlock formats resolved skills as a prompt section.
func renderSkillsBlock(skills []skillInfo) string {
	if len(skills) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n## Skills (what this app can do)\n\n")
	sb.WriteString("This app imports these skills. Choose widgets + data sources that reflect these capabilities:\n\n")
	for _, s := range skills {
		sb.WriteString("- **" + s.Name + "**")
		if len(s.Tags) > 0 {
			sb.WriteString(" [" + strings.Join(s.Tags, ", ") + "]")
		}
		if s.Description != "" {
			sb.WriteString(" — " + truncateStr(s.Description, 200))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// stripNativeBlocks removes any ```lumid:native ... ``` fenced block from the
// generated markdown. lumid:native is abandoned — pages are reproduced from
// their page-spec as real widgets + lumid:form, never an opaque embed. This is
// a hard server-side guarantee independent of how well the model obeyed.
func stripNativeBlocks(md string) string {
	lines := strings.Split(md, "\n")
	var out []string
	inNative := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if !inNative && strings.HasPrefix(t, "```lumid:native") {
			inNative = true
			continue
		}
		if inNative {
			if t == "```" {
				inNative = false
			}
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// stripOuterFence removes a single wrapping markdown code fence if the model
// wrapped the entire output in one (e.g. ```markdown ... ```).
func stripOuterFence(s string) string {
	s = strings.TrimSpace(s)
	for _, lang := range []string{"markdown", "md", ""} {
		open := "```" + lang
		if strings.HasPrefix(s, open) && strings.HasSuffix(s, "```") {
			inner := strings.TrimPrefix(s, open)
			if len(inner) > 0 && inner[0] == '\n' {
				inner = inner[1:]
				inner = strings.TrimSuffix(inner, "```")
				inner = strings.TrimSuffix(inner, "\n")
				return strings.TrimSpace(inner)
			}
		}
	}
	return s
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
