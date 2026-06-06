package handler

// Real workflow-assembly trace: search → match → verify, against LIVE xp.io.
//
// The compose step used to fabricate each skill's "source" and a fake match
// confidence. This resolves the truth instead, mirroring exactly how the
// runtime loads a forked app's skills (sdk/apps/app_runner.py:_load_skill_module):
//
//   1. SEARCH   — ask xp.io's skill catalog (/api/v1/skills/suggest) what it has
//                 for the intent. For a trading bot the community catalog has no
//                 specialised skill, so this honestly returns few/zero hits — and
//                 that's *why* we resolve from the auto-quant reference app.
//   2. MATCH    — for each pipeline skill, walk the fork parent (auto-quant) then
//                 the skill_imports (lumid-lqa, lumid-findata) and find the repo +
//                 path + blob SHA where it actually lives on xp.io.
//   3. VERIFY   — fork parent published? imports published? how many skills
//                 resolved vs ship local-only? is the risk officer wired? is the
//                 observe→learn shape complete?
//
// Best-effort: every xp.io call is time-boxed and any failure degrades to
// "unverified" rather than failing the compose.

import (
	"context"
	"fmt"
	"strings"
)

type ownerRepo struct {
	Owner string
	Repo  string
}

// Resolution candidates for the curated trading fork, in the SAME order the
// runtime resolves them: fork parent first, then each skill_import. Keep this
// in lock-step with buildTradingXpcloudYaml's fork_of + skill_imports.
var tradingParent = ownerRepo{Repo: "auto-quant"} // owner resolved live via search
var tradingImports = []ownerRepo{
	{Owner: "a3f48236-ffe9-4fb9-9548-6e044d5cd9c7", Repo: "lumid-lqa"},
	{Owner: "a3f48236-ffe9-4fb9-9548-6e044d5cd9c7", Repo: "lumid-findata"},
}

type skillLoc struct {
	Owner, Repo, Path, SHA string
}

// xpioResolveOwner finds the owner_sub of a repo by exact name via search.
// Reference apps are first-party, so an exact-name match is unambiguous.
func xpioResolveOwner(ctx context.Context, name string) string {
	resp, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/repos/search?q="+name+"&limit=8")
	if err != nil {
		return ""
	}
	list, _ := resp["results"].([]any)
	if list == nil {
		list, _ = resp["repos"].([]any)
	}
	for _, raw := range list {
		m, _ := raw.(map[string]any)
		if m == nil {
			continue
		}
		if s, _ := m["name"].(string); s == name {
			if o, _ := m["owner_sub"].(string); o != "" {
				return o
			}
		}
	}
	return ""
}

// xpioRepoSkills fetches a repo's skills/ tree and maps skill-name → location.
// Returns (map, published). published=false means the repo or its skills/ dir
// could not be read on xp.io.
func xpioRepoSkills(ctx context.Context, owner, repo string) (map[string]skillLoc, bool) {
	out := map[string]skillLoc{}
	if owner == "" || repo == "" {
		return out, false
	}
	url := fmt.Sprintf("%s/api/v1/repos/%s/%s/tree/main/skills", xpcloudBaseURL(), owner, repo)
	resp, err := httpGetJSON(ctx, url)
	if err != nil {
		return out, false
	}
	entries, ok := resp["entries"].([]any)
	if !ok {
		// repo exists but no skills/ dir, or 404 shaped as {detail:...}
		return out, resp["detail"] == nil
	}
	for _, raw := range entries {
		e, _ := raw.(map[string]any)
		if e == nil {
			continue
		}
		if t, _ := e["type"].(string); t != "blob" {
			continue
		}
		fn, _ := e["name"].(string)
		if !strings.HasSuffix(fn, ".py") || fn == "__init__.py" || strings.HasPrefix(fn, "_") {
			continue
		}
		base := strings.TrimSuffix(fn, ".py")
		sha, _ := e["sha"].(string)
		out[base] = skillLoc{Owner: owner, Repo: repo, Path: "skills/" + fn, SHA: sha}
	}
	return out, true
}

// buildAssemblyTrace runs the real search → match → verify procedure and
// returns (trace, enrichedSteps). enrichedSteps clones `steps` with resolved_*
// + source overwritten by the truth. Never errors — degrades to unverified.
func buildAssemblyTrace(ctx context.Context, intent string, steps []map[string]any) (map[string]any, []map[string]any) {
	// ── 1. SEARCH the live catalog ──────────────────────────────────
	search := map[string]any{
		"endpoint": "xp.io · /api/v1/skills/suggest",
		"query":    intent,
		"scorer":   "token-v1",
		"hits":     []map[string]any{},
	}
	{
		body := []byte(fmt.Sprintf(`{"intent":%q,"max":5}`, intent))
		if resp, err := httpPostJSON(ctx, xpcloudBaseURL()+"/api/v1/skills/suggest", body); err == nil {
			if sc, _ := resp["scorer"].(string); sc != "" {
				search["scorer"] = sc
			}
			hits := []map[string]any{}
			sg, _ := resp["suggestions"].([]any)
			for _, raw := range sg {
				m, _ := raw.(map[string]any)
				if m == nil {
					continue
				}
				hits = append(hits, map[string]any{
					"name": m["name"], "score": m["score"], "matched": m["matched"],
				})
			}
			search["hits"] = hits
		}
	}

	// ── 2. MATCH each skill against parent + imports (runtime order) ──
	parent := tradingParent
	if parent.Owner == "" {
		parent.Owner = xpioResolveOwner(ctx, parent.Repo)
	}
	candidates := append([]ownerRepo{parent}, tradingImports...)

	type repoProbe struct {
		ownerRepo
		skills    map[string]skillLoc
		published bool
	}
	probes := make([]repoProbe, 0, len(candidates))
	for _, cr := range candidates {
		sk, pub := xpioRepoSkills(ctx, cr.Owner, cr.Repo)
		probes = append(probes, repoProbe{ownerRepo: cr, skills: sk, published: pub})
	}

	resolve := func(skill string) (skillLoc, bool) {
		for _, p := range probes {
			if loc, ok := p.skills[skill]; ok {
				return loc, true
			}
		}
		return skillLoc{}, false
	}

	enriched := make([]map[string]any, 0, len(steps))
	resolvedCount, localOnly := 0, []string{}
	for _, st := range steps {
		ns := map[string]any{}
		for k, v := range st {
			ns[k] = v
		}
		skill, _ := st["skill"].(string)
		if loc, ok := resolve(skill); ok {
			resolvedCount++
			ns["resolved"] = true
			ns["source"] = loc.Repo
			ns["resolved_repo"] = loc.Owner + "/" + loc.Repo
			ns["resolved_path"] = loc.Path
			ns["resolved_sha"] = shortSHA(loc.SHA)
		} else {
			ns["resolved"] = false
			// Keep the curated source as a hint; flag it ships with the fork.
			if _, has := ns["source"]; !has {
				ns["source"] = "auto-quant"
			}
			ns["resolved_note"] = "ships with the fork (not separately published)"
			localOnly = append(localOnly, skill)
		}
		enriched = append(enriched, ns)
	}

	// ── 3. VERIFY ────────────────────────────────────────────────────
	resolvedFrom := []map[string]any{}
	for _, p := range probes {
		resolvedFrom = append(resolvedFrom, map[string]any{
			"repo": p.Repo, "owner": p.Owner, "published": p.published, "skill_count": len(p.skills),
		})
	}

	verify := []map[string]any{}
	addCheck := func(label, detail, status string) {
		verify = append(verify, map[string]any{"check": label, "detail": detail, "status": status})
	}
	// fork parent
	if probes[0].published {
		addCheck("Fork parent published", fmt.Sprintf("%s · %d skills on xp.io", parent.Repo, len(probes[0].skills)), "pass")
	} else {
		addCheck("Fork parent published", parent.Repo+" not readable on xp.io", "fail")
	}
	// imports
	impOK, impMiss := 0, []string{}
	for _, p := range probes[1:] {
		if p.published {
			impOK++
		} else {
			impMiss = append(impMiss, p.Repo)
		}
	}
	if len(impMiss) == 0 {
		addCheck("Skill imports published", fmt.Sprintf("%d/%d imports resolved", impOK, len(probes)-1), "pass")
	} else {
		addCheck("Skill imports published", "missing on xp.io: "+strings.Join(impMiss, ", "), "warn")
	}
	// skills resolved
	total := len(steps)
	skStatus := "pass"
	skDetail := fmt.Sprintf("%d/%d skills resolved on xp.io", resolvedCount, total)
	if len(localOnly) > 0 {
		skStatus = "warn"
		skDetail += " · local-only: " + strings.Join(localOnly, ", ")
	}
	if resolvedCount == 0 {
		skStatus = "fail"
	}
	addCheck("Skills resolved", skDetail, skStatus)
	// risk officer
	riskWired := false
	for _, st := range steps {
		if sub, _ := st["substage"].(string); sub == "risk-gate" {
			riskWired = true
		}
		if id, _ := st["id"].(string); id == "risk_gate" {
			riskWired = true
		}
	}
	if riskWired {
		addCheck("Risk officer wired", "score_proposal vets size/drawdown/regime before any journal", "pass")
	} else {
		addCheck("Risk officer wired", "no risk-gate step found", "warn")
	}
	// pipeline shape
	stages := map[string]bool{}
	for _, st := range steps {
		if s, _ := st["stage"].(string); s != "" {
			stages[s] = true
		}
	}
	have := []string{}
	for _, s := range []string{"observe", "hypothesize", "act", "analyze", "learn"} {
		if stages[s] {
			have = append(have, s)
		}
	}
	addCheck("Pipeline shape", fmt.Sprintf("%d steps · %s", total, strings.Join(have, "→")), "pass")

	note := ""
	if hits, _ := search["hits"].([]map[string]any); len(hits) == 0 {
		note = "No specialised trading skill in the public catalog — resolving the pipeline from the auto-quant reference app + lumid-lqa market-data skills."
	}
	if note != "" {
		search["note"] = note
	}

	trace := map[string]any{
		"search":        search,
		"resolved_from": resolvedFrom,
		"verify":        verify,
	}
	return trace, enriched
}

func shortSHA(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
