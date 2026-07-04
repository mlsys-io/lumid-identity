package handler

// /me/skills — skills as a first-class surface (Workstream E).
//
//   GET /me/skills            inventory: every skill the caller's apps
//                             import, inverted to used_by[{app,loops}],
//                             with installed/latest versions + CI health
//                             from xpcloud community lineage (the values
//                             skill-ci POSTs).
//   GET /me/skills/discover   proxy of xpcloud's trust-gated catalog
//                             (skill-roster's published output).
//   GET /me/skills/:owner/:name  detail: repo meta + lineage + readme +
//                             used_by expanded.
//
// xpcloud calls are best-effort with a short budget — the local
// inventory renders even when the marketspace is unreachable.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

type skillUsedBy struct {
	App   string   `json:"app"`
	Loops []string `json:"loops,omitempty"`
	// Version pin from skill_imports[] (semver range like "^0.1.0").
	VersionPinned string `json:"version_pinned,omitempty"`
}

type meSkillRow struct {
	Repo             string         `json:"repo"` // owner/name
	Name             string         `json:"name"`
	Summary          string         `json:"summary,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	VersionInstalled string         `json:"version_installed,omitempty"`
	VersionLatest    string         `json:"version_latest,omitempty"`
	UpdateAvailable  bool           `json:"update_available"`
	InstalledOnDisk  bool           `json:"installed_on_disk"`
	UsedBy           []skillUsedBy  `json:"used_by"`
	Health           map[string]any `json:"health,omitempty"` // adapter_status / ci_status / ci_last_run
}

// 60s meta cache — the inventory page polls; xpcloud round-trips per
// skill would otherwise dominate.
var skillMetaCache sync.Map // repo → struct{ exp time.Time; meta map[string]any; lineage map[string]any }

type skillMetaEntry struct {
	exp     time.Time
	meta    map[string]any
	lineage map[string]any
}

// appSkillDecl is the slice of xpcloud.yaml /me/skills reads per app.
type appSkillDecl struct {
	SkillImports []struct {
		Repo    string `yaml:"repo"`
		Version string `yaml:"version"`
	} `yaml:"skill_imports"`
	Loops []struct {
		Name          string          `yaml:"name"`
		SkillsInvoked flexYamlStrings `yaml:"skills_invoked"`
		Steps         []struct {
			Skill string `yaml:"skill"`
		} `yaml:"steps"`
	} `yaml:"loops"`
}

// flexYamlStrings tolerates entries as bare strings or {skill:|name:|id:} docs
// (same contract leniency as admin_loops.go's flexStrings).
type flexYamlStrings []string

func (f *flexYamlStrings) UnmarshalYAML(value *yaml.Node) error {
	var raw []any
	if err := value.Decode(&raw); err != nil {
		return err
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		switch v := e.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if s := coerceFlexEntry(v); s != "" {
				out = append(out, s)
			}
		}
	}
	*f = out
	return nil
}

// MeSkills — GET /api/v1/me/skills
func MeSkills(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// 1. Walk the caller's apps (tenant first, then operator-shared) and
	//    invert skill_imports[] → used_by. Tenant shadowing matches the
	//    rest of /me/*: a tenant app wins over a same-named shared one.
	usages := map[string]*skillUsage{} // repo → usage
	seenApps := map[string]bool{}
	for _, root := range []string{tenantAppsDir(userID), filepath.Join(operatorHome(), ".xp", "apps")} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") || seenApps[e.Name()] {
				continue
			}
			seenApps[e.Name()] = true
			app := e.Name()
			specPath, _ := ResolveSpecPath(filepath.Join(root, app))
			b, err := os.ReadFile(specPath)
			if err != nil {
				continue
			}
			var decl appSkillDecl
			if yaml.Unmarshal(b, &decl) != nil {
				continue
			}
			// Map a skill file id (e.g. "llm") back to the repo that ships
			// it is ambiguous; usage tracking stays at repo granularity —
			// loops list which loops belong to an app importing the repo.
			loopNames := []string{}
			for _, L := range decl.Loops {
				if L.Name != "" {
					loopNames = append(loopNames, L.Name)
				}
			}
			for _, si := range decl.SkillImports {
				repo := strings.TrimSpace(si.Repo)
				if repo == "" {
					continue
				}
				u := usages[repo]
				if u == nil {
					u = &skillUsage{loops: map[string]map[string]bool{}}
					usages[repo] = u
				}
				if si.Version != "" {
					u.pinned = si.Version
				}
				if u.loops[app] == nil {
					u.loops[app] = map[string]bool{}
				}
				for _, ln := range loopNames {
					u.loops[app][ln] = true
				}
			}
		}
	}

	// 2. Per repo: installed-on-disk version + xpcloud meta/lineage
	//    (parallel, cached, budgeted).
	skillRoots := []string{
		filepath.Join(tenantRoot(userID), ".xp", "skills"),
		filepath.Join(operatorHome(), ".xp", "skills"),
	}
	repos := make([]string, 0, len(usages))
	for r := range usages {
		repos = append(repos, r)
	}
	sort.Strings(repos)

	rows := make([]meSkillRow, len(repos))
	var wg sync.WaitGroup
	for i, repo := range repos {
		wg.Add(1)
		go func(i int, repo string) {
			defer wg.Done()
			rows[i] = buildSkillRow(repo, usages[repo], skillRoots)
		}(i, repo)
	}
	wg.Wait()

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"skills": rows, "count": len(rows)},
	})
}

func buildSkillRow(repo string, u *skillUsage, roots []string) meSkillRow {
	row := meSkillRow{Repo: repo, UsedBy: []skillUsedBy{}}
	if i := strings.LastIndex(repo, "/"); i >= 0 {
		row.Name = repo[i+1:]
	} else {
		row.Name = repo
	}
	// used_by
	apps := make([]string, 0, len(u.loops))
	for a := range u.loops {
		apps = append(apps, a)
	}
	sort.Strings(apps)
	for _, a := range apps {
		loops := make([]string, 0, len(u.loops[a]))
		for l := range u.loops[a] {
			loops = append(loops, l)
		}
		sort.Strings(loops)
		row.UsedBy = append(row.UsedBy, skillUsedBy{App: a, Loops: loops, VersionPinned: u.pinned})
	}
	// installed on disk + local version
	for _, root := range roots {
		base := filepath.Join(root, filepath.FromSlash(repo))
		if st, err := os.Stat(base); err == nil && st.IsDir() {
			row.InstalledOnDisk = true
			candidates := []string{}
			if mp, ok := ResolveManifestPath(base); ok {
				candidates = append(candidates, mp)
			}
			candidates = append(candidates, filepath.Join(base, "manifest.yml"))
			if sp, ok := ResolveSpecPath(base); ok {
				candidates = append(candidates, sp)
			}
			for _, fn := range candidates {
				b, err := os.ReadFile(fn)
				if err != nil {
					continue
				}
				var m struct {
					Version string `json:"version" yaml:"version"`
				}
				if yaml.Unmarshal(b, &m) == nil && m.Version != "" {
					row.VersionInstalled = m.Version
					break
				}
			}
			break
		}
	}
	// xpcloud meta + lineage (cached 60s)
	meta, lineage := skillRemoteMeta(repo)
	if meta != nil {
		if v, _ := meta["version"].(string); v != "" {
			row.VersionLatest = v
		}
		if s, _ := meta["summary"].(string); s != "" {
			row.Summary = s
		}
		if dn, _ := meta["display_name"].(string); dn != "" && dn != row.Name {
			row.Name = dn
		}
		if tags, ok := meta["tags"].([]any); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					row.Tags = append(row.Tags, s)
				}
			}
		}
	}
	if lineage != nil {
		row.Health = map[string]any{}
		for _, k := range []string{"adapter_status", "ci_status", "ci_last_run"} {
			if v, ok := lineage[k]; ok {
				row.Health[k] = v
			}
		}
		if len(row.Health) == 0 {
			row.Health = nil
		}
	}
	row.UpdateAvailable = row.VersionInstalled != "" && row.VersionLatest != "" &&
		row.VersionInstalled != row.VersionLatest
	return row
}

// skillUsage accumulates per-repo usage while MeSkills walks the apps.
type skillUsage struct {
	pinned string
	loops  map[string]map[string]bool // app → loop set
}

func skillRemoteMeta(repo string) (map[string]any, map[string]any) {
	if v, ok := skillMetaCache.Load(repo); ok {
		e := v.(skillMetaEntry)
		if time.Now().Before(e.exp) {
			return e.meta, e.lineage
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var meta, lineage map[string]any
	if m, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/repos/"+repo); err == nil {
		meta = m
	}
	if l, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/repos/"+repo+"/lineage"); err == nil {
		if inner, ok := l["lineage"].(map[string]any); ok {
			lineage = inner
		}
	}
	skillMetaCache.Store(repo, skillMetaEntry{exp: time.Now().Add(60 * time.Second), meta: meta, lineage: lineage})
	return meta, lineage
}

// MeSkillsDiscover — GET /api/v1/me/skills/discover: the marketspace
// skill catalog (trust-gated; skill-roster's published output).
func MeSkillsDiscover(c *gin.Context) {
	if _, ok := currentUserID(c); !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	out, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/skills/catalog")
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "marketspace unreachable: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": out})
}

// MeSkillDetail — GET /api/v1/me/skills/:owner/:name
func MeSkillDetail(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	owner, name := c.Param("owner"), c.Param("name")
	if !slugRe.MatchString(owner) || !slugRe.MatchString(name) {
		fail(c, http.StatusBadRequest, 1400, "invalid repo")
		return
	}
	repo := owner + "/" + name
	meta, lineage := skillRemoteMeta(repo)

	// Readme — local install first (offline-friendly), then xpcloud blob.
	readme := ""
	for _, root := range []string{
		filepath.Join(tenantRoot(userID), ".xp", "skills"),
		filepath.Join(operatorHome(), ".xp", "skills"),
	} {
		b, err := os.ReadFile(filepath.Join(root, owner, name, "README.md"))
		if err == nil {
			readme = string(b)
			break
		}
	}
	if readme == "" {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if blob, err := httpGetJSON(ctx, xpcloudBaseURL()+"/api/v1/repos/"+repo+"/blob/main/README.md"); err == nil {
			if s, _ := blob["content"].(string); s != "" {
				readme = s
			}
		}
	}
	if len(readme) > 128*1024 {
		readme = readme[:128*1024]
	}

	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"repo":    repo,
			"meta":    meta,
			"lineage": lineage,
			"readme":  readme,
		},
	})
}
