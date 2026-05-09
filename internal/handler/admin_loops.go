package handler

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gin-gonic/gin"
)

// GET /admin/loops — super-admin dashboard tile.
//
// Reports the autoresearch loops declared on this host + their last-
// run state. Two sources, in priority order:
//
//   1) ~/.lumilake/scheduler/xpio_state.json
//        Source-of-truth when the lumid-scheduler daemon is running.
//        Per loop: last_run_ts, last_ok, consecutive_failures.
//   2) ~/.xp/apps/<app>/.scheduler.json
//        Per-app index dropped by sdk/ops/apps._post_install_hooks.
//        Each app lists its loops with schedule + declared_in.
//
// When a loop appears in (2) but NOT (1) it means the daemon either
// hasn't fired it yet OR isn't running on this host. We surface
// last_run_ts=0 + status="never" so the operator can spot loops that
// are declared but cold.
//
// Identity runs in a container; ~/.xp lives on the host. The compose
// for lumid_identity bind-mounts /home/webmaster/.xp at /home/webmaster/.xp
// when the LUMID_OPERATOR_HOME env var is set; otherwise we look in
// the container's $HOME (typically empty on a fresh build). All paths
// are best-effort — missing files don't 500.

type loopRow struct {
	App                  string   `json:"app"`
	Loop                 string   `json:"loop"`
	Schedule             string   `json:"schedule"`
	DeclaredIn           string   `json:"declared_in"`
	LastRunTS            float64  `json:"last_run_ts"`
	LastOk               *bool    `json:"last_ok,omitempty"`
	ConsecutiveFailures  int      `json:"consecutive_failures"`
	LastDurationSeconds  float64  `json:"last_duration_s"`
	Status               string   `json:"status"` // "never" | "ok" | "failing" | "stale" | "manual"
	// Detail fields populated on click; cheap enough to ship inline so
	// the tile doesn't need a second fetch when a row expands.
	Description          string   `json:"description,omitempty"`
	PrimaryRole          string   `json:"primary_role,omitempty"`
	KnowledgeAgent       string   `json:"knowledge_agent,omitempty"`
	Mode                 string   `json:"mode,omitempty"`
	Skills               []string `json:"skills,omitempty"`
	Steps                []loopStep `json:"steps,omitempty"`
	Datasets             []string `json:"datasets,omitempty"`
	GoalPrimary          string   `json:"goal_primary,omitempty"`
	GoalTracked          []string `json:"goal_tracked,omitempty"`
	LatestCycleDir       string   `json:"latest_cycle_dir,omitempty"`
	LatestCycleTS        string   `json:"latest_cycle_ts,omitempty"`
}

type loopStep struct {
	ID             string `json:"id"`
	Skill          string `json:"skill"`
	KnowledgeAgent string `json:"knowledge_agent,omitempty"`
}

type schedulerState struct {
	Loops map[string]struct {
		LastRunTS           float64 `json:"last_run_ts"`
		ConsecutiveFailures int     `json:"consecutive_failures"`
		LastOk              *bool   `json:"last_ok"`
		LastDurationSeconds float64 `json:"last_duration_s"`
	} `json:"loops"`
}

type appSchedulerIndex struct {
	App     string `json:"app"`
	Version string `json:"version"`
	Loops   []struct {
		Name           string `json:"name"`
		Schedule       string `json:"schedule"`
		DeclaredIn     string `json:"declared_in"`
		KnowledgeAgent string `json:"knowledge_agent"`
	} `json:"loops"`
}

func operatorHome() string {
	if v := os.Getenv("LUMID_OPERATOR_HOME"); v != "" {
		return v
	}
	if u, err := user.Lookup("webmaster"); err == nil {
		return u.HomeDir
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/home/webmaster" // sensible default for the canonical host layout
}

// readSchedulerState pulls the daemon's per-loop runtime state. Empty
// map when missing/unparseable — caller treats those loops as "never".
func readSchedulerState(home string) schedulerState {
	out := schedulerState{Loops: map[string]struct {
		LastRunTS           float64 `json:"last_run_ts"`
		ConsecutiveFailures int     `json:"consecutive_failures"`
		LastOk              *bool   `json:"last_ok"`
		LastDurationSeconds float64 `json:"last_duration_s"`
	}{}}
	p := filepath.Join(home, ".lumilake", "scheduler", "xpio_state.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

// discoverManifestLoops walks every ~/.xp/apps/<app>/manifest.json +
// xpcloud.yaml + autoresearch.yaml and produces the same shape the
// lumid-scheduler daemon discovers. We re-derive on the fly rather
// than trust the static .scheduler.json index — that file may be
// stale if the operator edited a manifest after installing.
func discoverManifestLoops(home string) []appSchedulerIndex {
	root := filepath.Join(home, ".xp", "apps")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := make([]appSchedulerIndex, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		appDir := filepath.Join(root, e.Name())
		idx := appSchedulerIndex{App: e.Name()}
		// Prefer the .scheduler.json that install_hooks wrote — it
		// already has the correct loop shape merged from all 3 files.
		if b, err := os.ReadFile(filepath.Join(appDir, ".scheduler.json")); err == nil {
			if json.Unmarshal(b, &idx) == nil && idx.App != "" {
				out = append(out, idx)
				continue
			}
		}
		// Fallback: walk the three config files.
		idx.App = e.Name()
		// manifest.json::loops[] (mbb-ai shape)
		if mf, err := readManifestLoops(filepath.Join(appDir, "manifest.json")); err == nil {
			for _, L := range mf {
				idx.Loops = append(idx.Loops, struct {
					Name           string `json:"name"`
					Schedule       string `json:"schedule"`
					DeclaredIn     string `json:"declared_in"`
					KnowledgeAgent string `json:"knowledge_agent"`
				}{Name: L.Name, Schedule: L.Schedule, DeclaredIn: "manifest.json", KnowledgeAgent: L.KnowledgeAgent})
			}
		}
		// xpcloud.yaml::loops[] (auto-quant shape)
		if seenNames := loopNames(idx.Loops); true {
			if yamlLoops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
				for _, L := range yamlLoops {
					if _, dup := seenNames[L.Name]; dup {
						continue
					}
					idx.Loops = append(idx.Loops, struct {
						Name           string `json:"name"`
						Schedule       string `json:"schedule"`
						DeclaredIn     string `json:"declared_in"`
						KnowledgeAgent string `json:"knowledge_agent"`
					}{Name: L.Name, Schedule: L.Schedule, DeclaredIn: "xpcloud.yaml", KnowledgeAgent: L.KnowledgeAgent})
				}
			}
		}
		// autoresearch.yaml::name+schedule (ops/xpio-ops shape)
		if name, sched, err := readAutoresearchYaml(filepath.Join(appDir, "autoresearch.yaml")); err == nil && name != "" {
			seen := loopNames(idx.Loops)
			if _, dup := seen[name]; !dup {
				idx.Loops = append(idx.Loops, struct {
					Name           string `json:"name"`
					Schedule       string `json:"schedule"`
					DeclaredIn     string `json:"declared_in"`
					KnowledgeAgent string `json:"knowledge_agent"`
				}{Name: name, Schedule: sched, DeclaredIn: "autoresearch.yaml"})
			}
		}
		if len(idx.Loops) > 0 {
			out = append(out, idx)
		}
	}
	return out
}

func loopNames(ls []struct {
	Name           string `json:"name"`
	Schedule       string `json:"schedule"`
	DeclaredIn     string `json:"declared_in"`
	KnowledgeAgent string `json:"knowledge_agent"`
}) map[string]struct{} {
	out := make(map[string]struct{}, len(ls))
	for _, L := range ls {
		out[L.Name] = struct{}{}
	}
	return out
}

type rawLoop struct {
	Name           string     `json:"name"            yaml:"name"`
	Schedule       string     `json:"schedule"        yaml:"schedule"`
	KnowledgeAgent string     `json:"knowledge_agent" yaml:"knowledge_agent"`
	Description    string     `json:"description"     yaml:"description"`
	PrimaryRole    string     `json:"primary_role"    yaml:"primary_role"`
	Mode           string     `json:"mode"            yaml:"mode"`
	Skills         []string   `json:"skills"          yaml:"skills"`
	Datasets       []string   `json:"datasets"        yaml:"datasets"`
	Steps          []rawStep  `json:"steps"           yaml:"steps"`
	Goal           rawGoal    `json:"goal"            yaml:"goal"`
}

type rawStep struct {
	ID             string `json:"id"              yaml:"id"`
	Skill          string `json:"skill"           yaml:"skill"`
	KnowledgeAgent string `json:"knowledge_agent" yaml:"knowledge_agent"`
}

type rawGoal struct {
	Primary string   `json:"primary" yaml:"primary"`
	Tracked []string `json:"tracked" yaml:"tracked"`
}

// loadLoopDetail walks the app dir to fetch detail-fields for one
// loop. Best-effort — every field is optional. Reads in order:
//   manifest.json::loops[name=loop]   (mbb-ai shape, richest)
//   xpcloud.yaml::loops[name=loop]    (auto-quant shape)
//   autoresearch.yaml                  (ops/xpio-ops single-loop shape)
// Also resolves the most recent cycle dir under data/cycles/<loop>/<ts>/
// or data/outbox/<case>/<ts>/ when present.
func loadLoopDetail(home, app, loop string) (rawLoop, string, string) {
	appDir := filepath.Join(home, ".xp", "apps", app)
	// 1) manifest.json::loops[]
	if loops, err := readManifestLoops(filepath.Join(appDir, "manifest.json")); err == nil {
		for _, L := range loops {
			if L.Name == loop {
				p, ts := latestCycleDir(appDir, loop)
				return L, p, ts
			}
		}
	}
	// 2) xpcloud.yaml::loops[]
	if loops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
		for _, L := range loops {
			if L.Name == loop {
				p, ts := latestCycleDir(appDir, loop)
				return L, p, ts
			}
		}
	}
	// 3) autoresearch.yaml — single-loop apps
	if rl, err := readAutoresearchYamlFull(filepath.Join(appDir, "autoresearch.yaml")); err == nil && rl.Name == loop {
		p, ts := latestCycleDir(appDir, loop)
		return rl, p, ts
	}
	return rawLoop{}, "", ""
}

// readAutoresearchYamlFull is a richer read than the existing
// readAutoresearchYaml — pulls description + skills + stages.
func readAutoresearchYamlFull(p string) (rawLoop, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return rawLoop{}, err
	}
	var doc struct {
		Name        string   `yaml:"name"`
		Schedule    string   `yaml:"schedule"`
		Description string   `yaml:"description"`
		Skills      []string `yaml:"skills"`
		Stages      map[string]struct {
			Skills []string `yaml:"skills"`
		} `yaml:"stages"`
		Goal rawGoal `yaml:"goal"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return rawLoop{}, err
	}
	if doc.Name == "" {
		return rawLoop{}, errors.New("no name")
	}
	// Aggregate observe + act stage skills as the loop's effective skill list
	skills := append([]string{}, doc.Skills...)
	if obs, ok := doc.Stages["observe"]; ok {
		skills = append(skills, obs.Skills...)
	}
	if act, ok := doc.Stages["act"]; ok {
		skills = append(skills, act.Skills...)
	}
	skills = uniqStrings(skills)
	return rawLoop{
		Name:        doc.Name,
		Schedule:    doc.Schedule,
		Description: doc.Description,
		Skills:      skills,
		Goal:        doc.Goal,
	}, nil
}

func uniqStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// latestCycleDir returns (path, ts) for the newest cycle output
// under either data/cycles/<loop>/ (auto-quant/ops shape) or
// data/outbox/<case>/<ts>/ (mbb-ai shape; no per-loop subdir).
func latestCycleDir(appDir, loop string) (string, string) {
	// shape 1: data/cycles/<loop>/<ts>/
	c1 := filepath.Join(appDir, "data", "cycles", loop)
	if entries, err := os.ReadDir(c1); err == nil {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() > entries[j].Name() })
		for _, e := range entries {
			if e.IsDir() {
				return filepath.Join(c1, e.Name()), e.Name()
			}
		}
	}
	// shape 2: data/outbox/<case>/<ts>/ (mbb-ai); take newest globally.
	c2 := filepath.Join(appDir, "data", "outbox")
	type cand struct{ path, ts string }
	var newest cand
	if cases, err := os.ReadDir(c2); err == nil {
		for _, ce := range cases {
			if !ce.IsDir() {
				continue
			}
			if entries, err := os.ReadDir(filepath.Join(c2, ce.Name())); err == nil {
				for _, te := range entries {
					if te.IsDir() && te.Name() > newest.ts {
						newest = cand{filepath.Join(c2, ce.Name(), te.Name()), te.Name()}
					}
				}
			}
		}
	}
	return newest.path, newest.ts
}

func readManifestLoops(p string) ([]rawLoop, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m struct {
		Kind  string    `json:"kind"`
		Loops []rawLoop `json:"loops"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Kind == "skill" {
		return nil, nil
	}
	return m.Loops, nil
}

func readYamlLoops(p string) ([]rawLoop, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Loops []rawLoop `yaml:"loops"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Loops, nil
}

func readAutoresearchYaml(p string) (string, string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", "", err
	}
	var doc struct {
		Name     string `yaml:"name"`
		Schedule string `yaml:"schedule"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return "", "", err
	}
	if doc.Name == "" {
		return "", "", errors.New("no name in autoresearch.yaml")
	}
	return doc.Name, doc.Schedule, nil
}

func AdminLoops(c *gin.Context) {
	home := operatorHome()
	state := readSchedulerState(home)
	apps := discoverManifestLoops(home)

	now := time.Now().Unix()
	rows := make([]loopRow, 0, 16)

	for _, app := range apps {
		for _, L := range app.Loops {
			jobID := "xpio:" + app.App + ":" + L.Name
			s := state.Loops[jobID]

			row := loopRow{
				App:                 app.App,
				Loop:                L.Name,
				Schedule:            L.Schedule,
				DeclaredIn:          L.DeclaredIn,
				LastRunTS:           s.LastRunTS,
				LastOk:              s.LastOk,
				ConsecutiveFailures: s.ConsecutiveFailures,
				LastDurationSeconds: s.LastDurationSeconds,
			}

			// Hydrate the per-loop detail fields. Cheap (single file
			// reads, no LLM calls) so we ship inline rather than gating
			// on a separate /admin/loops/<id> endpoint.
			if detail, latestPath, latestTS := loadLoopDetail(home, app.App, L.Name); detail.Name != "" {
				row.Description = detail.Description
				row.PrimaryRole = detail.PrimaryRole
				row.KnowledgeAgent = detail.KnowledgeAgent
				row.Mode = detail.Mode
				row.Skills = detail.Skills
				row.Datasets = detail.Datasets
				row.GoalPrimary = detail.Goal.Primary
				row.GoalTracked = detail.Goal.Tracked
				for _, st := range detail.Steps {
					row.Steps = append(row.Steps, loopStep{
						ID: st.ID, Skill: st.Skill, KnowledgeAgent: st.KnowledgeAgent,
					})
				}
				row.LatestCycleDir = latestPath
				row.LatestCycleTS = latestTS
			}
			switch {
			case L.Schedule == "" || L.Schedule == "@trigger" || L.Schedule == "manual":
				row.Status = "manual"
			case s.LastRunTS == 0:
				row.Status = "never"
			case s.ConsecutiveFailures > 0:
				row.Status = "failing"
			case now-int64(s.LastRunTS) > 60*60*48: // >48h since last run
				row.Status = "stale"
			default:
				row.Status = "ok"
			}
			rows = append(rows, row)
		}
	}

	// Sort: app, then loop name — stable for the dashboard
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].App != rows[j].App {
			return rows[i].App < rows[j].App
		}
		return rows[i].Loop < rows[j].Loop
	})

	// Summary counts for the tile heading
	summary := map[string]int{"ok": 0, "never": 0, "failing": 0, "stale": 0, "manual": 0}
	for _, r := range rows {
		summary[r.Status]++
	}

	scheduler := "running"
	if _, err := os.Stat(filepath.Join(home, ".lumilake", "scheduler", "xpio_state.json")); errors.Is(err, fs.ErrNotExist) {
		scheduler = "not_installed"
	}

	ok(c, "ok", gin.H{
		"loops":                 rows,
		"summary":               summary,
		"scheduler_daemon":      scheduler,
		"operator_home":         home,
		"generated_at":          time.Now().UTC(),
	})
}
