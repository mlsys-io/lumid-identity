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
	App                  string  `json:"app"`
	Loop                 string  `json:"loop"`
	Schedule             string  `json:"schedule"`
	DeclaredIn           string  `json:"declared_in"`
	LastRunTS            float64 `json:"last_run_ts"`
	LastOk               *bool   `json:"last_ok,omitempty"`
	ConsecutiveFailures  int     `json:"consecutive_failures"`
	LastDurationSeconds  float64 `json:"last_duration_s"`
	Status               string  `json:"status"` // "never" | "ok" | "failing" | "stale"
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
	Name           string `json:"name"           yaml:"name"`
	Schedule       string `json:"schedule"       yaml:"schedule"`
	KnowledgeAgent string `json:"knowledge_agent" yaml:"knowledge_agent"`
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
