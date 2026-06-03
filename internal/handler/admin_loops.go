package handler

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
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
	// Failing-loop diagnostics — populated only when the loop's last
	// run errored. ``last_errors`` reads step_errors.json from the
	// most recent cycle dir; ``last_journal`` is the trailing entry of
	// journal.jsonl when the app keeps one (useful when the cycle
	// errored before reaching the per-step wrapper).
	LastErrors           []loopErrorRow `json:"last_errors,omitempty"`
	LastJournal          string         `json:"last_journal,omitempty"`
	// Engine pattern (Pattern A = runner_steps, Pattern B = command).
	// When command-driven, EngineModule names the verb the runner
	// dispatches into; SkillsInvoked is the documentation list of
	// what the verb actually calls.
	Engine               string         `json:"engine,omitempty"`
	EngineModule         string         `json:"engine_module,omitempty"`
	SkillsInvoked        []string       `json:"skills_invoked,omitempty"`
	// Cycle outcome — hydrated from score.json / insight.md / proposal.json
	// in the latest cycle dir. Present when any of those files exist.
	Outcome              *loopOutcome   `json:"outcome,omitempty"`
}

// loopOutcome surfaces the most recent cycle's key metrics so the
// dashboard tile can show α / benchmark / sharpe without the operator
// drilling into a cycle dir.
type loopOutcome struct {
	AlphaPP      *float64 `json:"alpha_pp,omitempty"`      // realized_alpha_pp from score.json
	Benchmark    string   `json:"benchmark,omitempty"`     // benchmark_label from score.json
	Sharpe       *float64 `json:"sharpe,omitempty"`        // sharpe from score.json
	MaxDD        *float64 `json:"max_dd,omitempty"`        // max_dd from score.json
	InsightHead  string   `json:"insight_head,omitempty"`  // first 5 lines of insight.md
	LastProposal *loopProposal `json:"last_proposal,omitempty"` // from proposal.json

	// Trading-cycle metrics derived from trades.json. Optional — observer
	// loops (regime_detector, competitor_observer) skip act/execute and
	// produce no trades.
	TradesCount    *int     `json:"trades_count,omitempty"`     // # of trades placed this cycle
	PnL            *float64 `json:"pnl,omitempty"`              // sum of per-trade pnl
	WinRate        *float64 `json:"win_rate,omitempty"`         // wins / total (0..1)
	MaxLoss        *float64 `json:"max_single_trade_loss,omitempty"`

	// Downstream jobs submitted during this cycle. Populated by scanning
	// ~/.lumilake/jobs.jsonl for rows tagged with this loop's name.
	// Empty for loops that don't use the submit_jobs path.
	DownstreamJobs []cycleJobRef `json:"downstream_jobs,omitempty"`
}

type loopProposal struct {
	Strategy  string  `json:"strategy,omitempty"`
	Symbol    string  `json:"symbol,omitempty"`
	Direction string  `json:"direction,omitempty"`
	SizePctNAV float64 `json:"size_pct_nav,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
}

// cycleJobRef is a slim pointer to a job in the unified ledger. The UI
// uses {job_id, source, state} to render a chip and link to
// /dashboard/jobs?submitter_loop=<loop>.
type cycleJobRef struct {
	JobID  string `json:"job_id"`
	Source string `json:"source"`
	Kind   string `json:"kind,omitempty"`
	State  string `json:"state"`
}

type loopStep struct {
	ID             string `json:"id"`
	Skill          string `json:"skill"`
	KnowledgeAgent string `json:"knowledge_agent,omitempty"`
}

// loopErrorRow mirrors one entry of step_errors.json — the runner
// records {step, skill, error}. We pass through verbatim so the UI
// can decide how to truncate.
type loopErrorRow struct {
	Step  string `json:"step,omitempty"`
	Skill string `json:"skill,omitempty"`
	Error string `json:"error"`
}

// strategyState is one entry from ~/.xp/apps/<app>/data/strategies/*/state.json
// (Theme I — strategy-grid-first layout). Fields map 1:1 with what the
// auto-quant runner writes after each cycle.
type strategyState struct {
	Name           string  `json:"name"`
	LifecycleStage string  `json:"lifecycle_stage,omitempty"` // smoke_test|explore|paper|semi|live|retired
	CycleCount     int     `json:"cycle_count,omitempty"`
	RecentSharpe   *float64 `json:"recent_sharpe,omitempty"`
	LifetimePnL    *float64 `json:"lifetime_pnl,omitempty"`
}

// appGitStatus is the per-app repo state surfaced on the dashboard.
// Combines local checkout state with the xp.io-published metadata so
// the operator can spot drift (uncommitted edits, unpublished version
// bumps, branch ahead/behind) without dropping into a shell.
type appGitStatus struct {
	App           string `json:"app"`
	Version       string `json:"version,omitempty"`
	Kind          string `json:"kind,omitempty"`
	Published     bool   `json:"published"`
	PublishedSlug string `json:"published_slug,omitempty"`
	// Local-checkout state (best-effort — not all app dirs are git repos)
	LocalHasGit       bool   `json:"local_has_git"`
	LocalDirtyCount   int    `json:"local_dirty_count"`
	LocalDirtyExample string `json:"local_dirty_example,omitempty"`
	LocalAheadOrigin  int    `json:"local_ahead_origin,omitempty"`
	LocalBehindOrigin int    `json:"local_behind_origin,omitempty"`
	LocalHEAD         string `json:"local_head,omitempty"`
	LocalBranch       string `json:"local_branch,omitempty"`
	// xp.io-published HEAD (only set when the app has been published)
	RemoteHEAD string `json:"remote_head,omitempty"`
	// summary verdict the dashboard renders inline:
	// "in_sync" | "dirty" | "ahead" | "behind" | "unpublished" | "no_git"
	Status string `json:"status"`
	// Strategies — per-strategy lifecycle state from data/strategies/*/state.json
	// (Theme I). Only populated for apps that have this directory.
	Strategies []strategyState `json:"strategies,omitempty"`
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
		// Fallback: walk the three config files. Order is load-bearing —
		// xpcloud.yaml is the canonical runtime source (per the xpio
		// autoresearch contract at docs/architecture/xpio_autoresearch_canonical.md);
		// manifest.json is a secondary mirror. We read xpcloud.yaml FIRST
		// so its schedule wins when both files declare the same loop.
		idx.App = e.Name()
		// xpcloud.yaml::loops[] (canonical)
		if yamlLoops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
			for _, L := range yamlLoops {
				idx.Loops = append(idx.Loops, struct {
					Name           string `json:"name"`
					Schedule       string `json:"schedule"`
					DeclaredIn     string `json:"declared_in"`
					KnowledgeAgent string `json:"knowledge_agent"`
				}{Name: L.Name, Schedule: L.Schedule, DeclaredIn: "xpcloud.yaml", KnowledgeAgent: L.KnowledgeAgent})
			}
		}
		// manifest.json::loops[] (legacy mirror — only fills in loops xpcloud.yaml didn't declare)
		if seenNames := loopNames(idx.Loops); true {
			if mf, err := readManifestLoops(filepath.Join(appDir, "manifest.json")); err == nil {
				for _, L := range mf {
					if _, dup := seenNames[L.Name]; dup {
						continue
					}
					idx.Loops = append(idx.Loops, struct {
						Name           string `json:"name"`
						Schedule       string `json:"schedule"`
						DeclaredIn     string `json:"declared_in"`
						KnowledgeAgent string `json:"knowledge_agent"`
					}{Name: L.Name, Schedule: L.Schedule, DeclaredIn: "manifest.json", KnowledgeAgent: L.KnowledgeAgent})
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
	SkillsInvoked  []string   `json:"skills_invoked"  yaml:"skills_invoked"`
	Datasets       []string   `json:"datasets"        yaml:"datasets"`
	Steps          []rawStep  `json:"steps"           yaml:"steps"`
	Engine         rawEngine  `json:"engine"          yaml:"engine"`
	Goal           rawGoal    `json:"goal"            yaml:"goal"`
}

type rawEngine struct {
	Type   string `json:"type"   yaml:"type"`
	Module string `json:"module" yaml:"module"`
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
//   xpcloud.yaml::loops[name=loop]    (canonical runtime source)
//   manifest.json::loops[name=loop]   (legacy mirror)
//   autoresearch.yaml                  (ops/xpio-ops single-loop shape)
// Also resolves the most recent cycle dir under data/cycles/<loop>/<ts>/
// or data/outbox/<case>/<ts>/ when present.
func loadLoopDetail(home, app, loop string) (rawLoop, string, string) {
	appDir := filepath.Join(home, ".xp", "apps", app)
	// 1) xpcloud.yaml::loops[] — canonical runtime source. Read first
	//    so its schedule + steps + skills_invoked beat any stale
	//    manifest.json mirror.
	if loops, err := readYamlLoops(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
		for _, L := range loops {
			if L.Name == loop {
				p, ts := latestCycleDir(appDir, loop)
				return L, p, ts
			}
		}
	}
	// 2) manifest.json::loops[] — fallback only.
	if loops, err := readManifestLoops(filepath.Join(appDir, "manifest.json")); err == nil {
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

// loadLastErrors reads step_errors.json from a cycle dir + the trailing
// journal entry. Either may be absent — the dashboard renders whichever
// one we manage to surface.
func loadLastErrors(cycleDir, appDir string) ([]loopErrorRow, string) {
	var errs []loopErrorRow
	if cycleDir != "" {
		if b, err := os.ReadFile(filepath.Join(cycleDir, "step_errors.json")); err == nil {
			var raw []loopErrorRow
			if json.Unmarshal(b, &raw) == nil {
				errs = raw
			}
		}
	}
	// journal.jsonl is the runner's append-only event log; the last
	// line typically captures pre-step failures (no setup, missing
	// loop, invalid mode) that don't reach step_errors.json. Apps
	// keep it under either ``journal.jsonl`` (top-level) or
	// ``data/journal.jsonl`` — try both and pick the newest.
	journalTail := ""
	for _, jp := range []string{
		filepath.Join(appDir, "data", "journal.jsonl"),
		filepath.Join(appDir, "journal.jsonl"),
	} {
		b, err := os.ReadFile(jp)
		if err != nil || len(b) == 0 {
			continue
		}
		lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		tail := lines[len(lines)-1]
		if len(tail) > 800 {
			tail = tail[:800] + "…"
		}
		journalTail = tail
		break
	}
	return errs, journalTail
}

// loadCycleOutcome reads the outcome artifacts from the latest cycle dir.
// All fields are optional — whichever files exist are returned.
func loadCycleOutcome(cycleDir string) *loopOutcome {
	if cycleDir == "" {
		return nil
	}
	out := &loopOutcome{}
	found := false

	// score.json — {realized_alpha_pp, benchmark_label, sharpe, max_dd}
	if b, err := os.ReadFile(filepath.Join(cycleDir, "score.json")); err == nil {
		var score struct {
			RealizedAlphaPP *float64 `json:"realized_alpha_pp"`
			BenchmarkLabel  string   `json:"benchmark_label"`
			Sharpe          *float64 `json:"sharpe"`
			MaxDD           *float64 `json:"max_dd"`
		}
		if json.Unmarshal(b, &score) == nil {
			out.AlphaPP = score.RealizedAlphaPP
			out.Benchmark = score.BenchmarkLabel
			out.Sharpe = score.Sharpe
			out.MaxDD = score.MaxDD
			found = true
		}
	}

	// insight.md — first 5 lines
	if b, err := os.ReadFile(filepath.Join(cycleDir, "insight.md")); err == nil {
		lines := strings.SplitN(string(b), "\n", 7)
		nLines := 5
		if len(lines) < nLines {
			nLines = len(lines)
		}
		head := strings.TrimSpace(strings.Join(lines[:nLines], "\n"))
		if head != "" {
			out.InsightHead = head
			found = true
		}
	}

	// proposal.json — {strategy, symbol, direction, size_pct_nav, confidence}
	if b, err := os.ReadFile(filepath.Join(cycleDir, "proposal.json")); err == nil {
		var p loopProposal
		if json.Unmarshal(b, &p) == nil && (p.Strategy != "" || p.Symbol != "") {
			out.LastProposal = &p
			found = true
		}
	}

	// trades.json — array of per-trade records. Schema varies by loop
	// (auto-quant's place_order writes {symbol, side, qty, fill_price,
	// pnl}); we tolerate missing fields and only surface aggregates when
	// the file actually has trades.
	if b, err := os.ReadFile(filepath.Join(cycleDir, "trades.json")); err == nil {
		var trades []struct {
			PnL    *float64 `json:"pnl,omitempty"`
			Profit *float64 `json:"profit,omitempty"` // alternate field name
		}
		if json.Unmarshal(b, &trades) == nil && len(trades) > 0 {
			n := len(trades)
			out.TradesCount = &n
			var sum, worst float64
			wins, hasPnl := 0, 0
			worstSet := false
			for _, t := range trades {
				p := t.PnL
				if p == nil {
					p = t.Profit
				}
				if p == nil {
					continue
				}
				hasPnl++
				sum += *p
				if *p > 0 {
					wins++
				}
				if !worstSet || *p < worst {
					worst = *p
					worstSet = true
				}
			}
			if hasPnl > 0 {
				out.PnL = &sum
				wr := float64(wins) / float64(hasPnl)
				out.WinRate = &wr
				if worstSet {
					out.MaxLoss = &worst
				}
			}
			found = true
		}
	}

	if !found {
		return nil
	}
	return out
}

// loadDownstreamJobs scans ~/.lumilake/jobs.jsonl for jobs submitted by
// the given (app, loop) pair. Read-only and cheap — bounded ledger.
// Returns the newest 10 (UI shows at most a few chips per cycle row).
func loadDownstreamJobs(app, loop string) []cycleJobRef {
	if app == "" || loop == "" {
		return nil
	}
	path := ledgerPath() // shared helper from jobs.go
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	type slimRow struct {
		JobID         string  `json:"job_id"`
		Source        string  `json:"source"`
		Kind          string  `json:"kind"`
		State         string  `json:"state"`
		SubmitterApp  string  `json:"submitter_app"`
		SubmitterLoop string  `json:"submitter_loop"`
		UpdatedAt     float64 `json:"updated_at"`
		StartedAt     float64 `json:"started_at"`
	}
	var matches []slimRow
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r slimRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if r.SubmitterApp != app || r.SubmitterLoop != loop {
			continue
		}
		matches = append(matches, r)
	}
	if len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, b := matches[i].UpdatedAt, matches[j].UpdatedAt
		if a == 0 {
			a = matches[i].StartedAt
		}
		if b == 0 {
			b = matches[j].StartedAt
		}
		return a > b
	})
	if len(matches) > 10 {
		matches = matches[:10]
	}
	out := make([]cycleJobRef, 0, len(matches))
	for _, m := range matches {
		out = append(out, cycleJobRef{JobID: m.JobID, Source: m.Source, Kind: m.Kind, State: m.State})
	}
	return out
}

// loadAppStrategies reads ~/.xp/apps/<app>/data/strategies/*/state.json
// and returns the lifecycle state for each strategy that has one.
// Returns nil when the directory doesn't exist (most apps don't use it).
func loadAppStrategies(home, app string) []strategyState {
	dir := filepath.Join(home, ".xp", "apps", app, "data", "strategies")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []strategyState
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		stateFile := filepath.Join(dir, e.Name(), "state.json")
		b, err := os.ReadFile(stateFile)
		if err != nil {
			continue
		}
		var s strategyState
		if json.Unmarshal(b, &s) == nil {
			if s.Name == "" {
				s.Name = e.Name()
			}
			out = append(out, s)
		}
	}
	return out
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

// readYamlLoopGoals returns loop-name → goal from xpcloud.yaml using a MINIMAL
// struct that ignores every other loop field. readYamlLoops unmarshals the
// full rawLoop and errors out when a loop carries object-typed datasets/
// skills_invoked (then me_workflows falls back to manifest.json, which has no
// goal) — this tolerant reader recovers the goal regardless.
func readYamlLoopGoals(p string) map[string]rawGoal {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var doc struct {
		Loops []struct {
			Name string  `yaml:"name"`
			Goal rawGoal `yaml:"goal"`
		} `yaml:"loops"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		return nil
	}
	out := map[string]rawGoal{}
	for _, l := range doc.Loops {
		if l.Name != "" && (l.Goal.Primary != "" || len(l.Goal.Tracked) > 0) {
			out[l.Name] = l.Goal
		}
	}
	return out
}

// readYamlMemoryAgents returns the app's knowledge agents — the top-level
// memory_agents list unioned with roles[].memory_agent — from xpcloud.yaml.
func readYamlMemoryAgents(p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var doc struct {
		MemoryAgents []string `yaml:"memory_agents"`
		Roles        []struct {
			MemoryAgent string `yaml:"memory_agent"`
		} `yaml:"roles"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range doc.MemoryAgents {
		if a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, r := range doc.Roles {
		if r.MemoryAgent != "" && !seen[r.MemoryAgent] {
			seen[r.MemoryAgent] = true
			out = append(out, r.MemoryAgent)
		}
	}
	return out
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

// loadAppGitStatus inspects one app dir on disk plus the matching
// xpcloud repo metadata. Cheap (3-5 small file reads + maybe one
// `git status --porcelain` invocation) so we ship inline with the
// loops response.
func loadAppGitStatus(home, app string) appGitStatus {
	out := appGitStatus{App: app, Status: "no_git"}
	appDir := filepath.Join(home, ".xp", "apps", app)
	// version + kind from manifest.json (preferred) or xpcloud.yaml
	if b, err := os.ReadFile(filepath.Join(appDir, "manifest.json")); err == nil {
		var m struct {
			Version string `json:"version"`
			Kind    string `json:"kind"`
		}
		if json.Unmarshal(b, &m) == nil {
			out.Version = m.Version
			out.Kind = m.Kind
		}
	}
	if out.Kind == "" {
		if b, err := os.ReadFile(filepath.Join(appDir, "xpcloud.yaml")); err == nil {
			var m struct {
				Kind    string `yaml:"kind"`
				Version string `yaml:"version"`
			}
			if yaml.Unmarshal(b, &m) == nil {
				if out.Kind == "" {
					out.Kind = m.Kind
				}
				if out.Version == "" {
					out.Version = m.Version
				}
			}
		}
	}
	// origin.json carries owner_sub + slug when the app was installed
	// from xpcloud. Newly-published-but-not-reinstalled apps may have
	// a different shape; fall back to the operator's PAT subject.
	publishedSlug := ""
	if b, err := os.ReadFile(filepath.Join(appDir, "origin.json")); err == nil {
		var o struct {
			Slug    string `json:"slug"`
			Owner   string `json:"owner_sub"`
			Name    string `json:"name"`
		}
		if json.Unmarshal(b, &o) == nil {
			if o.Slug != "" {
				publishedSlug = o.Slug
			} else if o.Owner != "" && o.Name != "" {
				publishedSlug = o.Owner + "/" + o.Name
			}
		}
	}
	out.PublishedSlug = publishedSlug
	if publishedSlug != "" {
		out.Published = true
		out.Status = "in_sync" // optimistic; refined below
	} else {
		out.Status = "unpublished"
	}

	// Local git inspection — opt-in: only when .git exists. Most app
	// dirs are plain checkouts, not full git repos, so this is a soft
	// "yes, additionally show drift if git is wired up" path.
	if _, err := os.Stat(filepath.Join(appDir, ".git")); err == nil {
		out.LocalHasGit = true
		// HEAD sha
		if b, err := exec.Command("git", "-C", appDir, "rev-parse", "HEAD").Output(); err == nil {
			out.LocalHEAD = strings.TrimSpace(string(b))
		}
		// branch
		if b, err := exec.Command("git", "-C", appDir, "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
			out.LocalBranch = strings.TrimSpace(string(b))
		}
		// dirty count + first dirty path (so the UI can show "5 dirty (commands/foo.py + 4 more)")
		if b, err := exec.Command("git", "-C", appDir, "status", "--porcelain").Output(); err == nil {
			lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
			if len(lines) > 0 && lines[0] != "" {
				out.LocalDirtyCount = len(lines)
				// First entry's path (skip the 2-char status prefix + space)
				if len(lines[0]) > 3 {
					out.LocalDirtyExample = strings.TrimSpace(lines[0][3:])
				}
			}
		}
		// ahead/behind vs origin/<branch>
		if out.LocalBranch != "" {
			ref := "origin/" + out.LocalBranch
			if b, err := exec.Command("git", "-C", appDir, "rev-list", "--left-right", "--count", out.LocalBranch+"..."+ref).Output(); err == nil {
				parts := strings.Fields(strings.TrimSpace(string(b)))
				if len(parts) == 2 {
					if n, err := parseInt(parts[0]); err == nil {
						out.LocalAheadOrigin = n
					}
					if n, err := parseInt(parts[1]); err == nil {
						out.LocalBehindOrigin = n
					}
				}
			}
		}
	}

	// xpcloud-side HEAD via /repos/{slug}/branches — the call is
	// in-cluster and authless for public repos.
	if out.Published {
		owner, name := splitSlug(publishedSlug)
		if owner != "" && name != "" {
			if branches := xpcloudBranches(owner, name); len(branches) > 0 {
				for _, br := range branches {
					if br.IsDefault || br.Name == "main" {
						out.RemoteHEAD = br.SHA
						break
					}
				}
				if out.RemoteHEAD == "" {
					out.RemoteHEAD = branches[0].SHA
				}
			}
		}
	}

	// Refine the verdict.
	switch {
	case !out.Published:
		out.Status = "unpublished"
	case out.LocalDirtyCount > 0:
		out.Status = "dirty"
	case out.LocalAheadOrigin > 0:
		out.Status = "ahead"
	case out.LocalBehindOrigin > 0:
		out.Status = "behind"
	case out.LocalHEAD != "" && out.RemoteHEAD != "" && out.LocalHEAD != out.RemoteHEAD:
		out.Status = "drift"
	}

	// Strategy lifecycle states (Theme I) — best-effort; most apps won't
	// have this directory.
	if strats := loadAppStrategies(home, app); len(strats) > 0 {
		out.Strategies = strats
	}
	return out
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("non-digit")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func splitSlug(s string) (owner, name string) {
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", ""
}

type xpcloudBranch struct {
	Name      string `json:"name"`
	SHA       string `json:"sha"`
	IsDefault bool   `json:"is_default"`
}

func xpcloudBranches(owner, name string) []xpcloudBranch {
	url := xpcloudBaseURL() + "/api/v1/repos/" + owner + "/" + name + "/branches"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var doc struct {
		Branches []xpcloudBranch `json:"branches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil
	}
	return doc.Branches
}

func xpcloudBaseURL() string {
	if v := os.Getenv("XPCLOUD_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://host.docker.internal:8900"
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
				row.SkillsInvoked = detail.SkillsInvoked
				row.Datasets = detail.Datasets
				row.GoalPrimary = detail.Goal.Primary
				row.GoalTracked = detail.Goal.Tracked
				if detail.Engine.Type != "" {
					row.Engine = detail.Engine.Type
					row.EngineModule = detail.Engine.Module
				} else {
					row.Engine = "runner_steps"
				}
				for _, st := range detail.Steps {
					row.Steps = append(row.Steps, loopStep{
						ID: st.ID, Skill: st.Skill, KnowledgeAgent: st.KnowledgeAgent,
					})
				}
				row.LatestCycleDir = latestPath
				row.LatestCycleTS = latestTS
				// Cycle outcome — score.json + insight.md + proposal.json + trades.json
				row.Outcome = loadCycleOutcome(latestPath)
				// Downstream jobs the loop dispatched (submit_jobs path).
				// Attach even when there's no other outcome so loops that
				// only fire jobs still surface them.
				if dj := loadDownstreamJobs(app.App, L.Name); len(dj) > 0 {
					if row.Outcome == nil {
						row.Outcome = &loopOutcome{}
					}
					row.Outcome.DownstreamJobs = dj
				}
				// When the daemon flagged this loop as failing, hydrate
				// the diagnostic fields. Cheap (file reads) so we ship
				// inline. Skip on success to keep the response slim.
				if s.LastOk != nil && !*s.LastOk {
					appDir := filepath.Join(home, ".xp", "apps", app.App)
					row.LastErrors, row.LastJournal = loadLastErrors(latestPath, appDir)
				}
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

	// Per-app git status — one entry per unique app referenced by any
	// loop. The dashboard pivots loops by app, so this is the natural
	// shape for "git status per repo".
	seenApps := map[string]struct{}{}
	apps_status := make([]appGitStatus, 0, len(apps))
	for _, app := range apps {
		if _, dup := seenApps[app.App]; dup {
			continue
		}
		seenApps[app.App] = struct{}{}
		apps_status = append(apps_status, loadAppGitStatus(home, app.App))
	}
	sort.Slice(apps_status, func(i, j int) bool {
		return apps_status[i].App < apps_status[j].App
	})

	ok(c, "ok", gin.H{
		"loops":                 rows,
		"apps":                  apps_status,
		"summary":               summary,
		"scheduler_daemon":      scheduler,
		"operator_home":         home,
		"generated_at":          time.Now().UTC(),
	})
}
