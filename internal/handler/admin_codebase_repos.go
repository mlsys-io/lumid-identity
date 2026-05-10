package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// GET /admin/codebase-repos — super-admin dashboard tile.
//
// Walks /var/lib/lumid-codebase (bind-mounted from /proj) and returns
// per-repo git status: branch, dirty count, ahead/behind vs origin,
// last-commit summary. Distinct from /admin/loops::apps[] (which
// covers the xpio app bundles under ~/.xp/apps); these are the source
// trees the platform itself is built from.
//
// Excludes /proj/deprecated/* by default (archived). Pass ?include_deprecated=1
// to surface them.
//
// Best-effort: missing or non-git dirs are simply skipped. The endpoint
// never 500s — empty list is a valid response when no repos are mounted.

// codebaseRepo is one source-tree git repo on disk.
type codebaseRepo struct {
	Path           string `json:"path"`           // mount-relative
	Name           string `json:"name"`           // last segment
	Group          string `json:"group,omitempty"` // parent dir (e.g. "quantarena")
	Branch         string `json:"branch,omitempty"`
	HeadShortSHA   string `json:"head_short_sha,omitempty"`
	HeadSubject    string `json:"head_subject,omitempty"`
	HeadAuthor     string `json:"head_author,omitempty"`
	HeadDate       string `json:"head_date,omitempty"`
	DirtyCount     int    `json:"dirty_count"`
	DirtyExample   string `json:"dirty_example,omitempty"`
	UntrackedCount int    `json:"untracked_count"`
	AheadOrigin    int    `json:"ahead_origin,omitempty"`
	BehindOrigin   int    `json:"behind_origin,omitempty"`
	HasUpstream    bool   `json:"has_upstream"`
	Deprecated     bool   `json:"deprecated,omitempty"`
	// Composite verdict for the tile:
	// "clean" | "dirty" | "ahead" | "behind" | "diverged" | "no_upstream" | "detached"
	Status         string `json:"status"`
}

// codebaseRoot is the host path /proj exposed inside the container.
// Falls back to /proj when unset (host-side use).
func codebaseRoot() string {
	if v := os.Getenv("LUMID_CODEBASE_ROOT"); v != "" {
		return v
	}
	if _, err := os.Stat("/var/lib/lumid-codebase"); err == nil {
		return "/var/lib/lumid-codebase"
	}
	return "/proj"
}

// findCodebaseRepos walks the codebase root up to maxDepth looking for
// any directory containing a .git subdir.  Returns repos sorted by
// (group, name) for stable rendering.
func findCodebaseRepos(root string, includeDeprecated bool) []string {
	var hits []string
	const maxDepth = 4
	rootDepth := strings.Count(root, string(filepath.Separator))
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Skip the .git contents themselves.
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		// Cap depth so we don't dive into node_modules etc.
		depth := strings.Count(p, string(filepath.Separator)) - rootDepth
		if d.IsDir() && depth > maxDepth {
			return filepath.SkipDir
		}
		// Filter deprecated unless asked.
		if !includeDeprecated && d.IsDir() && strings.Contains(p, "/deprecated") {
			// Skip the entire deprecated subtree
			if filepath.Base(p) == "deprecated" {
				return filepath.SkipDir
			}
		}
		if d.IsDir() {
			gitDir := filepath.Join(p, ".git")
			if st, gerr := os.Stat(gitDir); gerr == nil && st.IsDir() {
				hits = append(hits, p)
				return filepath.SkipDir // don't descend into a repo
			}
		}
		return nil
	})
	sort.Strings(hits)
	return hits
}

func gitOut(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_OPTIONAL_LOCKS=0",
		// Bind-mounted as :ro so the operator's UID may differ; trust
		// the path so git doesn't bail with "dubious ownership".
		"GIT_CONFIG_GLOBAL=/dev/null",
	)
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n"), nil
}

func loadCodebaseRepo(root, repoPath string) codebaseRepo {
	rel := strings.TrimPrefix(repoPath, root)
	rel = strings.TrimPrefix(rel, "/")
	r := codebaseRepo{
		Path:       rel,
		Name:       filepath.Base(repoPath),
		Deprecated: strings.HasPrefix(rel, "deprecated/"),
		Status:     "clean",
	}
	if parent := filepath.Dir(rel); parent != "." && parent != "" {
		r.Group = parent
	}
	// 'safe.directory' workaround for bind-mounted readonly trees.
	if _, err := gitOut(repoPath, "-c", "safe.directory=*", "rev-parse", "--is-inside-work-tree"); err != nil {
		r.Status = "no_git"
		return r
	}
	// Branch (or DETACHED)
	if br, err := gitOut(repoPath, "-c", "safe.directory=*", "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		r.Branch = br
	}
	if r.Branch == "HEAD" {
		r.Status = "detached"
	}
	// HEAD short sha + subject + author + date
	if line, err := gitOut(repoPath, "-c", "safe.directory=*", "log", "-1", "--pretty=%h%x09%s%x09%an%x09%cI"); err == nil && line != "" {
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) >= 1 {
			r.HeadShortSHA = parts[0]
		}
		if len(parts) >= 2 {
			r.HeadSubject = parts[1]
		}
		if len(parts) >= 3 {
			r.HeadAuthor = parts[2]
		}
		if len(parts) >= 4 {
			r.HeadDate = parts[3]
		}
	}
	// Dirty count + first dirty example. Two-letter status prefix +
	// space + path; untracked rows start with "??".
	if porc, err := gitOut(repoPath, "-c", "safe.directory=*", "status", "--porcelain"); err == nil && porc != "" {
		lines := strings.Split(porc, "\n")
		for _, ln := range lines {
			if len(ln) < 3 {
				continue
			}
			if strings.HasPrefix(ln, "??") {
				r.UntrackedCount++
			} else {
				r.DirtyCount++
			}
			if r.DirtyExample == "" {
				r.DirtyExample = strings.TrimSpace(ln[3:])
			}
		}
	}
	// Upstream ahead/behind. `@{upstream}` 404s when the branch has
	// none (a brand-new branch never pushed). HasUpstream tracks that
	// case so the UI can show "no upstream" instead of "0 ahead 0 behind".
	if br, err := gitOut(repoPath, "-c", "safe.directory=*", "rev-parse", "--abbrev-ref", "@{upstream}"); err == nil && br != "" {
		r.HasUpstream = true
		if line, err := gitOut(repoPath, "-c", "safe.directory=*", "rev-list", "--left-right", "--count", "@{upstream}...HEAD"); err == nil {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				if n, err := parseInt(parts[1]); err == nil {
					r.AheadOrigin = n
				}
				if n, err := parseInt(parts[0]); err == nil {
					r.BehindOrigin = n
				}
			}
		}
	}
	switch {
	case r.Status == "no_git" || r.Status == "detached":
		// keep
	case !r.HasUpstream:
		r.Status = "no_upstream"
	case r.DirtyCount > 0 || r.UntrackedCount > 0:
		r.Status = "dirty"
	case r.AheadOrigin > 0 && r.BehindOrigin > 0:
		r.Status = "diverged"
	case r.AheadOrigin > 0:
		r.Status = "ahead"
	case r.BehindOrigin > 0:
		r.Status = "behind"
	default:
		r.Status = "clean"
	}
	return r
}

func AdminCodebaseRepos(c *gin.Context) {
	includeDeprecated := c.Query("include_deprecated") == "1"
	root := codebaseRoot()
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		ok(c, "ok", gin.H{
			"root":  root,
			"repos": []codebaseRepo{},
			"summary": gin.H{
				"clean": 0, "dirty": 0, "ahead": 0, "behind": 0, "diverged": 0, "no_upstream": 0,
			},
			"generated_at": time.Now().UTC(),
			"warning":      "codebase root not mounted; expected /proj at /var/lib/lumid-codebase",
		})
		return
	}

	paths := findCodebaseRepos(root, includeDeprecated)
	repos := make([]codebaseRepo, 0, len(paths))
	for _, p := range paths {
		repos = append(repos, loadCodebaseRepo(root, p))
	}

	summary := map[string]int{
		"clean": 0, "dirty": 0, "ahead": 0, "behind": 0,
		"diverged": 0, "no_upstream": 0, "detached": 0, "no_git": 0,
	}
	for _, r := range repos {
		summary[r.Status]++
	}

	// Stable ordering: top-level repos first (no group), then grouped.
	sort.SliceStable(repos, func(i, j int) bool {
		if repos[i].Group != repos[j].Group {
			return repos[i].Group < repos[j].Group
		}
		return repos[i].Name < repos[j].Name
	})

	body, _ := json.Marshal(repos)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/json", []byte(`{"ret_code":0,"message":"ok","data":{"root":"`+root+`","repos":`+string(body)+`,"summary":`+func() string {
		b, _ := json.Marshal(summary)
		return string(b)
	}()+`,"generated_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}}`))
}
