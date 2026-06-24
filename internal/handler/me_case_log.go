// me_case_log.go — GET /api/v1/me/apps/:app/casebook/case-log?loop=&case_id=
//
// The data↔metric mapping is what a workflow produces ON a case: an AI
// labeling/scoring of that case, and the metric computed on it. This returns
// the LOG of those mappings for one case — every scoring record the loop's
// experiments wrote for it (per run / per cycle / per sub-question), newest
// first. Metrics are strictly bound to the loop (loopExperiments); the case
// (data) is shared, the records (metrics) are the workflow's.
package handler

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

type caseLogRecord struct {
	Ts         string         `json:"ts"`
	CycleTs    string         `json:"cycle_ts,omitempty"`
	VariantID  string         `json:"variant_id,omitempty"`
	Experiment string         `json:"experiment,omitempty"`
	Metrics    map[string]any `json:"metrics,omitempty"`
	Dims       map[string]any `json:"dims,omitempty"`
}

func MeCaseLog(c *gin.Context) {
	userID, okAuth := currentUserID(c)
	if !okAuth {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	loop := c.Query("loop")
	caseID := c.Query("case_id")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	if loop != "" && !slugRe.MatchString(loop) {
		fail(c, http.StatusBadRequest, 1400, "invalid loop")
		return
	}
	if caseID == "" {
		fail(c, http.StatusBadRequest, 1400, "missing case_id")
		return
	}
	appDir := resolveAppDir(userID, app)
	if appDir == "" {
		fail(c, http.StatusNotFound, 1404, "app not found")
		return
	}

	// Strict metrics→workflow: only the loop's declared experiments.
	allow := map[string]bool{}
	for _, x := range loopExperiments(appDir, loop) {
		allow[x] = true
	}
	strict := loop != ""

	records := []caseLogRecord{}
	if !(strict && len(allow) == 0) {
		// Resolve the experiments root through the runtime-path mapper, like
		// every other experiments reader (me_casebook / me_trajectory): it
		// prefers the canonical .lumid/experiments (post dotfile-migration)
		// and falls back to legacy data/experiments, across both bundle-root
		// candidates (agents/<name> then apps/<name>). Reading the raw
		// data/experiments path directly was the "No mapping records yet" bug —
		// migrated apps (mbb-ai, etc.) keep their results under .lumid/ where
		// this handler never looked.
		expRoot, _ := ResolveRuntimeReadPath(appDir, "data/experiments")
		if ents, err := os.ReadDir(expRoot); err == nil {
			for _, e := range ents {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				if strict && !allow[e.Name()] {
					continue
				}
				f, err := os.Open(filepath.Join(expRoot, e.Name(), "results.jsonl"))
				if err != nil {
					continue
				}
				sc := bufio.NewScanner(f)
				sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" {
						continue
					}
					var row map[string]any
					if json.Unmarshal([]byte(line), &row) != nil {
						continue
					}
					dims, _ := row["dims"].(map[string]any)
					if dims == nil { // U1: `item` mirrors `dims`
						dims, _ = row["item"].(map[string]any)
					}
					cid := ""
					if dims != nil {
						if s, ok := dims["case_id"].(string); ok {
							cid = s
						}
					}
					if cid != caseID {
						continue
					}
					rec := caseLogRecord{Experiment: e.Name(), Dims: dims}
					if s, ok := row["ts"].(string); ok {
						rec.Ts = s
					}
					if s, ok := row["cycle_ts"].(string); ok {
						rec.CycleTs = s
					}
					if s, ok := row["variant_id"].(string); ok {
						rec.VariantID = s
					}
					if m, ok := row["metrics"].(map[string]any); ok {
						rec.Metrics = m
					}
					records = append(records, rec)
				}
				f.Close()
			}
		}
	}

	// Newest first (by cycle_ts then ts).
	sort.Slice(records, func(i, j int) bool {
		ki := records[i].CycleTs + records[i].Ts
		kj := records[j].CycleTs + records[j].Ts
		return ki > kj
	})
	if len(records) > 200 {
		records = records[:200]
	}
	ok(c, "ok", gin.H{"app": app, "loop": loop, "case_id": caseID, "records": records, "count": len(records)})
}
