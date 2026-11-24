package handler

// The experiment detail's per-arm `series`, rebuilt from the RUN STORE when the
// results ledger is unreadable.
//
// loadExperimentDetailFor reads data/experiments/<id>/results.jsonl off disk.
// That ledger is written on the SCHEDULER's volume and identity mounts no tenant
// volume, so for every cloud install the read finds identity's materialised copy
// of the published bundle — declaration, never results — and the detail served
// `series: []` while the cycles that feed the experiment were self-reporting
// into me_app_runs all along. The list endpoint already overlays me_app_runs for
// the same reason (expStateFromRuns); this does the same for the curve.
//
// Same SHAPE as the disk path — [{variant_id, points: [{ts, v}]}] — so the UI's
// SeriesChart needs no second code path. The arm comes from where the scheduler
// stamps it (sdk/apps/app_runner.py `_self_report_run`: metrics.arm +
// metrics.experiment) or, for a run that resolves several claims, from each
// command_engine.results[] entry — the two shapes runArmObservations
// (admin_app_insights.go) already counts.

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// expRunSeriesCap bounds both the rows read and the points served: the newest
// N runs, then the newest N points (a run with per-result arms yields several).
const expRunSeriesCap = 2000

// expUnlabelledArm is the label for a run that carries no arm at all — a plain
// cron cycle running the app's current configuration. "current" is the apps'
// own convention for that (the arm a run is filed under when its variant names
// none, sdk/scheduling/me_intent_picker.py). Points filed here this way carry
// `arm_inferred: true` so a reader can tell the label was not on the row.
const expUnlabelledArm = "current"

type expRunPoint struct {
	runTs    int64
	arm      string
	v        float64
	inferred bool
}

// expRunPoints extracts this experiment's (arm, value) observations from one run.
//
// A run filed under a DIFFERENT experiment is skipped: one loop can feed several
// experiments (quant-research `backtest` feeds backtest_evidence and
// backtest_performance), so loop membership alone would plot another study's
// arms here. `experiment == arm` is kept — the scheduler falls back to the U1
// alias (experiment ≡ variant id) when the lineage names no arm, so that shape
// says nothing about which study it belongs to.
func expRunPoints(r models.MeAppRun, expID, metricName string) []expRunPoint {
	if metricName == "" || r.Metrics == "" {
		return nil
	}
	var doc any
	if json.Unmarshal([]byte(r.Metrics), &doc) != nil {
		return nil
	}
	m, _ := doc.(map[string]any)
	if m == nil {
		return nil
	}
	topArm, _ := m["arm"].(string)
	topExp, _ := m["experiment"].(string)
	topArm, topExp = strings.TrimSpace(topArm), strings.TrimSpace(topExp)
	foreign := func(exp, arm string) bool { return exp != "" && exp != expID && exp != arm }

	if topArm != "" {
		if foreign(topExp, topArm) {
			return nil
		}
		if v, _ := metricFromDocPath(m, metricName); v != nil {
			return []expRunPoint{{runTs: r.RunTs, arm: topArm, v: *v}}
		}
		return nil
	}

	// Per-result arms (command_engine.results[]). Each entry's value is read
	// from INSIDE that entry: the run-level blob holds one number for N arms.
	ce, _ := m["command_engine"].(map[string]any)
	results, _ := ce["results"].([]any)
	var pts []expRunPoint
	armedHere := false
	for _, it := range results {
		rm, _ := it.(map[string]any)
		arm, _ := rm["arm"].(string)
		arm = strings.TrimSpace(arm)
		if arm == "" {
			continue
		}
		exp, _ := rm["experiment"].(string)
		if foreign(strings.TrimSpace(exp), arm) {
			continue
		}
		armedHere = true
		if v, _ := metricFromDocPath(rm, metricName); v != nil {
			pts = append(pts, expRunPoint{runTs: r.RunTs, arm: arm, v: *v})
		}
	}
	if armedHere {
		// This run reported its arms for this experiment; never also file its
		// run-level number under an inferred label.
		return pts
	}

	if topExp != "" && topExp != expID {
		return nil
	}
	if v, _ := metricFromDocPath(m, metricName); v != nil {
		return []expRunPoint{{runTs: r.RunTs, arm: expUnlabelledArm, v: *v, inferred: true}}
	}
	return nil
}

// expSeriesFromRuns groups run-store observations into the detail's series
// shape. `runs` may arrive in any order; points come out oldest-first per arm,
// arms sorted by id (as the disk path sorts them). Keeps the newest capN points.
func expSeriesFromRuns(runs []models.MeAppRun, expID, metricName string, capN int) ([]gin.H, int) {
	var all []expRunPoint
	for _, r := range runs {
		all = append(all, expRunPoints(r, expID, metricName)...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].runTs < all[j].runTs })
	total := len(all)
	if capN > 0 && len(all) > capN {
		all = all[len(all)-capN:]
	}
	by := map[string][]gin.H{}
	inferred := map[string]bool{}
	for _, p := range all {
		pt := gin.H{"ts": time.Unix(p.runTs, 0).UTC().Format(time.RFC3339), "v": p.v}
		if p.inferred {
			pt["arm_inferred"] = true
			inferred[p.arm] = true
		}
		by[p.arm] = append(by[p.arm], pt)
	}
	series := make([]gin.H, 0, len(by))
	for arm, pts := range by {
		s := gin.H{"variant_id": arm, "points": pts}
		if inferred[arm] {
			s["arm_inferred"] = true
		}
		series = append(series, s)
	}
	sort.Slice(series, func(i, j int) bool {
		return series[i]["variant_id"].(string) < series[j]["variant_id"].(string)
	})
	return series, total
}

// expRunStoreSeries reads the newest runs of the experiment's feeding loops for
// this tenant — one query on uq_apprun (user_sub, app, loop, run_ts) — and
// builds the series. `total` is the points found in the runs read; `truncated`
// is true when either cap (runs read, points kept) cut something off. (nil, 0,
// false) when there is nothing to read or no DB.
func expRunStoreSeries(userSub, app, expID, metricName string, loops []string) ([]gin.H, int, bool) {
	if userSub == "" || app == "" || metricName == "" || len(loops) == 0 || common.DB == nil {
		return nil, 0, false
	}
	var runs []models.MeAppRun
	// `loop` is a MySQL reserved word — backtick-quote. Alias-aware like
	// appRunsFor: a renamed app must not lose its history.
	if err := common.DB.Select("`loop`", "run_ts", "metrics").
		Where("user_sub = ? AND app IN ? AND `loop` IN ?", userSub, appAliases(app), loops).
		Order("run_ts DESC").Limit(expRunSeriesCap).Find(&runs).Error; err != nil {
		return nil, 0, false
	}
	series, total := expSeriesFromRuns(runs, expID, metricName, expRunSeriesCap)
	return series, total, len(runs) >= expRunSeriesCap || total > expRunSeriesCap
}
