package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// readOnlyAppDataTools — the tools a SURFACE may invoke.
//
// Deliberately an allowlist, not a "tool is read-only" flag: a surface renders
// on page load with no user intent behind it, so anything reachable here runs
// unattended every time someone opens a tab. Entries must take no arguments
// beyond the app, mutate nothing, and return data already visible to the
// caller through the chat path.
var readOnlyAppDataTools = map[string]func(userID, app string) (map[string]any, bool){
	"casebook": func(userID, app string) (map[string]any, bool) {
		return toolCasebook(userID, app, "")
	},
	// The app's own run history — every cycle, scheduled or interactive, with
	// the metrics blob each one reported. This is what a results surface reads
	// to show coverage over time, and it is deliberately the SAME record the
	// trajectory reads, so a number on a page and a node on the tree cannot
	// disagree about what happened.
	"runs": func(userID, app string) (map[string]any, bool) {
		rows := appRunsFor(userID, app, "")
		out := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			m := map[string]any{}
			if r.Metrics != "" {
				_ = json.Unmarshal([]byte(r.Metrics), &m)
			}
			row := map[string]any{
				"loop": r.Loop, "run_ts": r.RunTs, "ok": r.Ok,
				"model": r.Model, "source": r.Source,
				"duration_s": r.DurationS, "metrics": m,
			}
			// Promote the run's SOURCE strategy to the top level.
			//
			// filterAppData matches top-level fields only, and deliberately
			// fails closed on a field no row has. So a surface filtering by
			// `source_strategy_id` — which is exactly what lqt-mailbox's
			// "Backtests for this strategy" widget does
			// (me://app-data?…&loop=backtest&source_strategy_id={strategy_id})
			// — matched NOTHING, permanently, and the section read empty for
			// every strategy. The id was present all along, but only buried in
			// `metrics.command_engine.source_strategy_id`.
			//
			// Do NOT read `command_engine.strategy_id` here: on a backtest row
			// that is the CLAIM's own id (`bt-<uuid>`), not the strategy the
			// backtest came from. Promoting it would make the filter match the
			// wrong thing, which is worse than matching nothing.
			if ce, ok := m["command_engine"].(map[string]any); ok {
				if v, ok := ce["source_strategy_id"].(string); ok && v != "" {
					row["source_strategy_id"] = v
				}
			}
			out = append(out, row)
		}
		return map[string]any{"app": app, "runs": out, "count": len(out)}, true
	},
}

// MeAppData — GET /me/apps/:app/data?tool=<name>
//
// Lets an app-authored surface list its own content declaratively
// (`me://app-data?app=X&tool=casebook`) instead of every app hardcoding a
// table into its page. Reading through the same tool the analyst uses means
// the picker cannot drift from what the analyst can actually load — a row the
// UI offers is by construction a row the agent can open, which a hand-written
// table in page.yaml cannot promise.
func MeAppData(c *gin.Context) {
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
	tool := c.Query("tool")
	fn, allowed := readOnlyAppDataTools[tool]
	if !allowed {
		// Name the allowlist rather than 404ing: an app author pointing a
		// surface at the wrong tool otherwise sees an empty table and no cause.
		names := make([]string, 0, len(readOnlyAppDataTools))
		for k := range readOnlyAppDataTools {
			names = append(names, k)
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"ret_code": 1400,
			"message":  "tool not readable from a surface",
			"data":     gin.H{"allowed": names},
		})
		return
	}
	res, okRes := fn(userID, app)
	if !okRes {
		// The tool's own error text (e.g. "app not found: x") is the useful
		// signal; pass it through rather than flattening to a generic 500.
		c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": res})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": filterAppData(c, res)})
}

// filterAppData narrows a tool's result by any extra query params.
//
// A surface could not scope an app-data table at all: the source forwards only
// app= and tool=, so `me://app-data?...&strategy_id=X` was silently dropped and
// the table showed everything under a heading claiming otherwise — a scope a
// reader believes and the data does not honour.
//
// Applied AFTER the tool runs, deliberately. Post-filtering can only REMOVE
// rows the caller was already entitled to see, so it cannot widen access
// however the params are crafted, and it needs no change to the tool
// signatures (and so no chance of one tool mishandling a filter). The cost is
// that the tool still does its full work; these results are small.
//
// A param naming a field no row has matches NOTHING rather than being ignored.
// Ignoring it is how a filtered-looking table quietly shows every row.
func filterAppData(c *gin.Context, res map[string]any) map[string]any {
	filters := map[string]string{}
	for k, v := range c.Request.URL.Query() {
		if k == "tool" || k == "app" || len(v) == 0 || v[0] == "" {
			continue
		}
		filters[k] = v[0]
	}
	if len(filters) == 0 || res == nil {
		return res
	}
	out := make(map[string]any, len(res))
	for key, val := range res {
		rows, isRows := val.([]map[string]any)
		if !isRows {
			out[key] = val
			continue
		}
		kept := make([]map[string]any, 0, len(rows))
		for _, r := range rows {
			match := true
			for fk, fv := range filters {
				if fmt.Sprintf("%v", r[fk]) != fv {
					match = false
					break
				}
			}
			if match {
				kept = append(kept, r)
			}
		}
		out[key] = kept
	}
	return out
}
