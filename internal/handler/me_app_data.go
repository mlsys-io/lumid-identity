package handler

import (
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
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": res})
}
