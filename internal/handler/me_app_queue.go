package handler

// GET /me/apps/:app/queue — the caller's queued, running and recent runs for
// one installed app, so Studio can show the runs waiting for compute.
//
// The run queue lives on the scheduler's disk, and identity mounts no tenant
// volume, so this is one more synchronous read intent (me_read_intent.go),
// exactly like cycle_read: insert `queue_read`, wait for the picker's answer,
// return it. The picker resolves the queue under the intent row's user_sub —
// the caller — so it can only ever answer with the caller's own runs.
//
// The picker returns {"app", "rows": [{req_id, loop, experiment_id, state,
// remaining, ran, priority, submitted_at, updated_at, last_error,
// branch_label, variant_id, position?}], "progress": {...}}. Rows pass
// through as loose maps on purpose: a field the picker adds later reaches the
// UI without an identity release, and a field it drops does not break one.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	queueReadAction = "queue_read"
	// queueReadLimit is how many rows the picker is asked for. The queue view
	// shows what is waiting and what just ran, not the full history.
	queueReadLimit = 50
)

// meQueueReadIntent is runReadIntent; a var so tests can stand in for the
// scheduler without a database.
var meQueueReadIntent = runReadIntent

// MeAppQueue — GET /me/apps/:app/queue
func MeAppQueue(c *gin.Context) {
	userID, okk := currentUserID(c)
	if !okk {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	// The /me/apps/:app validator, plus no traversal: the name goes into an
	// intent payload the scheduler resolves on its own disk.
	if !slugRe.MatchString(app) || strings.Contains(app, "/") || strings.Contains(app, "..") {
		fail(c, http.StatusBadRequest, 1400, "invalid app")
		return
	}
	data, err := meQueueReadIntent(ginReqCtx(c), userID, queueReadAction,
		map[string]any{"app": app, "limit": queueReadLimit}, readIntentDefaultTimeout)
	if err != nil {
		if errors.Is(err, errReadIntentTimeout) {
			fail(c, http.StatusGatewayTimeout, 1504, err.Error())
			return
		}
		var rf *readIntentFailed
		if errors.As(err, &rf) {
			fail(c, http.StatusBadGateway, 1502, rf.msg)
			return
		}
		fail(c, http.StatusBadGateway, 1502, "the run queue could not be read from the scheduler")
		return
	}
	ok(c, "ok", queueResponse(app, data))
}

// queueResponse shapes the picker's data for the client. rows is always an
// array and progress always an object — never JSON null, which a client that
// maps over rows would crash on.
func queueResponse(app string, data map[string]any) gin.H {
	rows := []map[string]any{}
	if rs, okk := data["rows"].([]any); okk {
		for _, r := range rs {
			if m, okk := r.(map[string]any); okk {
				rows = append(rows, m)
			}
		}
	}
	progress, _ := data["progress"].(map[string]any)
	if progress == nil {
		progress = map[string]any{}
	}
	return gin.H{"app": app, "rows": rows, "count": len(rows), "progress": progress}
}
