package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Canonical HTTP routes for workflows and runs — the verb contract (LumidOS
// docs/architecture/VERBS.md) on the /me surface:
//
//	GET    /me/agents/:agent/workflows/:workflow           get
//	PATCH  /me/agents/:agent/workflows/:workflow           define (enabled, schedule)
//	DELETE /me/agents/:agent/workflows/:workflow           delete
//	POST   /me/agents/:agent/workflows/:workflow/run       run    {mode: now|queue, …}
//	POST   /me/agents/:agent/workflows/:workflow/cancel    cancel
//	POST   /me/runs/:run_id/feedback                       feedback {verdict, note}
//
// Adapters, not new implementations: each hands the request to the handler
// that already does the job, with the parameters it expects. The routes they
// supersede keep working and answer with a Deprecation header naming the
// successor (deprecatedRoute), so callers can move before anything is removed.

// withParams renames path parameters for a handler written against the old
// route shape: {"app": "agent"} makes c.Param("app") read :agent.
func withParams(h gin.HandlerFunc, rename map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for oldKey, newKey := range rename {
			c.Params = append(c.Params, gin.Param{Key: oldKey, Value: c.Param(newKey)})
		}
		h(c)
	}
}

var agentWorkflowParams = map[string]string{"app": "agent", "loop": "workflow"}

// MeWorkflowGet — GET /me/agents/:agent/workflows/:workflow.
func MeWorkflowGet(c *gin.Context) {
	c.Params = append(c.Params, gin.Param{Key: "slug", Value: c.Param("agent") + ":" + c.Param("workflow")})
	MeWorkflowDetail(c)
}

// MeWorkflowRun — POST /me/agents/:agent/workflows/:workflow/run.
// mode "now" (default) runs once now; mode "queue" queues variants (the body
// MeLoopEnqueue takes). The rest of the body passes through unchanged.
func MeWorkflowRun(c *gin.Context) {
	raw, _ := io.ReadAll(io.LimitReader(c.Request.Body, 8<<20))
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	var peek struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(raw, &peek)
	switch strings.TrimSpace(peek.Mode) {
	case "", "now":
		withParams(MeLoopRunNow, agentWorkflowParams)(c)
	case "queue":
		withParams(MeLoopEnqueue, agentWorkflowParams)(c)
	default:
		fail(c, http.StatusBadRequest, 1400, "mode must be now or queue")
	}
}

// MeRunFeedback — POST /me/runs/:run_id/feedback {verdict, note}.
// succeeded|failed override the run's recorded outcome (was /runs/:id/mark);
// promote|discard mark it the chosen branch or grey it out (was
// /apps/:app/runs/:ts/promote|discard).
func MeRunFeedback(c *gin.Context) {
	// Authenticate before reading the body: the delegates check too, but a
	// caller with no credential must get 401, not a 400 about their JSON.
	if _, authed := currentUserID(c); !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var body struct {
		Verdict string `json:"verdict"`
		Note    string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	parts, err := feedbackTarget(c.Param("run_id"), body.Verdict)
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	if parts == nil { // succeeded | failed
		b, _ := json.Marshal(map[string]string{"state": body.Verdict, "note": body.Note})
		c.Request.Body = io.NopCloser(bytes.NewReader(b))
		MeRunMark(c)
		return
	}
	c.Params = append(c.Params, gin.Param{Key: "app", Value: parts[1]}, gin.Param{Key: "ts", Value: parts[3]})
	q := c.Request.URL.Query()
	q.Set("loop", parts[2])
	c.Request.URL.RawQuery = q.Encode()
	meRunMark(c, body.Verdict)
}

// feedbackTarget validates a verdict against a run id. For promote|discard it
// returns the id's parts (scheduled:<agent>:<workflow>:<ts>); for
// succeeded|failed, nil (MeRunMark parses the id itself).
func feedbackTarget(runID, verdict string) ([]string, error) {
	switch verdict {
	case "succeeded", "failed":
		return nil, nil
	case "promote", "discard":
		parts := strings.SplitN(runID, ":", 4)
		if len(parts) != 4 || parts[0] != "scheduled" {
			return nil, fmt.Errorf("promote/discard need a scheduled run id: scheduled:<agent>:<workflow>:<ts>")
		}
		return parts, nil
	}
	return nil, fmt.Errorf("verdict must be succeeded, failed, promote or discard")
}

// deprecatedRoute marks a superseded route: RFC 8594-style Deprecation and a
// successor Link on every response, and one log line per call so removal can
// wait for zero use (VERBS.md stage 3).
func deprecatedRoute(successor string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Deprecation", "true")
		c.Header("Link", "<"+successor+">; rel=\"successor-version\"")
		log.Printf("[deprecated-route] %s %s -> %s", c.Request.Method, c.FullPath(), successor)
		c.Next()
	}
}
