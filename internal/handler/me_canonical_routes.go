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
//	POST   /me/runs/:run_id/feedback                       feedback {verdict, note, …}
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

// MeRunFeedback — POST /me/runs/:run_id/feedback {verdict, note, …}.
// One verb for every verdict a person gives on a run; each hands off to the
// handler that already records it, with the body that handler reads:
//
//	succeeded|failed         override the recorded outcome      (was /runs/:id/mark)
//	promote|discard          chosen branch / greyed out         (was /apps/:app/runs/:ts/promote|discard)
//	good|bad|neutral         rate it, +1/-1/0, with a note      (was /cycles/feedback)
//	approve|edit|revamp|dismiss  answer its held step           (was /cycles/:app/:loop/:ts/review)
//	branch                   start a new experiment from it     (was /apps/:app/trajectory/signal)
//
// Every field besides verdict passes through, so a caller that sent the old
// route's body keeps its extras (label, planned_kwargs, from_variant_id, …).
func MeRunFeedback(c *gin.Context) {
	// Authenticate before reading the body: the delegates check too, but a
	// caller with no credential must get 401, not a 400 about their JSON.
	if _, authed := currentUserID(c); !authed {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	body := map[string]any{}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	verdict, _ := body["verdict"].(string)
	target, err := feedbackTarget(c.Param("run_id"), verdict)
	if err != nil {
		fail(c, http.StatusBadRequest, 1400, err.Error())
		return
	}
	delete(body, "verdict")
	switch target.kind {
	case "mark":
		body["state"] = verdict
		setJSONBody(c, body)
		MeRunMark(c)
	case "branch-state":
		c.Params = append(c.Params, gin.Param{Key: "app", Value: target.agent}, gin.Param{Key: "ts", Value: target.ts})
		q := c.Request.URL.Query()
		q.Set("loop", target.workflow)
		c.Request.URL.RawQuery = q.Encode()
		meRunMark(c, verdict)
	case "rating":
		body["app"], body["loop"], body["ts"] = target.agent, target.workflow, target.ts
		body["rating"] = map[string]int{"good": 1, "bad": -1, "neutral": 0}[verdict]
		setJSONBody(c, body)
		MeCycleFeedback(c)
	case "review":
		body["decision"] = verdict
		c.Params = append(c.Params, gin.Param{Key: "app", Value: target.agent},
			gin.Param{Key: "loop", Value: target.workflow}, gin.Param{Key: "ts", Value: target.ts})
		setJSONBody(c, body)
		MeCycleReview(c)
	case "branch":
		body["loop"], body["action"], body["from_id"] = target.workflow, "branch", target.ts
		c.Params = append(c.Params, gin.Param{Key: "app", Value: target.agent})
		setJSONBody(c, body)
		MeTrajectorySignal(c)
	}
}

func setJSONBody(c *gin.Context, body map[string]any) {
	b, _ := json.Marshal(body)
	c.Request.Body = io.NopCloser(bytes.NewReader(b))
	c.Request.ContentLength = int64(len(b))
}

type feedbackRoute struct {
	kind                string // mark | branch-state | rating | review | branch
	agent, workflow, ts string
}

// feedbackTarget validates a verdict against a run id. Every verdict but
// succeeded|failed needs a scheduled run id (scheduled:<agent>:<workflow>:<ts>);
// those two go to MeRunMark, which parses any run id itself.
func feedbackTarget(runID, verdict string) (feedbackRoute, error) {
	kind := map[string]string{
		"succeeded": "mark", "failed": "mark",
		"promote": "branch-state", "discard": "branch-state",
		"good": "rating", "bad": "rating", "neutral": "rating",
		"approve": "review", "edit": "review", "revamp": "review", "dismiss": "review",
		"branch": "branch",
	}[verdict]
	if kind == "" {
		return feedbackRoute{}, fmt.Errorf("verdict must be one of succeeded, failed, promote, discard, good, bad, neutral, approve, edit, revamp, dismiss, branch")
	}
	if kind == "mark" {
		return feedbackRoute{kind: kind}, nil
	}
	parts := strings.SplitN(runID, ":", 4)
	// promote|discard tolerate an empty workflow (meRunMark resolves the run by
	// agent + ts); the others write into one workflow's state and need it.
	if len(parts) != 4 || parts[0] != "scheduled" || parts[1] == "" || parts[3] == "" ||
		(parts[2] == "" && kind != "branch-state") {
		return feedbackRoute{}, fmt.Errorf("verdict %s needs a scheduled run id: scheduled:<agent>:<workflow>:<ts>", verdict)
	}
	return feedbackRoute{kind: kind, agent: parts[1], workflow: parts[2], ts: parts[3]}, nil
}

// deprecatedRoute marks a superseded route: RFC 8594-style Deprecation and a
// successor Link on every response, one log line per call, and a durable count
// (deprecation_usage.go) so removal can wait for zero use (VERBS.md stage 3).
func deprecatedRoute(successor string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Deprecation", "true")
		c.Header("Link", "<"+successor+">; rel=\"successor-version\"")
		log.Printf("[deprecated-route] %s %s -> %s", c.Request.Method, c.FullPath(), successor)
		by, _ := currentUserID(c)
		recordDeprecatedUse("route", c.Request.Method+" "+c.FullPath(), by)
		c.Next()
	}
}
