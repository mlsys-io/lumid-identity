package handler

// POST /api/v1/me/form-action — the submit target for `lumid:form` widgets in
// generated app surfaces.
//
// SECURITY MODEL — endpoint allowlist:
//   A generated page can ONLY reference an action by KEY, never an arbitrary
//   URL. Each key maps to a registered handler here, which validates input and
//   performs the action with the CALLER's auth + scope. An unknown key is a
//   403. This keeps "pages that submit to APIs" bounded: the page is data, the
//   set of things it can trigger is fixed in compiled code and reviewed here.
//
// Add a new form action = add one entry to formActions. Nothing else in the
// generated-markdown path can reach a backend write.

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// errFormActionNotAllowed is returned by dispatchFormAction when the action
// key isn't on the allowlist. Callers map it to the right status (403 for the
// HTTP handler, an error result for the chat tool).
var errFormActionNotAllowed = errors.New("form action not allowed")

type formActionReq struct {
	Action string         `json:"action" binding:"required"`
	Values map[string]any `json:"values"`
}

// formActionFn performs one allowlisted action for a caller. Returns a result
// payload (echoed to the UI) or an error.
type formActionFn func(c *gin.Context, userID, role string, values map[string]any) (any, error)

// formActions is the ALLOWLIST. Only keys present here are callable.
var formActions = map[string]formActionFn{
	// Diagnostic: echoes inputs back. Safe, lets a generated form prove the
	// round-trip end to end without touching any backend write.
	"diagnostic.echo": func(_ *gin.Context, userID, _ string, values map[string]any) (any, error) {
		return gin.H{"ok": true, "received": values, "user": userID}, nil
	},
	// Real per-app actions (e.g. "gpu_rental.create") are registered alongside
	// this one as they're wired to their backend path. Each must do its own
	// input validation + scope check.
}

// dispatchFormAction runs one allowlisted form action for a caller. Shared by
// the HTTP handler (MeFormAction) and the chat agent's app_action tool so a
// generated form and the AI hit the SAME validated backend path. Returns
// errFormActionNotAllowed when the key isn't registered.
func dispatchFormAction(c *gin.Context, userID, role, action string, values map[string]any) (any, error) {
	fn, allowed := formActions[action]
	if !allowed {
		return nil, errFormActionNotAllowed
	}
	return fn(c, userID, role, values)
}

func MeFormAction(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var req formActionReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body")
		return
	}
	role := currentUserRole(c)
	result, err := dispatchFormAction(c, userID, role, req.Action, req.Values)
	if errors.Is(err, errFormActionNotAllowed) {
		// Unknown / unregistered action — the allowlist's whole point.
		fail(c, http.StatusForbidden, 1005, "form action not allowed: "+req.Action)
		return
	}
	if err != nil {
		log.Printf("[form-action] action=%s user=%s err=%v", req.Action, userID, err)
		fail(c, http.StatusBadGateway, 1502, err.Error())
		return
	}
	ok_(c, "ok", result)
}
