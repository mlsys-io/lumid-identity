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
	"net/http"

	"github.com/gin-gonic/gin"
)

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
	fn, allowed := formActions[req.Action]
	if !allowed {
		// Unknown / unregistered action — the allowlist's whole point.
		fail(c, http.StatusForbidden, 1005, "form action not allowed: "+req.Action)
		return
	}
	role := currentUserRole(c)
	result, err := fn(c, userID, role, req.Values)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, err.Error())
		return
	}
	ok_(c, "ok", result)
}
