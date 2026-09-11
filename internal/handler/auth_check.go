package handler

// GET /api/v1/auth-check — "is this caller authenticated at all?"
//
// nginx's auth_request needs a cheap 200/401 for routes that admit ANY signed-in
// user (the user-level /fm/home surface). It used to subrequest /session-bearer,
// which was wrong in two ways:
//
//   1. session-bearer calls VerifyJWT, so it accepts ONLY session JWTs. Every
//      lm_pat_* / rm_pat_* credential got 401 — including a super_admin's. That
//      silently broke the documented `curl -H "Authorization: Bearer $PAT"` path
//      for the whole user-gated surface, while the admin-gated surface kept
//      working (RequireAdmin resolves PATs via resolveRole). Same estate, two
//      different answers to "is this a valid credential".
//   2. it MINTS a JWT per subrequest, whose body auth_request then discards — a
//      signature per gated request, for nothing.
//
// resolveRole is the same resolver RequireAdmin uses, so "authenticated" now
// means one thing here regardless of credential type. No role check: callers who
// need admin use /admin/check.

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func AuthCheckHandler(c *gin.Context) {
	tok := bearerToken(c)
	if tok == "" {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	userID, role, ok := resolveRole(tok)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "invalid credential")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"sub": userID, "role": role,
	}})
}
