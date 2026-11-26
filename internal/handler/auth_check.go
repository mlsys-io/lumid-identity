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
//
// EDGE AUDIENCES. This is the gate in FRONT of other services, not lum.id's own
// API, so a token minted for the service behind the gated path belongs here.
// Research Fleet (me_fleet_jobs.go) submits to https://lum.id/fm/<site>/… with
// an aud=flowmesh bridge JWT; when v0.5.480 bound JWTs to their audience,
// resolveRole (VerifyIdentityJWT) started refusing it and every fleet FlowMesh
// job got "compute service returned 401" (2026-11-25). The service still
// re-checks the token itself (FlowMesh introspects it), so admitting it at the
// edge widens nothing; it stays refused on every path that is not that
// service's, and on lum.id's own API.

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
)

// edgeAudiencePaths: a JWT whose aud is a key passes this gate only for a
// request under one of its prefixes.
var edgeAudiencePaths = map[string][]string{
	"flowmesh": {"/fm/"},
}

// edgeAudienceOK reports whether tok is a valid JWT minted for the service
// that serves originalURI — the gated request's URI, which nginx passes as
// X-Original-URI. Without that header the gate cannot tell which service is
// behind it, so a service token is refused.
func edgeAudienceOK(tok, originalURI string) (string, string, bool) {
	c, err := common.VerifyJWT(tok)
	if err != nil {
		return "", "", false
	}
	for _, aud := range c.Audience {
		for _, prefix := range edgeAudiencePaths[aud] {
			if originalURI != "" && strings.HasPrefix(originalURI, prefix) {
				return c.Subject, c.Role, true
			}
		}
	}
	return "", "", false
}

func AuthCheckHandler(c *gin.Context) {
	tok := bearerToken(c)
	if tok == "" {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	userID, role, ok := resolveRole(tok)
	if !ok {
		userID, role, ok = edgeAudienceOK(tok, c.GetHeader("X-Original-URI"))
	}
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "invalid credential")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"sub": userID, "role": role,
	}})
}

// GET /api/v1/auth-check/admin — auth-check's credential rules (PATs, identity
// JWTs, and a service-audience JWT for the path it serves) plus a role check:
// admin or super_admin, else 403.
//
// /admin/check cannot gate a FlowMesh site for a job identity submits on an
// admin's behalf: it resolves the role through identity-audience tokens only
// (v0.5.480 audience binding), and the credential identity mints for FlowMesh
// is addressed to "flowmesh". So an admin's measurement on NUS — admin+ by
// policy (2026-11-26) — was refused by nginx's own 401. This gate keeps NUS
// admin-only without that hole.
func AuthCheckAdminHandler(c *gin.Context) {
	tok := bearerToken(c)
	if tok == "" {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	userID, role, ok := resolveRole(tok)
	if !ok {
		userID, role, ok = edgeAudienceOK(tok, c.GetHeader("X-Original-URI"))
	}
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "invalid credential")
		return
	}
	if role != "admin" && role != "super_admin" {
		fail(c, http.StatusForbidden, 1403, "admins only")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{"sub": userID, "role": role}})
}
