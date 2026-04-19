package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Stub handlers — these return 501 while the feature is unwritten.
// Each phase's work fills one or more in.
//
// Keeping them explicit rather than a catch-all is deliberate: the
// router manifest is a contract, and 501s with a matched route make
// "is this feature live?" a single curl check.

func notImplemented(feature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{
			"error":  "not_implemented",
			"detail": feature + " is planned; tracked in the auth-consolidation plan",
		})
	}
}

// Phase 2 — 3rd-party social login. Deferred (needs client creds
// wired + redirect URIs reclaimed at the provider console).
var (
	GoogleLogin = notImplemented("POST /api/v1/oauth/google/login")
	GithubLogin = notImplemented("POST /api/v1/oauth/github/login")
)

// Login / Register / SendVerificationCode now live in auth.go.
// PAT mint/list/revoke now live in pat.go.
// OAuth authorize / token / userinfo now live in oauth.go.

// Phase 2 — OIDC authorization + token + userinfo
var (
	OAuthAuthorize = notImplemented("GET/POST /oauth/authorize")
	OAuthToken     = notImplemented("POST /oauth/token")
	OAuthUserinfo  = notImplemented("GET /oauth/userinfo")
)
