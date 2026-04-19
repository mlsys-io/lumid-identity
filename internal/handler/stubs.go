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

// Phase 2 — login / register / 3rd-party
var (
	Login                = notImplemented("POST /api/v1/login")
	RegisterUser         = notImplemented("POST /api/v1/register")
	SendVerificationCode = notImplemented("POST /api/v1/send-verification-code")
	GoogleLogin          = notImplemented("POST /api/v1/oauth/google/login")
	GithubLogin          = notImplemented("POST /api/v1/oauth/github/login")
)

// Phase 2/3 — PAT CRUD (move from LQA)
var (
	PATMint   = notImplemented("POST /api/v1/identity/personal-access-tokens")
	PATList   = notImplemented("GET /api/v1/identity/personal-access-tokens")
	PATRevoke = notImplemented("DELETE /api/v1/identity/personal-access-tokens/:id")
)

// Phase 2 — OIDC authorization + token + userinfo
var (
	OAuthAuthorize = notImplemented("GET/POST /oauth/authorize")
	OAuthToken     = notImplemented("POST /oauth/token")
	OAuthUserinfo  = notImplemented("GET /oauth/userinfo")
)
