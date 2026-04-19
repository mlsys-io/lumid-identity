package handler

import (
	"github.com/gin-gonic/gin"
)

// Register wires every endpoint. Order-independent: Gin handles
// routing deterministically and we don't use wildcards that could
// shadow each other.
func Register(r *gin.Engine) {
	r.GET("/healthz", Healthz)

	// OIDC / OAuth2 — the cross-subsystem contract
	r.GET("/.well-known/openid-configuration", OpenIDConfig)
	r.GET("/.well-known/jwks.json", Jwks)
	r.POST("/oauth/introspect", Introspect)
	r.GET("/oauth/authorize", OAuthAuthorize)
	r.POST("/oauth/authorize", OAuthAuthorize)
	r.POST("/oauth/token", OAuthToken)
	r.GET("/oauth/userinfo", OAuthUserinfo)

	v1 := r.Group("/api/v1")
	{
		v1.POST("/login", Login)
		v1.POST("/register", RegisterUser)
		v1.POST("/send-verification-code", SendVerificationCode)
		v1.POST("/oauth/google/login", GoogleLogin)
		v1.POST("/oauth/github/login", GithubLogin)

		// LQA-compatible PAT surface — same path so downstream code
		// (frontend /account/tokens, install.sh) works unchanged after
		// Phase 3 repoints the proxy.
		v1.POST("/identity/personal-access-tokens", PATMint)
		v1.GET("/identity/personal-access-tokens", PATList)
		v1.DELETE("/identity/personal-access-tokens/:id", PATRevoke)

		// LQA-compatible introspect path so Runmesh's existing
		// LUMID_LQA_BASE_URL switch is literally a URL change.
		v1.POST("/identity/introspect", Introspect)
	}
}

