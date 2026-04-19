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
	r.GET("/oauth/authorize", OAuthAuthorizeHandler)
	r.POST("/oauth/authorize", OAuthAuthorizeHandler)
	r.POST("/oauth/token", OAuthTokenHandler)
	r.GET("/oauth/userinfo", OAuthUserinfoHandler)

	v1 := r.Group("/api/v1")
	{
		v1.POST("/login", LoginHandler)
		v1.POST("/logout", LogoutHandler)
		v1.POST("/register", RegisterHandler)
		v1.POST("/send-verification-code", SendVerificationCodeHandler)
		v1.GET("/user", CurrentUserHandler)
		v1.GET("/session-bearer", SessionBearerHandler)
		v1.PUT("/user", UpdateUserHandler)
		v1.POST("/user/password", ChangePasswordHandler)
		v1.POST("/forgot-password", ForgotPasswordHandler)
		v1.POST("/reset-password", ResetPasswordHandler)
		v1.POST("/oauth/google/login", GoogleLoginHandler)
		v1.POST("/oauth/github/login", GithubLogin)

		// LQA-compatible PAT surface — same path so downstream code
		// (frontend /account/tokens, install.sh) works unchanged after
		// Phase 3 repoints the proxy.
		v1.POST("/identity/personal-access-tokens", PATMintHandler)
		v1.GET("/identity/personal-access-tokens", PATListHandler)
		v1.DELETE("/identity/personal-access-tokens/:id", PATRevokeHandler)

		// LQA-compatible introspect path so Runmesh's existing
		// LUMID_LQA_BASE_URL switch is literally a URL change.
		v1.POST("/identity/introspect", Introspect)

		// Admin invitation-code management (ported from LQA management UI).
		admin := v1.Group("/admin", RequireAdmin())
		{
			admin.POST("/invitation-codes", AdminInviteMint)
			admin.GET("/invitation-codes", AdminInviteList)
			admin.DELETE("/invitation-codes/:code", AdminInviteRevoke)
		}
	}
}

