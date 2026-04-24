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
		v1.POST("/identity/personal-access-tokens/:id/rotate", PATRotateHandler)
		// Drives the PAT mint dialog scope picker — tells the UI what
		// services + levels the caller can actually grant.
		v1.GET("/identity/grantable-scopes", GrantableScopesHandler)

		// Active-session management — list + revoke. Revoking a session
		// here has the same effect as the caller hitting /logout from
		// that browser: the JWT stays valid in form but every verify
		// path checks `sessions.revoked_at IS NULL`.
		v1.GET("/user/sessions", SessionsListHandler)
		v1.DELETE("/user/sessions/:id", SessionsRevokeHandler)
		v1.POST("/user/sessions/revoke-all", SessionsRevokeAllHandler)

		// User-uploaded SSH public keys. Needed for future git-over-SSH
		// push and for commit-signature verification. Actual server
		// component lives elsewhere; this just stores the material.
		v1.GET("/user/ssh-keys", SSHKeysListHandler)
		v1.POST("/user/ssh-keys", SSHKeysUploadHandler)
		v1.DELETE("/user/ssh-keys/:id", SSHKeysDeleteHandler)

		// LQA-compatible introspect path so Runmesh's existing
		// LUMID_LQA_BASE_URL switch is literally a URL change.
		v1.POST("/identity/introspect", Introspect)

		// Admin surface: all admin UIs at lum.id/app/admin/* call here.
		// Single-source: users here are THE user — no separate Runmesh
		// sys_user / LQA tbl_user / Lumilake principals admin. Those
		// tables still mirror for FK integrity (lazy, first-access),
		// but there's one editable row per person, and it lives here.
		admin := v1.Group("/admin", RequireAdmin())
		{
			admin.POST("/invitation-codes", AdminInviteMint)
			admin.GET("/invitation-codes", AdminInviteList)
			admin.DELETE("/invitation-codes/:code", AdminInviteRevoke)

			// Canonical user management + access matrix + audit.
			admin.GET("/users", AdminUsersList)
			admin.GET("/users/export.csv", AdminUsersExportCSV)
			admin.GET("/users/:id", AdminUsersGet)
			admin.PATCH("/users/:id", AdminUsersPatch)
			admin.POST("/users/:id/revoke-sessions", AdminUsersRevokeSessions)
			admin.GET("/users/:id/access", AdminUsersAccess)
			// Fine-grained per-service access grants — admin-applied
			// override layered on top of role and PAT scopes.
			admin.PUT("/users/:id/access/:service", AdminUsersAccessPut)
			admin.DELETE("/users/:id/access/:service", AdminUsersAccessDelete)
			admin.GET("/audit", AdminAuditList)
		}
	}
}

