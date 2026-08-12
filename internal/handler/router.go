package handler

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// meCORS — permissive but bounded CORS for the /api/v1/me/* surface
// the new web UI calls cross-origin. Allowed origins come from the
// ME_CORS_ALLOWED_ORIGINS env var (comma-separated). Default covers
// xp.io + lum.id + lumid.market (QA frontend) + localhost dev ports.
// Credentials are enabled (the UI sends lm_session cookie + PAT bearers).
//
// IMPORTANT: never use "*" with credentials — that's a security error
// browsers reject anyway. The Vary header keeps CDNs honest if any
// front-of-origin caching appears.
func meCORS() gin.HandlerFunc {
	allowed := os.Getenv("ME_CORS_ALLOWED_ORIGINS")
	if allowed == "" {
		allowed = "https://xp.io,https://lum.id,https://lumid.market,https://lumid.market:2443,http://localhost:3000,http://localhost:5173,http://localhost:13080"
	}
	set := map[string]bool{}
	for _, o := range strings.Split(allowed, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			set[o] = true
		}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && set[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
			c.Header("Access-Control-Max-Age", "600")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// Register wires every endpoint. Order-independent: Gin handles
// routing deterministically and we don't use wildcards that could
// shadow each other.
func Register(r *gin.Engine) {
	r.GET("/healthz", Healthz)
	r.GET("/version", Version)

	// OIDC / OAuth2 — the cross-subsystem contract
	r.GET("/.well-known/openid-configuration", OpenIDConfig)
	r.GET("/.well-known/jwks.json", Jwks)
	r.POST("/oauth/introspect", Introspect)
	r.GET("/oauth/authorize", OAuthAuthorizeHandler)
	r.POST("/oauth/authorize", OAuthAuthorizeHandler)
	r.POST("/oauth/token", OAuthTokenHandler)
	r.GET("/oauth/userinfo", OAuthUserinfoHandler)

	// CORS applies to the entire /api/v1/* surface, not just /me/*. The
	// cross-origin web UI at xp.io/go/* needs login/register/OTP/user/
	// session-bearer/forgot-password/reset-password just as much as the
	// /me/* write endpoints. Allowlist is bounded (xp.io + lum.id +
	// localhost dev); see meCORS() for the source-of-truth list.
	v1 := r.Group("/api/v1", meCORS())
	{
		// Catch-all OPTIONS for the v1 surface. meCORS aborts with
		// 204 + allow headers before this handler runs, so the inner
		// func is dead code — but the route MUST exist or Gin returns
		// 405 on OPTIONS before middleware can fire.
		v1.OPTIONS("/*path", func(c *gin.Context) { c.Status(http.StatusNoContent) })

		v1.GET("/version", Version)

		v1.POST("/login", LoginHandler)
		v1.POST("/logout", LogoutHandler)
		v1.POST("/register", RegisterHandler)
		v1.POST("/send-verification-code", SendVerificationCodeHandler)
		v1.GET("/user", CurrentUserHandler)
		v1.GET("/session-bearer", SessionBearerHandler)
		v1.PUT("/user", UpdateUserHandler)
		v1.POST("/user/password", ChangePasswordHandler)
		// First-time Google-OAuth users land at /auth/callback without an
		// invitation_code; the dialog there PUTs here to claim one before
		// the session is treated as fully established.
		v1.PUT("/user/invitation-code", RedeemInvitationCodeHandler)
		v1.POST("/forgot-password", ForgotPasswordHandler)
		v1.POST("/reset-password", ResetPasswordHandler)
		v1.POST("/oauth/google/login", GoogleLoginHandler)
		v1.POST("/oauth/github/login", GithubLogin)

		// Personal-agent / app Google scope grants. Init returns the
		// Google authorize URL with gmail.modify + calendar scopes;
		// callback persists the encrypted refresh-token; identity/google-token
		// hands it to the CLI's setup verb. Revoke is a soft-delete.
		v1.POST("/oauth/google/connect/init", GoogleConnectInit)
		v1.GET("/oauth/google/connect/callback", GoogleConnectCallback)
		v1.GET("/identity/google-token", GoogleTokenFetch)
		v1.DELETE("/identity/google-token", GoogleTokenRevoke)
		v1.GET("/identity/google-grants", GoogleGrantsList)
		v1.POST("/identity/google-access-token", GoogleAccessToken)

		// Microsoft Graph OAuth via device-code (no Azure app
		// registration needed — uses Microsoft's pre-registered
		// Graph PowerShell SDK public client_id). Centralized auth
		// + multi-tenant runtime: refresh-tokens encrypted at rest
		// in microsoft_grants, daemons/skills mint per-call access
		// tokens via /microsoft-access-token.
		v1.POST("/oauth/microsoft/connect/init", MicrosoftConnectInit)
		v1.POST("/oauth/microsoft/connect/poll", MicrosoftConnectPoll)
		v1.GET("/identity/microsoft-grants", MicrosoftGrantsList)
		v1.DELETE("/identity/microsoft-token", MicrosoftTokenRevoke)
		v1.POST("/identity/microsoft-access-token", MicrosoftAccessToken)

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
			// No-op admin-gated probe. Used as an nginx auth_request target to
			// gate internal doc routes (e.g. lum.id/docs/plugin-image-cd) to
			// admin/super_admin only — RequireAdmin admits both roles.
			admin.GET("/check", AdminCheck)
			admin.POST("/invitation-codes", AdminInviteMint)
			admin.GET("/invitation-codes", AdminInviteList)
			admin.DELETE("/invitation-codes/:code", AdminInviteRevoke)

			// Canonical user management + access matrix + audit.
			admin.GET("/users", AdminUsersList)
			admin.GET("/users/export.csv", AdminUsersExportCSV)
			admin.GET("/users/:id", AdminUsersGet)
			admin.PATCH("/users/:id", AdminUsersPatch)
			admin.DELETE("/users/:id", AdminUsersDelete)
			admin.POST("/users/:id/revoke-sessions", AdminUsersRevokeSessions)
			admin.GET("/users/:id/access", AdminUsersAccess)
			// Fine-grained per-service access grants — admin-applied
			// override layered on top of role and PAT scopes.
			admin.PUT("/users/:id/access/:service", AdminUsersAccessPut)
			admin.DELETE("/users/:id/access/:service", AdminUsersAccessDelete)
			admin.GET("/audit", AdminAuditList)

			// Super-admin dashboard read-only tiles. None of these
			// mutate state; auth-stats / qa-summary / cert-expiry /
			// backup-status / build-status visible to every admin
			// because operational visibility shouldn't gate on the
			// billing role. oauth-clients leaks which services
			// federate against us — keep that super_admin only.
			admin.GET("/auth-stats", AdminAuthStats)
			admin.GET("/qa-summary", AdminQASummary)
			admin.GET("/cert-expiry", AdminCertExpiry)
			admin.GET("/backup-status", AdminBackupStatus)
			admin.GET("/build-status", AdminBuildStatus)
			admin.GET("/loops", AdminLoops)
			admin.GET("/codebase-repos", AdminCodebaseRepos)
			admin.GET("/jobs", Jobs)
			admin.GET("/cycle-artifact", CycleArtifact)
			// Phase D follow-up: per-tenant snapshot for the
			// super-admin dashboard's tenants tile.
			admin.GET("/tenants", AdminTenants)
		}

		// User-scoped write surface for the new web-first UI (xp.io/go/*
		// during P0 — landing at /app/* later). All routes here are
		// gated by currentUserID() (session JWT or PAT). CORS is open
		// to the allowed-origins set so the xp.io-served bundle can
		// call cross-origin.
		// CORS + OPTIONS catch-all live on the parent v1 group; no
		// extra middleware needed here.
		// Phase D3 — /me/* rate limit. 60/min per caller (PAT / session
		// cookie / IP fallback). Soft-fails when Redis is unreachable.
		// no-store: /me/* is live dashboard data (loop status, cycles,
		// workflows). Without this the browser heuristically caches the
		// GETs, so the dashboard's polling re-reads stale cached responses
		// and looks frozen even though the server has fresh state.
		me := v1.Group("/me", MeRateLimit(), func(c *gin.Context) {
			c.Header("Cache-Control", "no-store")
			c.Next()
		})
		{
			// App lifecycle — async via intent queue.
			me.GET("/apps", MeAppsList)
			me.POST("/apps", MeAppsInstall)
			me.DELETE("/apps/:app", MeAppsUninstall)
			me.GET("/apps/:app/ui", MeAppUI) // app-declared Studio surface (markdown)
			me.GET("/apps/:app/ui/:surface", MeAppUISurface)
			me.GET("/apps/:app/data", MeAppData)   // read-only app content for declarative surfaces
			me.PUT("/apps/:app/ui", MeUpdateAppUI) // write/create surface markdown
			me.PUT("/apps/:app/ui/:surface", MeUpdateAppUISurface)
			me.POST("/apps/:app/ui/generate", MeGenerateAppUI) // AI-generate surface from config
			me.GET("/apps/:app/config", MeAppConfig)           // read xpcloud.yaml
			me.PUT("/apps/:app/config", MeUpdateAppConfig)     // write xpcloud.yaml (YAML-validated)
			// Prompt editor — analyst & judge prompt cards. List unions local
			// overrides with inherited shared-skill prompts; PUT/DELETE write a
			// LOCAL override in the caller's own app only (never the shared file).
			me.GET("/apps/:app/prompts", MeAppPrompts)
			me.GET("/apps/:app/prompts/:name", MeAppPrompt)
			me.PUT("/apps/:app/prompts/:name", MeUpdateAppPrompt)
			me.DELETE("/apps/:app/prompts/:name", MeDeleteAppPrompt)
			me.POST("/apps/:app/skills", MeAppAddSkill) // add a kind=skill repo to skill_imports[]
			// Repo workflow — fork a showcase app, publish your tree
			// to YOUR xp.io repo, propose changes upstream as a PR.
			me.POST("/apps/:app/update", MeAppUpdate) // pull upstream updates (three-way merge)
			me.POST("/apps/:app/fork", MeAppFork)
			me.POST("/apps/:app/publish", MeAppPublish)
			me.POST("/apps/:app/propose", MeAppPropose)
			// Experiments — read-only observability for experiments[]
			// (hypothesis × variants × dataset/casebook × metric).
			me.GET("/experiments", MeExperiments) // cross-app aggregate (Workstream F)
			me.GET("/apps/:app/experiments", MeAppExperiments)
			me.GET("/apps/:app/experiments/:id", MeAppExperiment)
			me.GET("/apps/:app/experiments/:id/case/:caseId", MeAppExperimentCase)
			me.GET("/intents/:id", MeIntentGet)
			// Permanently dismiss a failed/optimistic install card by app name.
			me.DELETE("/install-intents/:name", MeInstallIntentDelete)
			// Submit target for lumid:form widgets — allowlisted actions only.
			me.POST("/form-action", MeFormAction)
			// GPU rentals store — backs the me://gpu-rentals read source.
			me.GET("/gpu-rentals", MeGpuRentalsList)

			// Per-loop control.
			me.PATCH("/loops/:app/:loop", MeLoopPatch)
			me.POST("/loops/:app/:loop/run", MeLoopRunNow)
			me.POST("/loops/:app/:loop/stop", MeLoopStop)
			me.GET("/loops/health", MeLoopsHealth)

			// Per-(app, key) secrets.
			me.GET("/apps/:app/secrets", MeSecretsList)
			me.PUT("/apps/:app/secrets/:key", MeSecretPut)
			me.DELETE("/apps/:app/secrets/:key", MeSecretDelete)
			me.GET("/apps/:app/secrets/:key/value", MeSecretFetchValue)
			// Live-verify a pasted Claude credential against Anthropic + store
			// it only if it authenticates (backs the "Connect Claude" popup).
			me.POST("/apps/:app/secrets/claude-verify", MeSecretClaudeVerify)

			// Power Automate inbound webhook lifecycle. The Outlook
			// bridge workaround for users whose org blocks Microsoft
			// Graph OAuth: user pastes the minted URL into a Power
			// Automate flow that fires on new email.
			me.POST("/power-automate-tokens", MePowerAutomateTokenMint)
			me.GET("/power-automate-tokens", MePowerAutomateTokenStatus)
			me.DELETE("/power-automate-tokens", MePowerAutomateTokenRevoke)
			// Pre-baked PA package .zip the user imports at
			// make.powerautomate.com → My flows → Import. Webhook
			// URL is hard-coded into the HTTP action so post-import
			// the user just confirms the Outlook connection and
			// saves. Always rotates the underlying token.
			me.GET("/power-automate-tokens/flow-template", MePowerAutomateFlowTemplate)
			// One-click "send me a test email through my flow" — verifies
			// the outbound POWER_AUTOMATE_SEND_URL end-to-end without
			// the user needing a PAT + curl.
			me.POST("/apps/lumid-outlook-pa/test-send", MeOutlookPATestSend)

			// Cycle-level feedback (Hook 2 keystone). Same backend
			// for clickable UI + conversational-agent give_feedback tool.
			me.POST("/cycles/feedback", MeCycleFeedback)

			// Improvement ledger — every change to an intent across
			// the six axes (examples/standard/recipe/pieces/memory/
			// rules). POST appends a row; the cycle-feedback handler
			// above also dual-writes here. GET returns events +
			// axis_movements summary for the Intent detail page.
			me.POST("/feedback", MeFeedbackSave)
			me.GET("/intents/:id/audit", MeIntentAudit)

			// Conversational shell — the natural-interaction layer.
			// The agent calls the same tools the UI buttons would call.
			me.POST("/agent/chat", MeAgentChat)
			// Streaming sibling — same body shape, SSE-style chunked
			// response. The frontend reads via fetch().body.getReader()
			// to render text deltas + tool-call events as they arrive,
			// instead of waiting 5-10s for a synchronous reply.
			me.POST("/agent/chat/stream", MeAgentChatStream)
			// Tool approval — unblocks a destructive tool pending user consent.
			me.POST("/agent/chat/tool-approve", MeAgentToolApprove)
			// Cooperative stop for a live Claude Code turn (see
			// me_agent_claude_code.go) — beats aborting the fetch, which
			// SIGKILLed the CLI and discarded partial work.
			me.POST("/agent/chat/interrupt", MeAgentChatInterrupt)
			// super_admin-only tenant inspection — read-only view of another
			// tenant's checkpointed Claude Code state via the sandbox gateway.
			// Replaces the retired super_admin shared-workspaces-root affordance.
			me.GET("/agent/admin/tenant", MeAgentAdminTenant)
			// Persistent "always allow" grants for destructive tools —
			// written by tool-approve with always=true; listed/revoked here.
			me.GET("/agent/tool-grants", MeAgentToolGrants)
			me.DELETE("/agent/tool-grants/:name", MeAgentToolGrantRevoke)
			// Available LLM backends — populates the model dropdown
			// in StudioChat. Returns [{id, displayName, default}].
			me.GET("/agent/models", MeAgentModels)

			// Installed xpio agents — populates the agent picker in
			// StudioChat. Chat body can set agent_id to ground the
			// turn in that agent's bank.
			me.GET("/agents", MeAgentsList)

			// User-defined personas — custom system prompts + tool
			// subsets. Chat body sets persona_id to apply.
			me.GET("/personas", MePersonasList)
			me.GET("/personas/:id", MePersonaGet)
			me.POST("/personas", MePersonaSave)
			me.DELETE("/personas/:id", MePersonaDelete)

			// Artifacts — saved long-form output from chat. Backed
			// by ~/.tenants/<userID>/.artifacts/<id>.json.
			me.GET("/artifacts", MeArtifactsList)
			me.GET("/artifacts/:id", MeArtifactGet)
			me.DELETE("/artifacts/:id", MeArtifactDelete)

			// Persistent chat history — sidebar in StudioChat. One
			// file per thread under ~/.tenants/<userID>/.chats/.
			me.GET("/chats", MeChatsList)
			me.GET("/chats/:id", MeChatGet)
			me.POST("/chats", MeChatSave)
			me.DELETE("/chats/:id", MeChatDelete)

			// Tier-1 quota state — read-only. Used by /app/loops to
			// render the "Free tier reached" banner + per-loop hints.
			// Writes flow through /internal/usage/charge below.
			me.GET("/limits", MeLimits)

			// Claude account-pool session recording (lum.id/claude). Owner
			// reads own transcripts; recording is on by default, opt-out here.
			me.GET("/claude-sessions", MeClaudeSessions)
			me.GET("/claude-sessions/:conv", MeClaudeSessionDetail)
			me.DELETE("/claude-sessions/:conv", MeClaudeSessionDelete)
			me.GET("/claude-recording", MeClaudeRecordingGet)
			me.POST("/claude-recording", MeClaudeRecordingSet)
			// Self-serve pool consumption (5h/7d windows + per-model 7d) —
			// powers the chatbox QuotaMeter for claude-code models.
			me.GET("/claude-usage", MeClaudeUsage)

			// Today summary — server-side aggregation of journal
			// entries + drafts queue + quota state for the /app/loops
			// "Today" section. One round-trip per page load; UI
			// renders headlines[] directly without per-app fan-out.
			me.GET("/today", MeToday)

			// Phase D2 — storage usage snapshot per tenant. Cached
			// 5 min; under {used_bytes, cap_mb, fraction, largest_path}.
			me.GET("/storage", MeStorage)

			// Phase D4 — external-API audit log. Same usage_events
			// table Tier-1 counts against (kind=external_api); now
			// human-readable so the user can see every Gmail send /
			// calendar create / Slack post their AI made.
			me.GET("/audit", MeAudit)

			// Phase S3-B — cycle inspector. List + drill-down for
			// the user's per-app cycle artifacts (step outputs +
			// prompt audit + summary).
			me.GET("/cycles", MeCyclesList)
			me.GET("/cycles/:app/:loop/:ts", MeCycleDetail)
			// Grep a single cycle's run-log + issues (transcript + journal +
			// step errors) for a query string.
			me.GET("/cycles/:app/:loop/:ts/search", MeCycleLogSearch)
			// Per-run PROVENANCE — the versioned assets this run used.
			me.GET("/cycles/:app/:loop/:ts/provenance", MeCycleProvenance)
			// Dataset / casebook explorer for the app-overview page.
			me.GET("/apps/:app/datasets", MeAppDatasets)
			me.GET("/apps/:app/dataset-file", MeAppDatasetFile)
			me.GET("/apps/:app/casebook", MeCasebook)
			// Per-case data↔metric mapping log (AI labeling/scoring records).
			me.GET("/apps/:app/casebook/case-log", MeCaseLog)
			// A case's full evaluation report (per-Q breakdown + cited evidence).
			me.GET("/apps/:app/case-report", MeCaseReport)
			// Live execution feed — tail journal.jsonl for a running cycle.
			me.GET("/apps/:app/cycle-log", MeCycleLog)
			// Variant trajectory tree (baseline → per-cycle variants → champion trunk).
			me.GET("/apps/:app/trajectory", MeTrajectory)
			// Trajectory control-signal channel (right-click "branch from here").
			me.POST("/apps/:app/trajectory/signal", MeTrajectorySignal)
			me.GET("/apps/:app/trajectory/signals", MeTrajectorySignals)
			// Goal-metric trajectory across cycles (improvement over iterations).
			me.GET("/apps/:app/loops/:loop/metric-series", MeLoopMetricSeries)
			// Branching-runtime ops + recommender (thin shims over the
			// lumid-trajectory CLI; HOME bound to the caller's tenant root).
			me.GET("/apps/:app/next-actions", MeNextActions)         // recommender: what to do next
			me.GET("/apps/:app/loops/:loop/lineage", MeLoopLineage)  // branch tree (parent_run_id edges)
			me.POST("/apps/:app/loops/:loop/enqueue", MeLoopEnqueue) // Phase C: fan-out variants → trajectory queue
			me.POST("/apps/:app/runs/:ts/promote", MeRunPromote)     // mark chosen branch
			me.POST("/apps/:app/runs/:ts/discard", MeRunDiscard)     // grey out a run
			// Hard-remove a single workflow (loop) from one of the caller's apps.
			me.DELETE("/apps/:app/loops/:loop", MeLoopDelete)
			// Direct workflow compose (composer wizard — instant, no chat LLM).
			me.POST("/workflows/compose", MeComposeWorkflow)
			// Server-truth validation of a composed draft (manifest_lint +
			// pipeline_shape) for the new-workflow wizard's validation card.
			me.POST("/workflows/validate", MeValidateWorkflow)
			// Engine-revamp human checkpoint — approve/revamp a cycle's
			// held actions; writes the engine's side files for next cycle.
			me.POST("/cycles/:app/:loop/:ts/review", MeCycleReview)

			// Workstream E — skills as a first-class surface: inventory
			// (used_by + versions + CI health), catalog discovery, detail.
			me.GET("/skills", MeSkills)
			me.GET("/skills/discover", MeSkillsDiscover)
			me.GET("/skills/:owner/:name", MeSkillDetail)

			// Phase S3-D — knowledge browser. Per-agent bank.jsonl
			// listing + paginated memories with kind filter.
			me.GET("/knowledge/agents", MeKnowledgeAgents)
			me.GET("/knowledge/agents/:id/memories", MeKnowledgeMemories)
			// Marketplace kind=agent consumption: delta-sync a published
			// bank into the caller's tenant KG (subscribe_bank intent).
			me.POST("/knowledge/subscriptions", MeKnowledgeSubscribe)

			// Approval queue — drafts produced by personal-agent's
			// email/draft + calendar/propose skills. The send action
			// enqueues an intent the picker drains (Gmail call lands
			// in the tenant context with their OAuth grant); edit +
			// dismiss are state-only updates.
			me.GET("/drafts", MeDraftsList)
			me.POST("/drafts/:id/send", MeDraftSend)
			me.POST("/drafts/:id/edit", MeDraftEdit)
			me.POST("/drafts/:id/dismiss", MeDraftDismiss)

			// Workflow surface — W1 (unifies xpio loops + n8n workflows).
			// /me/workflows ≈ "list everything you have running" across
			// runtimes; the per-slug detail returns the full definition.
			me.GET("/workflows", MeWorkflows)
			me.GET("/workflows/:slug", MeWorkflowDetail)
			me.POST("/workflows/import-from-n8n", MeImportFromN8n)

			// Runs — unified history across runtimes + SSE state-stream
			// for live "lights" in /studio/runs.
			me.GET("/runs", MeRuns)
			me.GET("/runs/:run_id", MeRunDetail)
			me.POST("/runs/:run_id/mark", MeRunMark)
			me.GET("/runs/stream", MeRunsStream)

			// Fleet — P4. Cross-workflow rollup: per-workflow health +
			// 30d cost/tokens/learning, plus fleet totals.
			me.GET("/portfolio", MePortfolio)

			// Mind — the Improve surface (W4). Per-workflow report
			// cards (plain-English deltas) + on-demand skill evaluation.
			me.GET("/mind/workflow/:slug", MeMindWorkflow)
			me.GET("/mind/skills", MeMindSkills)
			me.POST("/mind/evaluate", MeMindEvaluate)
		}

		// Internal service-to-service surface. The scheduler/picker
		// (Python) calls /usage/charge at cycle-fire time + per LLM /
		// external-API call to atomically check-and-record against the
		// Tier-1 caps. Bridge-secret gated (X-Bridge-Secret header);
		// never reachable from the public surface.
		internal := v1.Group("/internal", RequireBridge())
		{
			internal.POST("/usage/charge", InternalUsageCharge)
			// DB-backed /me/apps intent queue — the scheduler picker claims
			// pending intents (atomic SKIP LOCKED) + posts results back.
			internal.POST("/me-intents/claim", InternalMeIntentsClaim)
			internal.POST("/me-intents/:id/result", InternalMeIntentResult)
			// Decrypted per-(user,app) secrets for the scheduler to inject
			// into the cycle env (pure-UI credential path).
			internal.POST("/app-secrets/fetch", InternalAppSecretsFetch)
			// Cross-node run store — the cycle self-reports each run's metrics
			// here so the Studio trajectory/experiments surfaces (which can't
			// read the scheduler PVC) can reconstruct run history. App-agnostic.
			internal.POST("/app-runs", InternalAppRunRecord)
			// Claude Code quota reporter — each account's cron/stop-hook
			// POSTs here; no user session, only X-Bridge-Secret.
			internal.POST("/claude-quota/report", InternalClaudeQuotaReport)
			// Claude account-pool lease — claude-proxy (lum.id/claude) asks
			// for the healthiest pooled account's access token.
			internal.POST("/claude-token/lease", InternalClaudeTokenLease)
			// Pool-wide account bench — claude-proxy reports a 401/403 here so
			// the cooldown applies across every proxy replica, not just the pod
			// that saw the failure.
			internal.POST("/claude-account/bench", InternalClaudeAccountBench)
			// Field-box fingerprint adoption — each proxy replica reports the
			// client version triples it saw, and reads back ONE aggregated
			// pool. Central because the replicas must present an identical
			// identity per box; adopting per-pod would split it during exactly
			// the version transitions that matter.
			internal.POST("/claude-fingerprint/observe", InternalClaudeFingerprintObserve)
			internal.GET("/claude-fingerprint/pool", InternalClaudeFingerprintPool)
			// Per-user "act as <sub>" bridge credential — claude-proxy mints one
			// to forward LumidOS tool calls to a backend as the resolved user,
			// without the client ever holding a broad backend PAT.
			internal.POST("/mint-user-token", InternalMintUserToken)
			// Claude session recording — claude-proxy posts each turn's full
			// request+response; stored delta-compacted (respects opt-out).
			internal.POST("/claude-transcript", InternalClaudeTranscript)
			// Loops dashboard feed — the lumid-scheduler daemon POSTs its live
			// loop/app state here every discovery pass; cached in Redis so
			// /admin/loops reflects the SCHEDULER's fs, not identity's empty one.
			internal.POST("/loops-summary", InternalLoopsSummary)
		}

		// Inbound webhook for Power Automate's Outlook bridge. The
		// path-segment <token> IS the auth; no Authorization header
		// (Power Automate's HTTP step can set them but the simpler
		// integration is URL-only). Per-user random secret, hashed
		// at rest. Lives outside /me on purpose — Power Automate
		// doesn't have a lum.id session.
		v1.POST("/inbox/power-automate/:token", InboxPowerAutomateReceive)

		// super_admin-only — billing/accounting/secrets endpoints.
		superAdmin := v1.Group("/admin", RequireSuperAdmin())
		{
			// Lightweight probe for nginx auth_request on /quota and other
			// super_admin-only pages. Returns 200 if the session cookie or
			// bearer token belongs to a super_admin, otherwise 401/403.
			superAdmin.GET("/super-check", SuperAdminCheck)
			superAdmin.GET("/oauth-clients", AdminOAuthClientsList)
			// Reset the per-user SHORT-window quota clock. super_admin, not admin:
			// it hands capacity back to users, which is a budget decision.
			superAdmin.POST("/claude-pool/reset-window", AdminClaudePoolResetWindow)
		}

		// admin + super_admin — Claude Code quota dashboard (/quota page) and
		// pool session transcripts.
		adminQuota := v1.Group("/admin", RequireAdmin())
		{
			adminQuota.GET("/claude-quota", AdminClaudeQuota)
			adminQuota.GET("/claude-user-usage", AdminClaudeUserUsage)
			adminQuota.GET("/claude-account-users", AdminClaudeAccountUsers)
			adminQuota.POST("/claude-token", AdminClaudeTokenAdd)
			adminQuota.DELETE("/claude-token/:email", AdminClaudeTokenDelete)
			// Label-only update — move an account between field boxes without
			// re-adding it (which would mean re-running `claude auth login`).
			adminQuota.PATCH("/claude-token/:email", AdminClaudeTokenLabel)
			// Pool session transcripts — admin can view all users' sessions.
			// Per-field-box traffic + via_relay health.
			adminQuota.GET("/claude-field-boxes", AdminClaudeFieldBoxes)
			adminQuota.GET("/claude-sessions", AdminClaudeSessions)
			adminQuota.GET("/claude-sessions/:conv", AdminClaudeSessionDetail)
			adminQuota.DELETE("/claude-sessions/:conv", AdminClaudeSessionDelete)
		}
	}
}
