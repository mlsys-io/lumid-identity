# CLAUDE.md — lumid-identity

This file provides guidance to Claude Code (claude.ai/code) when working in this repository.

**`lumid-identity` is the sole token authority for the entire Lumid ecosystem.** Go + Gin + GORM,
port **9900**. Every other service — QuantArena, Runmesh, FlowMesh, Lumilake, xpcloud, LQT,
claude-proxy, chatbox — is a bearer-auth *consumer* of this service. If you are adding
authentication anywhere in the stack, you are almost certainly adding a consumer, not a new
authority.

> **Where this runs (checked 2026-08-09).** Deployment `lumid-identity` (**2 replicas**, deliberate
> — WebSocket sessions need cross-node reach) in ns `lumid` on cluster `lumid-prod2`, **service**
> tier. Argo CD app `lumid-identity` from `/proj/deploy_infra/k8s-lift/lumid-identity/`. Live image
> was `v0.4.6` (checked 2026-08-10). It is reachable only through the `lumid-landing` nginx, which proxies
> `https://lum.id/api/v1/*`, `/oauth/*` and `/.well-known/*` to `lumid-identity:9900`.
> Database: the shared in-cluster `mysql-trading` (schema `lumid_identity`).
>
> **`VERSION` in this repo reads `0.3.0` and is not the release source** — releases are git tags
> (`v0.3.96`, …) which drive the image tag. Don't trust the file.

## Release / deploy

Tag-driven. Cut a `vX.Y.Z` tag → CI builds `ghcr.io/mlsys-io/lumid-identity:vX.Y.Z` → pin it in
`/proj/deploy_infra/k8s-lift/lumid-identity/kustomization.yaml` → commit to `deploy_infra` branch
`migration/uks` → Argo reconciles. Rollback = git revert the pin.
**Never `kubectl set image`** — `selfHeal: true` reverts it within minutes.
Protocol: `/proj/deploy_infra/k8s-lift/CD-PROTOCOL.md`.

```bash
export KUBECONFIG=~/.kube/lumid-prod2.yaml
kubectl -n lumid logs deploy/lumid-identity --tail 50
kubectl -n lumid rollout status deploy/lumid-identity
```

## Layout

```
cmd/identity/main.go       entry point
internal/handler/          ~123 files. The surface is large; group by prefix:
  auth.go                  login / register / send-code / logout / session cookie
  password_reset.go        forgot + reset
  user.go                  GET/PUT /user, session-bearer
  introspect.go            /oauth/introspect — what every consumer calls
  jwks.go                  /.well-known/jwks.json
  pat.go                   personal access tokens
  oauth_google.go, google_grants.go, microsoft_grants.go   server-mediated OAuth
  internal_mint.go         X-Bridge-Secret internal token minting
  admin_*.go               role-gated dashboards: users, invitations, loops,
                           codebase-repos, tenants, oauth-clients, claude-quota,
                           build/backup/cert status, auth stats, qa summary
  me_agent_*.go            the /me surface behind Studio: apps, agents, chats,
                           artifacts, code, codesearch, cluster, claude-code, …
internal/common/           jwt.go (RS256, IssueJWT + IssueBridgeJWT), signing.go (kid keyring),
                           email.go (Gmail SMTPS), grant_crypto.go (AES-256-GCM),
                           db.go, redis.go
internal/config/           YAML config, env-interpolated
models/                    users, identities, tokens, sessions, oauth_*, password_resets,
                           signing_keys, user_access_grants, google_grants, microsoft_grants,
                           app_secrets, claude_quota/transcripts/user_assignment,
                           me_app_intent, me_app_run, me_artifact, me_pref, ssh_key, usage_event
migrations/                001…009 (009 seeds the argocd oauth client)
configs/identity.yaml      YAML config
docs/unified-auth.md       the shared `lumid_auth` hook-library spec for consumer services
```

## The invariants — do not break these

- **One authority.** Never add a second issuer. A new service authenticates by calling
  `/oauth/introspect` or verifying against `/.well-known/jwks.json`, never by minting its own
  tokens.
- **Three token shapes, all accepted forever:**
  | Prefix | Validation |
  |---|---|
  | `lm_pat_live_*` | SHA-256 hash lookup — the canonical PAT |
  | `rm_pat_live_*` | same table; legacy QuantArena format, kept so no user is broken |
  | JWT (3 dot-segments) | RS256 against the JWKS |
- **`computeAccess(user, service)` precedence, in this order:** `status=suspended` → `none`;
  role `admin|super_admin` → `admin` everywhere; an explicit `user_access_grants` row → its level;
  otherwise `read` plus PAT-scope upgrades. Role trumps grants; status trumps role.
- **`super_admin` is the only role that may promote to `super_admin`**, and the only one allowed
  on billing/accounting. Bootstrap:
  `UPDATE users SET role='super_admin' WHERE email='admin@lum.id';` then re-login — the role is a
  cached JWT claim, so an existing session keeps the old one.
- **`lm_session`** — RS256 JWT, 24 h, `Domain=lum.id; HttpOnly; Secure; SameSite=Lax`. Set by
  `setSessionCookie` in `internal/handler/auth.go`. Apex domain is what makes subdomain SSO work.
  Logout flips `sessions.revoked_at` by `jti`.
- **`GET /api/v1/session-bearer` must stay short-lived and scoped** — 10 min, `aud=runmesh`,
  `scope=runmesh:admin`, minted by `common.IssueBridgeJWT`. It exists precisely so an XSS on
  lum.id cannot replay a general 24 h session against `runmesh.ai`. Widening its TTL or audience
  defeats the whole design.
- **OAuth `client_secret` and refresh-tokens never leave this service.** Refresh-tokens are
  AES-256-GCM encrypted with `IDENTITY_GRANT_KEY` into `google_grants` / `microsoft_grants`. The
  CLI calls `POST /api/v1/identity/google-access-token` per use and caches the short-lived access
  token client-side. `GET …/google-grants` returns status only — never a token — so it is safe for
  the browser.
- **Internal bridge routes are gated by `X-Bridge-Secret`**, not by a user bearer
  (`internal_mint.go`, `/internal/me-intents`). The scheduler drains its intent queue this way
  because there is no shared filesystem between pods on UKS.
- **The per-user Claude pool 5h/7d quota is a HARD fixed window, not a rolling one** (v0.4.4).
  Two anchors per user in `claude_pool_windows`; token totals are still summed live from
  `usage_events` but bounded by the anchor, and an anchor only rolls forward once its window has
  fully elapsed. Do not "simplify" this back to `ts >= now - 5h` — a rolling window makes the
  displayed reset always ≈now for an active user, which is the bug this replaced. Two invariants
  the tests pin (`internal/common/quota_window_test.go`): a **denied** charge and a **dry-run**
  gate check must NEVER create or roll an anchor — a rejected, unrecorded request must not be
  able to start someone's billing clock. Concurrent rolls converge via
  `INSERT … ON DUPLICATE KEY UPDATE` with an elapsed-guard, so no row locking.

## Gotchas

- **Email**: SMTPS 465, authenticates as `yao@lum.id`, sends `From: market@lum.id` (a Workspace
  "Send mail as" alias, so DMARC/SPF pass). Empty `EMAIL_SMTP_HOST` → stdout fallback for dev.
  **Never test with `admin@lum.id` or any yao alias as the recipient** — Gmail dedupes self-sends
  into All Mail, not Inbox, and you will conclude email is broken when it isn't.
- **`/admin/codebase-repos`** shells out to `git`, so the container image must keep the `git`
  package, and `/proj` must stay mounted at `/var/lib/lumid-codebase:ro`.
- **`/admin/loops` reads `xpcloud.yaml` first**, then `manifest.json` — matching the canonical
  discovery priority. Ghost loops usually mean a stale `~/.xp/apps/<app>/.scheduler.json`.
- **Consumers must tolerate both token shapes.** A consumer that only checks for a JWT will reject
  every PAT, and a consumer that only checks the `lm_` prefix will reject every legacy
  `rm_pat_live_*`. See `docs/unified-auth.md`.

## Local development

```bash
go run ./cmd/identity -c configs/identity.yaml    # :9900
go build ./... && go test ./...
```
End-user auth journeys live in `/proj/lumid_e2e/` (Playwright, real Gmail via ImapFlow).

Broader context — the full auth architecture diagram, the Runmesh SSO bridge, and the role matrix
— is in the root `/proj/CLAUDE.md` §4.
