# lumid-identity

**The identity authority for the Lumid ecosystem.** Single backend that issues JWTs + PATs, validates them (introspect), and hosts the OIDC endpoints that every Lumid subsystem (QuantArena, Runmesh, FlowMesh, Lumilake, Umami) delegates to.

## Status

**Live — sole token authority.** lumid-identity at `https://lum.id` is the single auth authority for the ecosystem: it issues JWTs + `lm_pat_*` PATs (legacy `rm_pat_*` still accepted), validates them via introspect, and hosts the OIDC endpoints. Every other service (QuantArena, Runmesh, FlowMesh, Lumilake, xpcloud) is a bearer-auth consumer that delegates here. As of 2026-07 the stack runs on UpCloud Managed Kubernetes (`lumid-prod2`, sg-sin1); domains are served via the UpCloud LB with acme.sh certs.

> **Historical:** this doc originally described a Phase-1 *shadow* deployment mirroring QuantArena's `trading_community` DB before consumers cut over. That cutover is long complete — the auth-consolidation is GA. See `/proj/CLAUDE.md` "Auth Architecture — one authority on lum.id" for the current contract.

## Stack

- **Go 1.25** + **Gin** + **GORM** (matches LQA — reuses conventions, libraries, devops muscle memory)
- **MySQL** for persistence (new database `lumid_identity` on the existing `trading_mysql` instance — dedicated Postgres is a Phase 8 consideration)
- **Redis** for session blacklist + introspect cache (shared with LQA for now)
- **RS256** JWTs; keys rotated monthly via `signing_keys` table
- PAT hashing via **SHA-256** hash lookup today (argon2id is planned, not yet in place)

## Run

```bash
cd /proj/lumid_identity
go run cmd/identity/main.go -c configs/identity.yaml
# default port 9900
```

## Endpoints (live)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/oauth/introspect` | RFC 7662 — everyone calls this |
| GET | `/.well-known/jwks.json` | RS256 pubkeys for local JWT verify |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/oauth/authorize` | PKCE authorization_code flow start |
| POST | `/oauth/token` | exchange code or refresh token |
| GET | `/oauth/userinfo` | OIDC userinfo |
| POST | `/api/v1/login` | email + password → session cookie |
| POST | `/api/v1/register` | email + password + verification code |
| POST | `/api/v1/oauth/{google,github}/login` | 3rd-party login callbacks |
| POST | `/api/v1/identity/personal-access-tokens` | mint PAT |
| GET | `/api/v1/identity/personal-access-tokens` | list caller's PATs |
| DELETE | `/api/v1/identity/personal-access-tokens/:id` | revoke |
| POST | `/api/v1/send-verification-code` | email OTP for registration |

## Reference

Current auth contract (roles, token formats, session cookie, SSO bridge, Google OAuth for apps): see `/proj/CLAUDE.md` → "Auth Architecture — one authority on lum.id". Additional handlers not shown above: `google_grants.go` (server-mediated Google OAuth), `admin_loops.go` (super-admin loops dashboard), `admin_oauth_clients.go`.
