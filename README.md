# lumid-identity

**The identity authority for the Lumid ecosystem.** Single backend that issues JWTs + PATs, validates them (introspect), and hosts the OIDC endpoints that every Lumid subsystem (QuantArena, Runmesh, FlowMesh, Lumilake, Umami) delegates to.

## Status

Phase 1 — **shadow** deployment. The service runs at `identity.lum.id:9900` and mirrors the auth data from QuantArena's `trading_community` DB. Consumers (LQA, Runmesh, …) haven't cut over yet; this service just has to answer introspect queries identically so we can flip traffic in Phase 3.

## Stack

- **Go 1.25** + **Gin** + **GORM** (matches LQA — reuses conventions, libraries, devops muscle memory)
- **MySQL** for persistence (new database `lumid_identity` on the existing `trading_mysql` instance — dedicated Postgres is a Phase 8 consideration)
- **Redis** for session blacklist + introspect cache (shared with LQA for now)
- **RS256** JWTs; keys rotated monthly via `signing_keys` table
- **argon2id** for PAT hashing (upgrade from LQA's plain SHA-256)

## Run

```bash
cd /proj/lumid_identity
go run cmd/identity/main.go -c configs/identity.yaml
# default port 9900
```

## Endpoints (target)

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

## Plan reference

Full phased migration: `.claude_junyi/plans/parsed-dancing-yeti.md`.
