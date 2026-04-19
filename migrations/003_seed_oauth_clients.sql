-- 003_seed_oauth_clients.sql
--
-- Seed the OIDC clients every Lumid subsystem will use.
--
-- Client secrets are bcrypt-hashed here. The plaintexts live in
-- /proj/infra/compose/<service>/.env (gitignored); generate a fresh
-- one with `openssl rand -hex 24` and bcrypt it with:
--   htpasswd -nbBC 10 "" "<secret>" | tr -d ':\n' | sed 's/^\$2y/\$2a/'
--
-- Idempotent — INSERT IGNORE skips rows whose client_id already
-- exists. Update secrets by UPDATE-ing the row, not re-seeding.

USE lumid_identity;

-- Umami analytics (oauth2-proxy sidecar). Public = false so it must
-- send client_secret_basic on the token endpoint.
-- Redirect URI shape follows oauth2-proxy default: <site>/oauth2/callback
INSERT IGNORE INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'umami',
  -- bcrypt('umami-dev-secret-change-me') — rotate in prod
  '$2a$10$sHjfoQlBZ0IKV1e0ABufpeLMGSf6SIu7V4jvdVJiZyjjT9pV/dsI.',
  'Umami self-hosted analytics',
  'https://analytics.lum.id/oauth2/callback\nhttps://analytics.lumid.market/oauth2/callback',
  'authorization_code refresh_token',
  'openid email profile umami:admin',
  FALSE,
  CURRENT_TIMESTAMP
);

-- lumid-cli — device-auth flow for `install.sh` (Phase 7+). Public
-- so no client_secret; PKCE is the only guarantee.
INSERT IGNORE INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'lumid-cli',
  '',
  'LumidOS CLI installer',
  'http://127.0.0.1:5200/callback\nhttp://localhost:5200/callback',
  'authorization_code',
  'openid email profile quantarena:* runmesh:* flowmesh:* lumilake:*',
  TRUE,
  CURRENT_TIMESTAMP
);

-- Runmesh frontend (runmesh.lum.id) — public client, same idea.
INSERT IGNORE INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'runmesh',
  '',
  'Runmesh cloud frontend',
  'https://runmesh.lum.id/auth/callback\nhttps://runmesh.ai/auth/callback',
  'authorization_code refresh_token',
  'openid email profile runmesh:*',
  TRUE,
  CURRENT_TIMESTAMP
);

-- QuantArena (market.lum.id or lumid.market) — the product
-- frontend. The in-browser flow is served by lum.id/auth, but app
-- API calls will still need this client when we migrate off LQA's
-- local login.
INSERT IGNORE INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'quantarena',
  '',
  'Lumid QuantArena',
  'https://market.lum.id/auth/callback\nhttps://lumid.market/auth/callback',
  'authorization_code refresh_token',
  'openid email profile quantarena:*',
  TRUE,
  CURRENT_TIMESTAMP
);

SELECT client_id, name, is_public FROM oauth_clients;
