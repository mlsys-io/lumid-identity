-- 005_seed_xp_client.sql
--
-- Register xp.io as an OIDC client in lumid-identity.
--
-- xp.io is the cloud knowledge-graph + apps + research dashboard.
-- All identity lives at lum.id; xp.io is just another relying party.
-- Public client — PKCE required, no client_secret (browser-only flow).
-- Also accepts PAT bearer for CLI/MCP (resolves via /oauth/introspect,
-- no client registration needed for that path).

USE lumid_identity;

INSERT IGNORE INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'xp',
  '',
  'XP.io cloud knowledge graph',
  'https://xp.io/auth/callback',
  'authorization_code refresh_token',
  'openid email profile xp:read xp:write',
  TRUE,
  CURRENT_TIMESTAMP
);

SELECT client_id, name, is_public FROM oauth_clients WHERE client_id = 'xp';
