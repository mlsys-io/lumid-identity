-- 006_seed_grafana_client.sql
--
-- Seed the OIDC client for Grafana behind oauth2-proxy at lum.id/grafana.
-- Client secret rotation: regenerate the raw secret, bcrypt it
-- (htpasswd -nbBC 10 "" "<secret>" | tr -d ':\n' | sed 's/^\$2y/\$2a/'),
-- update both this file and the corresponding OAuth env in
-- /proj/infra/compose/observability/.env, then re-run.

USE lumid_identity;

INSERT INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'grafana',
  '$2b$12$F.TbvfXjsTITqtumruZT9.Wrs7layPOmAsPZT/hjOZkRrM5UCcR2C',
  'Lumid ops Grafana',
  'https://lum.id/grafana/oauth2/callback',
  'authorization_code refresh_token',
  'openid email profile',
  FALSE,
  CURRENT_TIMESTAMP
)
ON DUPLICATE KEY UPDATE
  secret_hash   = VALUES(secret_hash),
  redirect_uris = VALUES(redirect_uris),
  name          = VALUES(name);

SELECT client_id, name, is_public FROM oauth_clients WHERE client_id = 'grafana';
