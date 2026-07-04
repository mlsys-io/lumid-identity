-- 009_seed_argocd_client.sql
--
-- Seed the OIDC client for Argo CD, the GitOps control plane for the whole
-- fleet, served at https://lum.id/argocd. Argo is a confidential relying
-- party (client_secret in argocd-secret as `oidc.lumid.clientSecret`; the
-- bcrypt hash lives here). Login-less SSO for lum.id super_admins: the
-- id_token/userinfo now carry a `groups: [<role>]` claim (see
-- internal/common/jwt.go IssueIDToken), and Argo's argocd-rbac-cm maps
-- `g, super_admin, role:admin`.
--
-- Client secret rotation: regenerate the raw secret, bcrypt it
--   (python3 -c "import bcrypt;print(bcrypt.hashpw(b'<secret>',bcrypt.gensalt(12)).decode())"),
-- update BOTH this file's secret_hash AND the `oidc.lumid.clientSecret` key
-- in the `argocd-secret` Secret (ns argocd), then restart argocd-server.
-- The placeholder below is a non-functional sentinel; the live hash is
-- applied out-of-band (never commit a real secret hash to git).

USE lumid_identity;

INSERT INTO oauth_clients
  (client_id, secret_hash, name, redirect_uris, grant_types, allowed_scopes, is_public, created_at)
VALUES (
  'argocd',
  'REPLACE_WITH_BCRYPT_HASH_APPLIED_OUT_OF_BAND',
  'Argo CD GitOps control plane',
  'https://lum.id/argocd/auth/callback',
  'authorization_code refresh_token',
  'openid email profile groups',
  FALSE,
  CURRENT_TIMESTAMP
)
ON DUPLICATE KEY UPDATE
  redirect_uris  = VALUES(redirect_uris),
  allowed_scopes = VALUES(allowed_scopes),
  name           = VALUES(name);

SELECT client_id, name, is_public FROM oauth_clients WHERE client_id = 'argocd';
