-- 007_google_grants.sql — refresh-token storage for lum.id-mediated
-- Google OAuth (Gmail + Calendar scopes for the personal-agent xpio app).
--
-- Flow:
--   1. User clicks "Connect Gmail + Calendar" at lum.id/dashboard/account/connect/google.
--   2. Browser does OAuth dance with the existing lumid Google client +
--      requests gmail.modify + calendar scopes on top of openid email profile.
--   3. /api/v1/oauth/google/connect/callback exchanges the code, encrypts
--      the refresh-token with the IDENTITY_GRANT_KEY symmetric key, and
--      stores one row here per user.
--   4. CLI `setup` polls /api/v1/identity/google-token (session-bearer-gated)
--      to receive the refresh-token + client_id, writes it locally mode 0600.
--      The grant stays in this table as a fallback for re-fetch.
--   5. Revoke from /dashboard/account/connect → sets revoked_at; future
--      /api/v1/identity/google-token returns 404 until user re-consents.

CREATE TABLE IF NOT EXISTS google_grants (
  user_sub VARCHAR(36) PRIMARY KEY,
  refresh_token_encrypted TEXT NOT NULL,
  scopes TEXT,
  client_id VARCHAR(255),
  granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  CONSTRAINT fk_google_grants_user FOREIGN KEY (user_sub) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_google_grants_revoked ON google_grants(revoked_at);
