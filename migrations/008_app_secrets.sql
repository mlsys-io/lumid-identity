-- 008_app_secrets.sql — per-(user, xpio-app, key) runtime secrets.
--
-- The structural columns are auto-created by GORM AutoMigrate from
-- models/app_secret.go on every boot. This file exists for the things
-- AutoMigrate doesn't manage cleanly:
--   1. FK to users(id) with CASCADE delete (so revoking a user wipes
--      their secrets), and
--   2. Secondary index on (user_sub, app_slug) so the cloud-runtime's
--      "fetch all secrets this app needs" call doesn't full-scan.
--
-- Idempotent: safe to re-run.
--
-- Flow:
--   1. UI form (P1) or CLI sets a secret via PUT /api/v1/me/apps/:app/secrets/:key.
--      Handler encrypts the value with IDENTITY_GRANT_KEY (AES-256-GCM)
--      and upserts one row here.
--   2. Cloud-side scheduler fetches plaintext at cycle-start via the
--      service-to-service introspect path; local CLI reads it once via
--      the same endpoint and caches in ~/.lumid/apps/<app>/secrets.json
--      (mode 0600).
--   3. UI GET surface returns presence only (`is_set: true|false`) —
--      plaintext never leaves the server outside the runner-bound
--      introspect call.

-- FK + cascade — only added if the constraint name doesn't already exist
-- (AutoMigrate skips FK creation by default).
SET @fk_exists := (
  SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
  WHERE CONSTRAINT_SCHEMA = DATABASE()
    AND TABLE_NAME = 'app_secrets'
    AND CONSTRAINT_NAME = 'fk_app_secrets_user'
);
SET @sql := IF(@fk_exists = 0,
  'ALTER TABLE app_secrets ADD CONSTRAINT fk_app_secrets_user FOREIGN KEY (user_sub) REFERENCES users(id) ON DELETE CASCADE',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Secondary index for "all secrets for one (user, app)" lookups.
CREATE INDEX IF NOT EXISTS idx_app_secrets_user_app ON app_secrets(user_sub, app_slug);
