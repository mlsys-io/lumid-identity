-- 010_claude_pools.sql — DOCUMENTATION COPY ONLY.
--
-- Unlike every other file in this directory, this one is NOT the enforcement
-- path. lumid_identity AutoMigrates on every pod boot and is fully
-- self-deploying (git tag -> CI -> Argo Image Updater rolls it automatically)
-- with no operator step where a numbered migrations/*.sql file gets run by
-- hand — relying on this file alone would silently never execute in
-- production. The actual seed/backfill is idempotent Go code:
-- internal/handler/claude_pool_admin.go's EnsureDefaultClaudePool, invoked
-- from cmd/identity/main.go right after models.AutoMigrate on every boot.
--
-- This file is kept only as a readable reference for what that function
-- does, and for manual replay against a scratch/offline copy of the schema
-- if you ever need to reason about it outside a running identity process.

CREATE TABLE IF NOT EXISTS claude_pools (
  id                    VARCHAR(64)  PRIMARY KEY,
  name                  VARCHAR(128) NOT NULL,
  mode                  VARCHAR(16)  NOT NULL DEFAULT 'distributed',
  owner_sub             VARCHAR(36),
  conservative_ceiling  INT          NOT NULL DEFAULT 0,
  created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  deleted_at            TIMESTAMP    NULL,
  INDEX idx_claude_pools_owner (owner_sub)
);

CREATE TABLE IF NOT EXISTS claude_pool_members (
  pool_id     VARCHAR(64) NOT NULL,
  user_sub    VARCHAR(36) NOT NULL,
  is_primary  BOOLEAN     NOT NULL DEFAULT FALSE,
  added_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  added_by    VARCHAR(36),
  -- Generated column + unique index: enforces "at most one is_primary row
  -- per user_sub" AT THE DB LAYER. MySQL unique indexes never collide on
  -- NULL, so only rows where is_primary=TRUE compete for uniqueness.
  primary_marker VARCHAR(36) AS (IF(is_primary, user_sub, NULL)) STORED,
  PRIMARY KEY (pool_id, user_sub),
  UNIQUE KEY uq_cpm_one_primary (primary_marker),
  INDEX idx_cpm_user (user_sub)
);

ALTER TABLE claude_quota_tokens
  ADD COLUMN IF NOT EXISTS pool_id VARCHAR(64) NOT NULL DEFAULT 'default',
  ADD COLUMN IF NOT EXISTS pool_sort_order INT NOT NULL DEFAULT 0,
  ADD INDEX IF NOT EXISTS idx_cqt_pool (pool_id);

-- ClaudeUserAssignment PK widen — the riskiest step here. A user may belong
-- to more than one pool (ClaudePoolMember is many-to-many), so they need a
-- durable "home account" PER POOL, not one home overall.
ALTER TABLE claude_user_assignments ADD COLUMN pool_id VARCHAR(64) NOT NULL DEFAULT 'default';
UPDATE claude_user_assignments SET pool_id = 'default' WHERE pool_id = '' OR pool_id IS NULL;
ALTER TABLE claude_user_assignments DROP PRIMARY KEY, ADD PRIMARY KEY (pool_id, user_sub);

INSERT IGNORE INTO claude_pools (id, name, mode, owner_sub)
  SELECT 'default', 'Default Pool', 'distributed', id FROM users WHERE email = 'admin@lum.id';

INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary)
  SELECT 'default', id, TRUE FROM users;
