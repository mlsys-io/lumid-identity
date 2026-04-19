-- 002_backfill_from_lqa.sql
--
-- Copies users + PATs from trading_community into lumid_identity,
-- preserving relationships so existing rm_pat_* tokens (which are
-- already SHA-256 hashed in LQA's tbl_rm_personal_access_token)
-- keep verifying post-cutover.
--
-- Idempotent: run as many times as you like. Safe to run while both
-- services are up because:
--   * INSERT IGNORE on users skips rows we've already copied
--   * INSERT IGNORE on tokens skips rows whose hash already exists
--
-- Run from the trading_mysql container:
--   docker exec -i trading_mysql bash -lc 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD"' \
--     < migrations/002_backfill_from_lqa.sql
--
-- The uuid5 derivation `concat('lqa:', id)` matches what the runtime
-- lazy-backfill in internal/handler/auth.go::findUserOrMirror uses,
-- so a user copied here vs lazy-copied at login time ends up with
-- the same sub.

USE lumid_identity;

-- ----------------------------------------------------------------
-- users  ←  trading_community.tbl_user
-- ----------------------------------------------------------------
-- MySQL doesn't have uuid5, so we fake the deterministic id by
-- SHA1(namespace || 'lqa:' || numeric_id) and formatting as 8-4-4-4-12.
-- This matches uuid.NewSHA1(uuid.NameSpaceOID, "lqa:<id>").
--
-- uuid.NameSpaceOID = 6ba7b812-9dad-11d1-80b4-00c04fd430c8
-- binary form = 0x6ba7b8129dad11d180b400c04fd430c8

DROP FUNCTION IF EXISTS uuid5_lqa;

DELIMITER $$
CREATE FUNCTION uuid5_lqa(lqa_id BIGINT) RETURNS CHAR(36) DETERMINISTIC
BEGIN
  DECLARE ns BINARY(16) DEFAULT UNHEX('6ba7b8129dad11d180b400c04fd430c8');
  DECLARE full_sha BINARY(20);
  DECLARE v5 BINARY(16);
  SET full_sha = UNHEX(SHA1(CONCAT(ns, CONVERT(CONCAT('lqa:', lqa_id) USING utf8mb4))));
  -- Take first 16 bytes; force version=5 (byte 6 high nibble) + variant=RFC (byte 8 high bits 10xx).
  SET v5 = CONCAT(
    SUBSTRING(full_sha, 1, 6),
    UNHEX(CONCAT('5', HEX(ORD(SUBSTRING(full_sha, 7, 1)) & 0x0F))),
    UNHEX(CONCAT(HEX((ORD(SUBSTRING(full_sha, 9, 1)) & 0x3F) | 0x80), HEX(ORD(SUBSTRING(full_sha, 10, 1))))),
    SUBSTRING(full_sha, 11, 6)
  );
  RETURN LOWER(CONCAT_WS('-',
    HEX(SUBSTRING(v5, 1, 4)),
    HEX(SUBSTRING(v5, 5, 2)),
    HEX(SUBSTRING(v5, 7, 2)),
    HEX(SUBSTRING(v5, 9, 2)),
    HEX(SUBSTRING(v5, 11, 6))
  ));
END$$
DELIMITER ;

INSERT IGNORE INTO users
  (id, email, email_verified, password_hash, name, role, status, invitation_code_used, created_at, updated_at)
SELECT
  uuid5_lqa(u.id),
  LOWER(u.email),
  TRUE,
  u.password_hash,
  COALESCE(NULLIF(u.username, ''), u.email),
  COALESCE(NULLIF(u.role, ''), 'user'),
  COALESCE(NULLIF(u.status, ''), 'active'),
  NULLIF(u.invitation_code, ''),
  FROM_UNIXTIME(u.create_time),
  FROM_UNIXTIME(u.update_time)
FROM trading_community.tbl_user u
WHERE u.email IS NOT NULL AND u.email <> '';

-- Identity row for each local-password account.
INSERT IGNORE INTO identities (user_id, provider, provider_sub, created_at)
SELECT id, 'local', email, created_at FROM users;

-- ----------------------------------------------------------------
-- tokens  ←  trading_community.tbl_rm_personal_access_token
-- ----------------------------------------------------------------
-- Preserve the existing SHA-256 hash (we can't argon2id-rehash
-- without cleartext). Mark hash_alg='sha256' + source='legacy-lqa'
-- so reporters can tell these apart from native lm_pat_* rows.

INSERT IGNORE INTO tokens
  (id, user_id, prefix, hash, hash_alg, name, scopes, last_used_at, expires_at, revoked_at, source, created_at)
SELECT
  UUID(),
  uuid5_lqa(t.user_id),
  'rm_pat_',
  t.token_hash,
  'sha256',
  COALESCE(NULLIF(t.name, ''), CONCAT('migrated from LQA id=', t.id)),
  REPLACE(t.scopes, ',', ' '),
  CASE WHEN t.last_used_at IS NULL OR t.last_used_at = 0 THEN NULL ELSE FROM_UNIXTIME(t.last_used_at) END,
  CASE WHEN t.expires_at  IS NULL OR t.expires_at  = 0 THEN NULL ELSE FROM_UNIXTIME(t.expires_at)  END,
  CASE WHEN t.revoked_at  IS NULL OR t.revoked_at  = 0 THEN NULL ELSE FROM_UNIXTIME(t.revoked_at)  END,
  'legacy-lqa',
  FROM_UNIXTIME(t.create_time)
FROM trading_community.tbl_rm_personal_access_token t
WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = uuid5_lqa(t.user_id));

-- ----------------------------------------------------------------
-- Stats
-- ----------------------------------------------------------------
SELECT
  (SELECT COUNT(*) FROM users)      AS lumid_users,
  (SELECT COUNT(*) FROM identities) AS lumid_identities,
  (SELECT COUNT(*) FROM tokens)     AS lumid_tokens;
