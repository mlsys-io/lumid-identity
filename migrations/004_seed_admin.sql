-- 004_seed_admin.sql
--
-- Promote the initial admin. Pass the target email via shell env:
--   docker exec -e LUMID_ADMIN_EMAIL=junyi@lum.id trading_mysql \
--     bash -lc 'envsubst < /tmp/004.sql | mysql ...'
--
-- Idempotent — re-running only UPDATEs the row, never overwrites
-- non-admin data.

USE lumid_identity;

-- Promote the initial admin. Edit the email below (or pipe through
-- sed for automation). Idempotent.
UPDATE users SET role = 'admin'
WHERE email = 'junyi@lum.id' AND role <> 'admin';

SELECT id, email, role, status FROM users WHERE email = 'junyi@lum.id';
