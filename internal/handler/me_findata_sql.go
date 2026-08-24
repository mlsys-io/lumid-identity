package handler

// Self-service FinData SQL credentials.
//
// A researcher with a `findata` grant mints their own Postgres password for
// sql.lum.id here, instead of an operator generating one and sending it over a
// side channel. Full design: deploy_infra k8s-lift/findata-sql/README.md §8.
//
// THE SHAPE, AND WHY
//
//   * A ROLE IS AN ENTITLEMENT; A CREDENTIAL IS SEPARATE. Roles are created
//     NOLOGIN with no password by provision-sql-users.sh. Minting is what makes
//     one usable. So an entitled-but-never-minted user gets `FATAL: no such
//     user`, and provisioning a hundred roles distributes nothing.
//
//   * THE PASSWORD IS SHOWN ONCE. Same contract as a PAT. It is not stored
//     anywhere on this side — see the note on encryption below, which is a
//     deliberate departure from google_grants.
//
//   * IT MUST BE WRITTEN IN TWO PLACES, TOGETHER. pgbouncer authenticates the
//     client against pgbouncer_auth.credentials AND re-authenticates upstream
//     to Postgres as that same role. So the role's own password and the
//     credential row must match, or the client authenticates and every upstream
//     connection fails — the confusing two-hop failure documented in that
//     README. Both writes go in ONE transaction for exactly that reason.
//
//   * IDENTITY HOLDS A NARROW CREDENTIAL, NOT SUPERUSER. It connects as
//     `sql_provisioner`: CREATEROLE (which since PG16 owns only roles it
//     created), admin-on-lumid_reader WITHOUT membership, and rw on one table.
//     It cannot read a single warehouse row. That is what makes it acceptable
//     for the token authority to talk to the warehouse at all.
//
// ON NOT ENCRYPTING THE PASSWORD AT REST HERE
// google_grants and app_secrets store their secrets with common.EncryptGrant
// because they must be REPLAYED later (a refresh token is useless if you cannot
// read it back). A SQL password never needs replaying: the user has it, and if
// they lose it they mint another. Storing it — encrypted or not — would add a
// second place to steal it from and buy nothing. So it is generated, written to
// Postgres, returned once, and dropped.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const (
	// 7 days. GUI clients (DBeaver, pgAdmin, Metabase) store a password in a
	// connection profile, so a short TTL is not "more secure", it is unusable —
	// people work around it, typically by writing the password somewhere worse.
	// A week is short enough that a leaked credential expires on its own and
	// long enough that nobody routes around it.
	findataSQLCredTTL = 7 * 24 * time.Hour

	// The provisioner is only ever running four short statements. A generous
	// bound still fails fast if the tailnet hop to the warehouse is down.
	findataSQLDialTimeout = 10 * time.Second
	findataSQLOpTimeout   = 20 * time.Second
)

// Defence in depth: role names come from our own findata_sql_accounts table, so
// they are already trusted — but this string is interpolated into DDL, where
// there is no placeholder syntax for an identifier. Anything that fails this
// never reaches the warehouse.
var findataSQLRoleRe = regexp.MustCompile(`^sql_[a-z0-9_]{1,58}$`)

func findataSQLDSN() string { return strings.TrimSpace(os.Getenv("FINDATA_PROVISIONER_DSN")) }

// findataSQLConnect dials the warehouse per operation rather than holding a
// pool. Minting is rare, and identity runs replicas:2 against a warehouse whose
// max_connections is 200 and already shared with findata-app and the data lake
// — a standing pool here would consume that ceiling permanently to serve an
// operation that happens a few times a week.
func findataSQLConnect(ctx context.Context) (*pgx.Conn, error) {
	dsn := findataSQLDSN()
	if dsn == "" {
		return nil, fmt.Errorf("findata sql provisioning not configured")
	}
	dialCtx, cancel := context.WithTimeout(ctx, findataSQLDialTimeout)
	defer cancel()
	return pgx.Connect(dialCtx, dsn)
}

// findataSQLEntitled reports whether the user may hold a warehouse login.
//
// Deliberately reads the explicit grant row rather than computeAccess(): every
// active user defaults to `read` on any registered service (admin_users.go,
// `best := "read"`), so computeAccess would entitle the entire user base to the
// warehouse the moment `findata` was added to accessServices. A warehouse seat
// is granted, never defaulted. Admins are exempt, matching every other surface.
func findataSQLEntitled(u models.User) bool {
	if u.Status != "active" {
		return false
	}
	if u.Role == "admin" || u.Role == "super_admin" {
		return true
	}
	var g models.UserAccessGrant
	if err := common.DB.Where("user_id = ? AND service = ?", u.ID, "findata").
		First(&g).Error; err != nil {
		return false
	}
	return g.Level != "" && g.Level != "none"
}

func findataSQLLoadUser(c *gin.Context) (models.User, bool) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return models.User{}, false
	}
	var u models.User
	if err := common.DB.Where("id = ?", userID).First(&u).Error; err != nil {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return models.User{}, false
	}
	return u, true
}

// MeFindataSQL — GET /api/v1/me/findata-sql
//
// Always 200 for an authenticated caller: an un-entitled user needs to be told
// they are not entitled and what to do about it, not handed a 403 to decode.
func MeFindataSQL(c *gin.Context) {
	u, ok := findataSQLLoadUser(c)
	if !ok {
		return
	}
	entitled := findataSQLEntitled(u)

	var acct models.FindataSQLAccount
	hasAcct := common.DB.Where("user_id = ?", u.ID).First(&acct).Error == nil

	data := gin.H{
		"entitled":  entitled,
		"host":      "sql.lum.id",
		"port":      5432,
		"database":  "findata",
		"sslmode":   "verify-full",
		"ca_url":    "https://lum.id/findata/sql-ca.pem",
		"ttl_days":  int(findataSQLCredTTL.Hours() / 24),
		"available": findataSQLDSN() != "",
	}
	switch {
	case !entitled:
		data["reason"] = "no findata grant — ask an operator for warehouse access"
	case !hasAcct:
		data["reason"] = "entitled, but no warehouse role provisioned yet"
	default:
		data["role"] = acct.RoleName
		data["last_minted_at"] = acct.LastMintedAt
		data["credential_expires_at"] = acct.CredentialExpiresAt
		data["credential_active"] = acct.CredentialExpiresAt != nil &&
			acct.CredentialExpiresAt.After(time.Now())
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": data})
}

// MeFindataSQLMint — POST /api/v1/me/findata-sql/credential
//
// Issues (or rotates) the caller's warehouse password. Returns it exactly once.
func MeFindataSQLMint(c *gin.Context) {
	u, ok := findataSQLLoadUser(c)
	if !ok {
		return
	}
	if !findataSQLEntitled(u) {
		fail(c, http.StatusForbidden, 1005,
			"no findata grant — warehouse access is granted by an operator, not self-served")
		return
	}
	var acct models.FindataSQLAccount
	if err := common.DB.Where("user_id = ?", u.ID).First(&acct).Error; err != nil {
		// Entitled but unprovisioned. Say so precisely: the fix is an operator
		// running provision-sql-users.sh, not anything the user can do.
		fail(c, http.StatusConflict, 1006,
			"entitled, but no warehouse role exists yet — an operator must provision one")
		return
	}
	if !findataSQLRoleRe.MatchString(acct.RoleName) {
		fail(c, http.StatusInternalServerError, 1500, "stored role name is not well-formed")
		return
	}

	pw, err := findataSQLPassword()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rng")
		return
	}
	expires := time.Now().UTC().Add(findataSQLCredTTL)

	ctx, cancel := context.WithTimeout(c.Request.Context(), findataSQLOpTimeout)
	defer cancel()
	conn, err := findataSQLConnect(ctx)
	if err != nil {
		if findataSQLDSN() == "" {
			fail(c, http.StatusServiceUnavailable, 1503, "findata sql provisioning not configured")
			return
		}
		fail(c, http.StatusBadGateway, 1502, "warehouse unreachable: "+err.Error())
		return
	}
	defer conn.Close(context.Background())

	// ONE transaction. The role password and the credential row must move
	// together: if only the row lands, pgbouncer authenticates the client and
	// then fails upstream; if only the role lands, the client cannot get in at
	// all. Either half alone is a broken login that looks like a network fault.
	tx, err := conn.Begin(ctx)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// DDL takes no placeholders for identifiers or passwords, hence quote_ident
	// / quote_literal via format(). The role name is regex-checked above and the
	// password is generated here, so neither is attacker-controlled; this is the
	// belt to that braces.
	var stmt string
	if err := tx.QueryRow(ctx,
		`SELECT format('ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',
		               $1::text, $2::text, $3::timestamptz)`,
		acct.RoleName, pw, expires).Scan(&stmt); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}
	if _, err := tx.Exec(ctx, stmt); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}

	// The credential pgbouncer's auth_query resolves. Plaintext by design — a
	// SCRAM verifier cannot be used to log INTO a server, only to verify a
	// client, so a verifier here breaks the upstream leg. See the README.
	if _, err := tx.Exec(ctx, `
		INSERT INTO pgbouncer_auth.credentials (username, password, expires_at, lumid_sub)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username) DO UPDATE
		   SET password = EXCLUDED.password,
		       expires_at = EXCLUDED.expires_at,
		       lumid_sub  = EXCLUDED.lumid_sub,
		       revoked_at = NULL`,
		acct.RoleName, pw, expires, u.ID); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse commit: "+err.Error())
		return
	}

	now := time.Now().UTC()
	common.DB.Model(&acct).Updates(map[string]interface{}{
		"credential_expires_at": expires,
		"last_minted_at":        now,
	})
	writeAudit(c, u.ID, u.ID, "me:findata-sql:mint", "role="+acct.RoleName)

	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"role":       acct.RoleName,
		"password":   pw, // shown once, never retrievable again
		"expires_at": expires.Format(time.RFC3339),
		"dsn": fmt.Sprintf(
			"postgresql://%s@sql.lum.id:5432/findata?sslmode=verify-full&sslrootcert=sql-ca.pem",
			acct.RoleName),
		"note": "Copy this now — it is not stored and cannot be shown again. " +
			"Fetch the CA from https://lum.id/findata/sql-ca.pem and use " +
			"sslmode=verify-full; `require` encrypts but verifies nothing.",
	}})
}

// MeFindataSQLRevoke — DELETE /api/v1/me/findata-sql/credential
func MeFindataSQLRevoke(c *gin.Context) {
	u, ok := findataSQLLoadUser(c)
	if !ok {
		return
	}
	var acct models.FindataSQLAccount
	if err := common.DB.Where("user_id = ?", u.ID).First(&acct).Error; err != nil {
		fail(c, http.StatusNotFound, 1004, "no warehouse role for this account")
		return
	}
	if !findataSQLRoleRe.MatchString(acct.RoleName) {
		fail(c, http.StatusInternalServerError, 1500, "stored role name is not well-formed")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), findataSQLOpTimeout)
	defer cancel()
	conn, err := findataSQLConnect(ctx)
	if err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse unreachable: "+err.Error())
		return
	}
	defer conn.Close(context.Background())

	// Three steps, and all three are needed. Clearing the credential stops NEW
	// connections; NOLOGIN stops them at the backend too; terminating the
	// backends is what actually disconnects anyone already in. A live Postgres
	// session re-checks nothing once established — unlike every other
	// revocation in this codebase, where the consumer re-validates on its next
	// call and a flipped flag is therefore sufficient.
	if _, err := conn.Exec(ctx,
		`UPDATE pgbouncer_auth.credentials SET revoked_at = now() WHERE username = $1`,
		acct.RoleName); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}
	var stmt string
	if err := conn.QueryRow(ctx, `SELECT format('ALTER ROLE %I NOLOGIN', $1::text)`,
		acct.RoleName).Scan(&stmt); err == nil {
		_, _ = conn.Exec(ctx, stmt)
	}
	var killed int
	_ = conn.QueryRow(ctx, `
		SELECT count(*) FROM (
			SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1
		) t`, acct.RoleName).Scan(&killed)

	common.DB.Model(&acct).Updates(map[string]interface{}{"credential_expires_at": nil})
	writeAudit(c, u.ID, u.ID, "me:findata-sql:revoke",
		fmt.Sprintf("role=%s sessions_terminated=%d", acct.RoleName, killed))

	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"role":                acct.RoleName,
		"sessions_terminated": killed,
		"note":                "Credential revoked and live sessions terminated. Mint again to regain access.",
	}})
}

// findataSQLPassword returns a 32-char alphanumeric password.
//
// Alphanumeric on purpose: this string is pasted into psql connection strings,
// ODBC DSNs and GUI profile fields, where punctuation gets mangled by quoting
// rules that differ per client. 32 chars of [A-Za-z0-9] is ~190 bits — the
// entropy loss versus a full symbol set is irrelevant next to the support cost.
func findataSQLPassword() (string, error) {
	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(buf)
	s = strings.NewReplacer("-", "", "_", "").Replace(s)
	if len(s) < 32 {
		return "", fmt.Errorf("short rng")
	}
	return s[:32], nil
}

// findataSQLNewAccountID is used by the provisioning backfill.
func findataSQLNewAccountID() string { return uuid.NewString() }
