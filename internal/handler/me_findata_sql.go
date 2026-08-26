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
//   * THE PASSWORD IS SHOWN ONCE, AND ALSO STORED ENCRYPTED. Shown once because
//     that is the PAT contract users already know; stored because the
//     session/sandbox has to be able to replay it. See the note below.
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
// ON STORING THE PASSWORD ENCRYPTED AT REST (REVERSED 2026-08-26)
// This file used to argue the opposite, and the argument was sound on its own
// premise: google_grants and app_secrets encrypt because they must be REPLAYED,
// whereas "a SQL password never needs replaying: the user has it, and if they
// lose it they mint another".
//
// That premise no longer holds. A user working in the UI, in chat, or through
// the CLI never handles the password at all — the session/sandbox opens the
// connection on their behalf, so something other than the user must be able to
// replay it. Once a secret is replayable, this repo's convention is
// common.EncryptGrant, the same call app_secrets uses, and the fetch path
// mirrors InternalAppSecretsFetch — the existing "pure-UI credential path".
//
// The cost the old comment named is real: this is a second place to steal it
// from. Three things bound it, and they should stay true.
//   1. It is NEVER returned on a user-authenticated route. MeFindataSQL reports
//      status only. Only the bridge-authed internal endpoint decrypts, so a
//      stolen user PAT cannot read a standing warehouse password.
//   2. The credential it protects is read-only, expires in 7 days, and is
//      capped at 4 connections — the blast radius is a bounded read.
//   3. Revoke clears the ciphertext, so "revoked" means gone here too, not just
//      refused at the proxy.
//
// The password is STILL returned once at mint. That is not redundant: someone
// connecting from their own DBeaver needs it in hand, and that path has no
// sandbox to fetch on their behalf.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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

	pw, expires, err := findataSQLIssue(c.Request.Context(), u.ID, acct.RoleName, &acct)
	if err != nil {
		switch {
		case errors.Is(err, errFindataSQLUnconfigured):
			fail(c, http.StatusServiceUnavailable, 1503, "findata sql provisioning not configured")
		case errors.Is(err, errFindataSQLRNG):
			fail(c, http.StatusInternalServerError, 1500, "rng")
		default:
			fail(c, http.StatusBadGateway, 1502, err.Error())
		}
		return
	}
	writeAudit(c, u.ID, u.ID, "me:findata-sql:mint", "role="+acct.RoleName)

	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"role": acct.RoleName,
		// Shown once. It is also stored encrypted for the session/sandbox to
		// replay, but that copy is never readable on a user-authenticated route,
		// so from the browser's point of view this is still the only sighting.
		"password":   pw,
		"expires_at": expires.Format(time.RFC3339),
		"dsn": fmt.Sprintf(
			"postgresql://%s@sql.lum.id:5432/findata?sslmode=verify-full&sslrootcert=sql-ca.pem",
			acct.RoleName),
		"note": "Copy this now — it will not be shown again. You only need it to " +
			"connect from your own database client; in Studio and in chat the " +
			"query runs as you, with no password to handle. If you do connect " +
			"directly, use sslmode=verify-full — `require` encrypts but verifies " +
			"nothing.",
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
		acct.RoleName).Scan(&stmt); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		fail(c, http.StatusBadGateway, 1502, "warehouse: "+err.Error())
		return
	}

	// Terminating live backends goes through a SECURITY DEFINER wrapper, not
	// pg_terminate_backend directly. sql_provisioner holds the cohort roles
	// WITHOUT their privileges (INHERIT FALSE — the thing keeping it out of the
	// warehouse data), so it also lacks "privileges of the role whose process is
	// being terminated" and a direct call fails with permission denied. The
	// blunt alternative, GRANT pg_signal_backend, would let it kill ANY
	// non-superuser backend including findata-app's; the wrapper bounds it to
	// `sql_*` seats.
	//
	// The error is NOT swallowed. An earlier revision ignored it, which meant a
	// revoke whose termination failed still reported success with
	// sessions_terminated: 0 — indistinguishable from "there was nothing to
	// kill" while the session kept running. That is the precise failure this
	// endpoint exists to prevent, so it must be loud.
	var killed int
	if err := conn.QueryRow(ctx,
		`SELECT pgbouncer_auth.terminate_user_backends($1)`, acct.RoleName).Scan(&killed); err != nil {
		fail(c, http.StatusBadGateway, 1502,
			"credential revoked, but live sessions could NOT be terminated: "+err.Error())
		return
	}

	// Clear the replayable copy too. Without this, "revoked" would be true at
	// the warehouse and false here: the sandbox would keep fetching a password
	// that no longer authenticates, turning a clean revocation into a login
	// failure nobody can explain. Revoked must mean gone in both places.
	common.DB.Model(&acct).Updates(map[string]interface{}{
		"credential_expires_at": nil,
		"password_encrypted":    "",
	})
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

// InternalFindataSQLFetch — POST /api/v1/internal/findata-sql/fetch
//
// Hands the user's warehouse credential to a runtime acting on their behalf:
// the chatbox sandbox, or any surface that opens the connection for them. Same
// shape and same gate as InternalAppSecretsFetch — the established "pure-UI
// credential path" — so there is one pattern here, not two.
//
// BRIDGE-AUTHED, DELIBERATELY. This is the only route that decrypts the stored
// password, and X-Bridge-Secret is held by services, never by a browser or a
// user's PAT. Putting it on /me/ would mean any leaked user token could read a
// standing warehouse password, which is exactly the risk the old
// never-store design was avoiding. Keep it off the user surface.
//
// Returns 404 rather than an empty credential when there is nothing to replay,
// so a caller can tell "this user has no seat" from "this user has a seat and
// the password is blank" — the second would be a bug worth surfacing.
func InternalFindataSQLFetch(c *gin.Context) {
	var body struct {
		UserSub string `json:"user_sub" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}

	var acct models.FindataSQLAccount
	if err := common.DB.Where("user_id = ?", body.UserSub).First(&acct).Error; err != nil {
		fail(c, http.StatusNotFound, 1004, "no warehouse role for this user")
		return
	}
	if acct.PasswordEncrypted == "" {
		fail(c, http.StatusNotFound, 1004, "no credential minted for this user")
		return
	}
	// Expiry is checked HERE as well as at the proxy. The proxy is authoritative
	// and would refuse it anyway, but handing out a password we already know is
	// dead produces a connection failure at the far end of the sandbox, which is
	// a much worse place to diagnose it from.
	if acct.CredentialExpiresAt == nil || !acct.CredentialExpiresAt.After(time.Now()) {
		fail(c, http.StatusGone, 1010, "credential expired — the user must mint again")
		return
	}
	pw, err := common.DecryptGrant(acct.PasswordEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "ok", "data": gin.H{
		"role":       acct.RoleName,
		"password":   pw,
		"host":       "sql.lum.id",
		"port":       5432,
		"database":   "findata",
		"sslmode":    "verify-full",
		"ca_url":     "https://lum.id/findata/sql-ca.pem",
		"expires_at": acct.CredentialExpiresAt.UTC().Format(time.RFC3339),
	}})
}

var (
	errFindataSQLUnconfigured = errors.New("findata sql provisioning not configured")
	errFindataSQLRNG          = errors.New("rng")
)

// findataSQLIssue mints (or rotates) a warehouse password for one role.
//
// Extracted from MeFindataSQLMint so the PAT path can shadow-mint the same
// credential. Every invariant the handler documented lives here now, because
// this is the only place that writes them:
//
//   - BOTH WRITES IN ONE TRANSACTION. pgbouncer authenticates the client
//     against pgbouncer_auth.credentials AND re-authenticates upstream to
//     Postgres as that same role. If only one lands, the client authenticates
//     and then every upstream connection fails — a broken login that presents
//     as a network fault.
//   - The role name is regex-checked by the CALLER before it gets here; it is
//     interpolated into DDL, where there is no placeholder for an identifier.
//   - The encrypted copy is best-effort. The warehouse write is what grants
//     access, so failing the whole mint over a bookkeeping error would trade a
//     working credential for a tidy database.
//
// acct may be nil when the caller has no row loaded; the local mirror is then
// skipped rather than guessed at.
func findataSQLIssue(ctx context.Context, userID, roleName string, acct *models.FindataSQLAccount) (string, time.Time, error) {
	pw, err := findataSQLPassword()
	if err != nil {
		return "", time.Time{}, errFindataSQLRNG
	}
	expires := time.Now().UTC().Add(findataSQLCredTTL)

	opCtx, cancel := context.WithTimeout(ctx, findataSQLOpTimeout)
	defer cancel()
	conn, err := findataSQLConnect(opCtx)
	if err != nil {
		if findataSQLDSN() == "" {
			return "", time.Time{}, errFindataSQLUnconfigured
		}
		return "", time.Time{}, fmt.Errorf("warehouse unreachable: %w", err)
	}
	defer conn.Close(context.Background())

	tx, err := conn.Begin(opCtx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("warehouse: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	var stmt string
	if err := tx.QueryRow(opCtx,
		`SELECT format('ALTER ROLE %I LOGIN PASSWORD %L VALID UNTIL %L',
		               $1::text, $2::text, $3::timestamptz)`,
		roleName, pw, expires).Scan(&stmt); err != nil {
		return "", time.Time{}, fmt.Errorf("warehouse: %w", err)
	}
	if _, err := tx.Exec(opCtx, stmt); err != nil {
		return "", time.Time{}, fmt.Errorf("warehouse: %w", err)
	}
	if _, err := tx.Exec(opCtx, `
		INSERT INTO pgbouncer_auth.credentials (username, password, expires_at, lumid_sub)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username) DO UPDATE
		   SET password = EXCLUDED.password,
		       expires_at = EXCLUDED.expires_at,
		       lumid_sub  = EXCLUDED.lumid_sub,
		       revoked_at = NULL`,
		roleName, pw, expires, userID); err != nil {
		return "", time.Time{}, fmt.Errorf("warehouse: %w", err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return "", time.Time{}, fmt.Errorf("warehouse commit: %w", err)
	}

	if acct != nil {
		updates := map[string]interface{}{
			"credential_expires_at": expires,
			"last_minted_at":        time.Now().UTC(),
		}
		if enc, encErr := common.EncryptGrant(pw); encErr == nil {
			updates["password_encrypted"] = enc
		} else {
			log.Printf("findata-sql: no replayable credential stored for %s: %v", roleName, encErr)
		}
		common.DB.Model(acct).Updates(updates)
	}
	return pw, expires, nil
}

// findataSQLShadowMint issues a warehouse credential as a SIDE EFFECT of
// minting a PAT that carries the findata:sql capability tag.
//
// WHY THE TAG IS NOT THE PRIVILEGE. findata:sql is a capability scope, so
// canGrant lets any active user ask for it — capability tags confer no
// platform access by design. The tag therefore expresses INTENT ("this token
// is for warehouse work"), and entitlement is still decided by the same gate
// as the self-service path: an explicit findata grant plus a provisioned role.
// A user without those gets a PAT with a tag that does nothing, which is the
// correct outcome and not an error worth failing their mint over.
//
// Returns the role name when a credential was issued, "" when it was skipped.
// Never returns an error to the caller: a PAT mint must not fail because a
// side effect did.
func findataSQLShadowMint(ctx context.Context, u models.User) string {
	if !findataSQLEntitled(u) {
		return ""
	}
	var acct models.FindataSQLAccount
	if err := common.DB.Where("user_id = ?", u.ID).First(&acct).Error; err != nil {
		return ""
	}
	if !findataSQLRoleRe.MatchString(acct.RoleName) {
		log.Printf("findata-sql: shadow mint skipped, malformed role %q", acct.RoleName)
		return ""
	}
	if _, _, err := findataSQLIssue(ctx, u.ID, acct.RoleName, &acct); err != nil {
		log.Printf("findata-sql: shadow mint failed for %s: %v", acct.RoleName, err)
		return ""
	}
	return acct.RoleName
}
