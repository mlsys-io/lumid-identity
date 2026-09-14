package handler

// Regression guard for the admin-delete revival defect (measured 2026-09-14).
//
// DELETE /admin/users/:id used to delete only the lumid_identity rows. Signup
// dual-writes into QuantArena's legacy MySQL, so the surviving legacy row let
// findUserOrMirror re-create the account on the user's very next login -- with
// status=active, the old password hash, and a NEW sub. The endpoint answered
// 200 "deleted" and wrote an audit row saying so.
//
// These tests exercise the real revival mechanism (findUserOrMirror) rather
// than a proxy for it, and assert the ordering property that makes a partial
// failure safe.
//
//   TEST_MYSQL_DSN='root:testpass@tcp(127.0.0.1:3306)/' \
//     go test ./internal/handler -run AdminUserDeleteLegacy -v

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

const (
	legacyTestIdentityDB = "legacy_del_identity_test"
	legacyTestLQADB      = "legacy_del_lqa_test"
)

// setupLegacyDeleteDBs builds two throwaway schemas: the identity side
// (gorm-migrated) and a hand-rolled LQA side matching the columns the
// production queries actually use.
func setupLegacyDeleteDBs(t *testing.T) (*gorm.DB, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping legacy-delete integration test")
	}
	// TEST_MYSQL_DSN is written both ways in this package: with a database
	// (me_intents_db_test.go) and without. Strip any db + params back to the
	// server root so either shape works.
	base := dsn
	if i := strings.Index(base, ")/"); i >= 0 {
		base = base[:i+2]
	} else if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	admin, err := gorm.Open(mysql.Open(base+"?parseTime=true"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	for _, db := range []string{legacyTestIdentityDB, legacyTestLQADB} {
		admin.Exec("DROP DATABASE IF EXISTS " + db)
		if err := admin.Exec("CREATE DATABASE " + db).Error; err != nil {
			t.Fatalf("create %s: %v", db, err)
		}
	}

	idb, err := gorm.Open(mysql.Open(base+legacyTestIdentityDB+"?parseTime=true"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open identity db: %v", err)
	}
	if err := idb.AutoMigrate(&models.User{}, &models.Session{}, &models.Token{},
		&models.Identity{}, &models.PasswordReset{}, &models.UserAccessGrant{},
		&models.OAuthCode{}, &models.SSHKey{}, &models.AuditLog{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	ldb, err := gorm.Open(mysql.Open(base+legacyTestLQADB+"?parseTime=true"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open lqa db: %v", err)
	}
	// Column set mirrors what findUserOrMirror / introspectLegacyLQA read.
	if err := ldb.Exec(`CREATE TABLE tbl_user (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		email VARCHAR(255), username VARCHAR(255), password_hash VARCHAR(255),
		role VARCHAR(32), status VARCHAR(32), invitation_code VARCHAR(64),
		create_time BIGINT, update_time BIGINT)`).Error; err != nil {
		t.Fatalf("create tbl_user: %v", err)
	}
	if err := ldb.Exec(`CREATE TABLE tbl_rm_personal_access_token (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		user_id BIGINT, token_hash VARCHAR(128), scopes TEXT,
		expires_at BIGINT, revoked_at BIGINT, name VARCHAR(128))`).Error; err != nil {
		t.Fatalf("create tbl_rm_personal_access_token: %v", err)
	}

	common.DB, common.LegacyDB = idb, ldb
	// config.G is a *Config populated at startup from YAML; it is nil in tests.
	prevCfg := config.G
	config.G = &config.Config{}
	config.G.Legacy.Enabled = true

	t.Cleanup(func() {
		admin.Exec("DROP DATABASE IF EXISTS " + legacyTestIdentityDB)
		admin.Exec("DROP DATABASE IF EXISTS " + legacyTestLQADB)
		common.LegacyDB = nil
		config.G = prevCfg
	})
	return idb, ldb
}

func legacyDeleteRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.DELETE("/api/v1/admin/users/:id", func(c *gin.Context) {
		c.Set("admin_user_id", "admin-actor")
		AdminUsersDelete(c)
	})
	return r
}

// seedBothStores creates the user on both sides, the way signup's dual-write
// leaves things, plus a legacy PAT.
func seedBothStores(t *testing.T, idb, ldb *gorm.DB, id, email string) {
	t.Helper()
	if err := idb.Create(&models.User{
		ID: id, Email: email, Name: email, Role: "user",
		Status: "active", PasswordHash: "$argon2id$fake", EmailVerified: true,
	}).Error; err != nil {
		t.Fatalf("seed identity user: %v", err)
	}
	if err := ldb.Exec(`INSERT INTO tbl_user
		(email, username, password_hash, role, status, invitation_code, create_time, update_time)
		VALUES (?, ?, ?, 'user', 'active', '', UNIX_TIMESTAMP(), UNIX_TIMESTAMP())`,
		email, email, "$argon2id$fake").Error; err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	var legacyID int64
	ldb.Raw(`SELECT id FROM tbl_user WHERE email = ? LIMIT 1`, email).Scan(&legacyID)
	if err := ldb.Exec(`INSERT INTO tbl_rm_personal_access_token
		(user_id, token_hash, scopes, expires_at, revoked_at, name)
		VALUES (?, 'deadbeefhash', 'flowmesh:workflows:write', 0, 0, 'legacy-pat')`,
		legacyID).Error; err != nil {
		t.Fatalf("seed legacy pat: %v", err)
	}
}

func doDelete(t *testing.T, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+id, nil)
	w := httptest.NewRecorder()
	legacyDeleteRouter().ServeHTTP(w, req)
	return w
}

// TestAdminUserDeleteLegacyMirrorRemoved is the core guard: after a delete the
// account must not be revivable, and the legacy PAT must not outlive its owner.
func TestAdminUserDeleteLegacyMirrorRemoved(t *testing.T) {
	idb, ldb := setupLegacyDeleteDBs(t)
	const id, email = "11111111-1111-1111-1111-111111111111", "revive-me@yao.lu"
	seedBothStores(t, idb, ldb, id, email)

	// Positive control: the revival path really does fire before the fix's
	// work is done. Without this, a passing test could just mean the mirror
	// was never reachable in this fixture.
	idb.Where("id = ?", id).Delete(&models.User{})
	if u, err := findUserOrMirror(email); err != nil || u == nil {
		t.Fatalf("control: mirror should revive a legacy-only user, got u=%v err=%v", u, err)
	}
	// The mirror just re-created the row under a new sub; clear both sides and
	// reseed so the handler sees the original id.
	idb.Where("email = ?", email).Delete(&models.User{})
	ldb.Exec(`DELETE FROM tbl_user WHERE email = ?`, email)
	ldb.Exec(`DELETE FROM tbl_rm_personal_access_token`)
	seedBothStores(t, idb, ldb, id, email)

	if w := doDelete(t, id); w.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d: %s", w.Code, w.Body.String())
	}

	var identityCount, legacyUsers, legacyPATs int64
	idb.Model(&models.User{}).Where("id = ?", id).Count(&identityCount)
	ldb.Raw(`SELECT COUNT(*) FROM tbl_user WHERE email = ?`, email).Scan(&legacyUsers)
	ldb.Raw(`SELECT COUNT(*) FROM tbl_rm_personal_access_token`).Scan(&legacyPATs)

	if identityCount != 0 {
		t.Errorf("identity row survived: %d", identityCount)
	}
	if legacyUsers != 0 {
		t.Errorf("legacy tbl_user row survived (account is revivable): %d", legacyUsers)
	}
	if legacyPATs != 0 {
		t.Errorf("legacy PAT outlived its user (live credential): %d", legacyPATs)
	}

	// The property that actually matters, via the real mechanism.
	u, err := findUserOrMirror(email)
	if err != nil {
		t.Fatalf("findUserOrMirror: %v", err)
	}
	if u != nil {
		t.Fatalf("account was REVIVED after delete: sub=%s status=%s", u.ID, u.Status)
	}
}

// TestAdminUserDeleteLegacyDuplicateRows covers LQA having no unique index on
// email: one survivor is enough to revive the account.
func TestAdminUserDeleteLegacyDuplicateRows(t *testing.T) {
	idb, ldb := setupLegacyDeleteDBs(t)
	const id, email = "22222222-2222-2222-2222-222222222222", "dupe@yao.lu"
	seedBothStores(t, idb, ldb, id, email)
	// A second legacy row for the same address.
	ldb.Exec(`INSERT INTO tbl_user (email, username, password_hash, role, status,
		invitation_code, create_time, update_time)
		VALUES (?, ?, 'h', 'user', 'active', '', UNIX_TIMESTAMP(), UNIX_TIMESTAMP())`, email, email)

	if w := doDelete(t, id); w.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var n int64
	ldb.Raw(`SELECT COUNT(*) FROM tbl_user WHERE email = ?`, email).Scan(&n)
	if n != 0 {
		t.Errorf("duplicate legacy rows survived: %d", n)
	}
	if u, _ := findUserOrMirror(email); u != nil {
		t.Errorf("revived via duplicate row: sub=%s", u.ID)
	}
}

// TestAdminUserDeleteLegacyFailureRefuses is the ordering property: if the
// legacy leg fails, the endpoint must report failure and leave the identity
// row intact, rather than half-deleting into the revivable state.
func TestAdminUserDeleteLegacyFailureRefuses(t *testing.T) {
	idb, ldb := setupLegacyDeleteDBs(t)
	const id, email = "33333333-3333-3333-3333-333333333333", "legacy-broken@yao.lu"
	seedBothStores(t, idb, ldb, id, email)

	// Break the legacy leg the way a real outage would: the table is gone.
	ldb.Exec(`DROP TABLE tbl_user`)

	w := doDelete(t, id)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when the legacy leg fails, got %d: %s", w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, "legacy") {
		t.Errorf("error should name the legacy mirror, got %s", body)
	}
	var n int64
	idb.Model(&models.User{}).Where("id = ?", id).Count(&n)
	if n != 1 {
		t.Errorf("identity row was deleted despite the legacy failure (unsafe partial): %d", n)
	}
}

// TestAdminUserDeleteLegacyDisabled: with shadow off there is nothing to
// mirror, so delete must still succeed and touch nothing legacy-side.
func TestAdminUserDeleteLegacyDisabled(t *testing.T) {
	idb, _ := setupLegacyDeleteDBs(t)
	config.G.Legacy.Enabled = false
	const id, email = "44444444-4444-4444-4444-444444444444", "no-shadow@yao.lu"
	if err := idb.Create(&models.User{
		ID: id, Email: email, Name: email, Role: "user", Status: "active",
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	if w := doDelete(t, id); w.Code != http.StatusOK {
		t.Fatalf("want 200 with shadow off, got %d: %s", w.Code, w.Body.String())
	}
	var n int64
	idb.Model(&models.User{}).Where("id = ?", id).Count(&n)
	if n != 0 {
		t.Errorf("identity row survived: %d", n)
	}
	users, tokens, err := deleteLegacyUser(email)
	if err != nil || users != 0 || tokens != 0 {
		t.Errorf("disabled shadow should be a no-op, got users=%d tokens=%d err=%v", users, tokens, err)
	}
	_ = fmt.Sprint()
}
