package handler

// The delegation's whole value is its NARROWNESS, so the tests are about what
// a manager cannot reach, not what they can.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func managerRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/me/claude-pool/manage", MeClaudePoolManage)
	r.POST("/api/v1/me/claude-pool/accounts/:email/drain", MeClaudePoolAccountDrain)
	r.POST("/api/v1/me/claude-pool/reset-window", MeClaudePoolResetWindow)
	return r
}

// managerPAT mints a REAL token for the user, because currentUserID resolves
// the caller from the bearer — not from a context key a test could set. A stub
// would have tested the stub: the first draft of this file did exactly that
// and every containment assertion passed on a 401.
func managerPAT(t *testing.T, sub string) string {
	t.Helper()
	tok, row, err := mintPATForUser(sub, "cptest-manager", []string{"claude:proxy"}, nil, "native")
	if err != nil {
		t.Fatalf("mint PAT: %v", err)
	}
	t.Cleanup(func() { common.DB.Where("id = ?", row.ID).Delete(&models.Token{}) })
	return tok
}

func authed(t *testing.T, method, path, body, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	managerRouter().ServeHTTP(w, r)
	return w
}

// Being a member is not being a manager, and being an admin is not either.
// managedPools is the only source of the capability.
func TestManagedPoolsIsEmptyWithoutAnExplicitGrant(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-mgr-a"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'A', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "mgrplain")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, added_at) VALUES (?, ?, TRUE, NOW())`, pool, sub)

	if got := managedPools(sub); len(got) != 0 {
		t.Fatalf("a plain member was treated as a manager: %v", got)
	}
	if managesPool(sub, pool) {
		t.Fatal("managesPool true without a grant")
	}

	db.Exec(`UPDATE claude_pool_members SET is_manager = TRUE WHERE pool_id = ? AND user_sub = ?`, pool, sub)
	if !managesPool(sub, pool) {
		t.Fatal("an explicit grant did not take effect")
	}
}

// A non-manager gets an EMPTY roster, not a 403 — every session asks this on
// load, and the UI hides the section on the empty answer.
func TestManageRosterIsEmptyNotForbiddenForOrdinaryUsers(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	sub := claudePoolTestUser(t, db, "mgrnone")
	w := authed(t, http.MethodGet, "/api/v1/me/claude-pool/manage", "", managerPAT(t, sub))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 with an empty roster: %s", w.Code, w.Body.String())
	}
	for _, k := range []string{`"pools":[]`, `"accounts":[]`} {
		if !strings.Contains(strings.ReplaceAll(w.Body.String(), " ", ""), k) {
			t.Errorf("roster not empty for a non-manager: %s", w.Body.String())
		}
	}
}

// The core containment property: a manager of pool A must not be able to
// pause an account belonging to pool B, and must not learn it exists.
func TestManagerCannotDrainAnAccountInAnotherPool(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	poolA, poolB := "cptest-mgr-own", "cptest-mgr-other"
	for _, p := range []string{poolA, poolB} {
		db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, ?, 'distributed')`, p, p)
		cleanupClaudePool(t, db, p)
	}
	sub := claudePoolTestUser(t, db, "mgrown")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, poolA, sub)

	foreign := "cptest-foreign@acct"
	db.Exec(`INSERT IGNORE INTO claude_quota_tokens (email, value_encrypted, pool_id) VALUES (?, 'x', ?)`, foreign, poolB)
	t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_tokens WHERE email = ?`, foreign) })

	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+foreign+"/drain",
		`{"draining":true}`, managerPAT(t, sub))

	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-pool drain returned %d, want 404: %s", w.Code, w.Body.String())
	}
	var row models.ClaudeQuotaToken
	common.DB.Where("email = ?", foreign).First(&row)
	if row.DrainingSince != nil {
		t.Fatal("an account in another pool was actually paused")
	}
}

// The admin form of reset-window treats an omitted user as "everyone". A
// delegate must never get that shape — an omitted field defaulting to
// estate-wide is the worst possible way to make that mistake.
func TestManagerCannotResetEveryone(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-mgr-reset"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'R', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "mgrreset")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, pool, sub)

	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/reset-window", `{}`, managerPAT(t, sub))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty body returned %d, want 400 — it must not mean 'reset everyone': %s", w.Code, w.Body.String())
	}
}

// The denial tests above would all pass against a handler that 404s
// unconditionally. This is the one that says the capability actually works:
// a manager CAN pause an account in their own pool, and the pause lands.
func TestManagerCanDrainTheirOwnPoolsAccount(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-mgr-positive"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'P', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "mgrpos")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, pool, sub)

	// TWO accounts: the last-usable-account guard would otherwise refuse, and
	// that refusal would look exactly like the capability not working.
	mine, spare := "cptest-mine@acct", "cptest-spare@acct"
	for _, e := range []string{mine, spare} {
		db.Exec(`INSERT IGNORE INTO claude_quota_tokens (email, value_encrypted, pool_id) VALUES (?, 'x', ?)`, e, pool)
		email := e
		t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_tokens WHERE email = ?`, email) })
	}

	tok := managerPAT(t, sub)
	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+mine+"/drain",
		`{"draining":true,"reason":"test"}`, tok)
	if w.Code != http.StatusOK {
		t.Fatalf("manager could not pause their OWN pool's account: status=%d %s", w.Code, w.Body.String())
	}
	var row models.ClaudeQuotaToken
	common.DB.Where("email = ?", mine).First(&row)
	if row.DrainingSince == nil {
		t.Fatal("drain returned 200 but the account was not actually paused")
	}

	// And resume puts it back.
	if w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+mine+"/drain",
		`{"draining":false}`, tok); w.Code != http.StatusOK {
		t.Fatalf("resume failed: status=%d %s", w.Code, w.Body.String())
	}
	// FRESH struct, deliberately. Re-scanning into the already-populated `row`
	// leaves a *time.Time holding its old value when the column comes back
	// NULL, so the previous version of this assertion failed against a handler
	// that had resumed correctly — the test was reading its own stale memory.
	var after models.ClaudeQuotaToken
	common.DB.Where("email = ?", mine).First(&after)
	if after.DrainingSince != nil {
		t.Fatalf("resume returned 200 but the account is still paused (draining_since=%v)", after.DrainingSince)
	}
}

// The last-usable-account guard: a delegate must not be able to take their own
// pool offline. Same refusal the estate-wide admin endpoint makes.
func TestManagerCannotPauseTheLastUsableAccount(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-mgr-last"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'L', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "mgrlast")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, pool, sub)

	only := "cptest-only@acct"
	db.Exec(`INSERT IGNORE INTO claude_quota_tokens (email, value_encrypted, pool_id) VALUES (?, 'x', ?)`, only, pool)
	t.Cleanup(func() { db.Exec(`DELETE FROM claude_quota_tokens WHERE email = ?`, only) })

	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/accounts/"+only+"/drain",
		`{"draining":true}`, managerPAT(t, sub))
	if w.Code != http.StatusConflict {
		t.Fatalf("pausing the last usable account returned %d, want 409: %s", w.Code, w.Body.String())
	}
}

// IsManager is a property OF a membership, so a manager is ALWAYS a member of
// the pool they manage — meaning the share-a-pool check passes on their own
// sub. Without an explicit self-refusal a delegate could reset their own
// clock on demand: an unlimited personal quota, from a capability whose
// estate-wide equivalent is super_admin precisely because it hands out budget.
func TestManagerCannotResetTheirOwnClock(t *testing.T) {
	db := setupClaudePoolTestDB(t)
	pool := "cptest-mgr-self"
	db.Exec(`INSERT IGNORE INTO claude_pools (id, name, mode) VALUES (?, 'S', 'distributed')`, pool)
	cleanupClaudePool(t, db, pool)
	sub := claudePoolTestUser(t, db, "mgrself")
	db.Exec(`INSERT IGNORE INTO claude_pool_members (pool_id, user_sub, is_primary, is_manager, added_at) VALUES (?, ?, TRUE, TRUE, NOW())`, pool, sub)

	w := authed(t, http.MethodPost, "/api/v1/me/claude-pool/reset-window",
		`{"user_sub":"`+sub+`"}`, managerPAT(t, sub))
	if w.Code != http.StatusForbidden {
		t.Fatalf("self-reset returned %d, want 403 — a manager must not be able to hand themselves budget: %s",
			w.Code, w.Body.String())
	}
}
