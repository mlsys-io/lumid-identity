package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

const usersExistsTestSecret = "test-bridge-secret"

func usersExistsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	t.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", usersExistsTestSecret)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/internal", RequireBridge())
	g.POST("/users/exists", InternalUsersExists)
	g.POST("/mint-user-token", InternalMintUserToken)
	r.GET("/api/v1/admin/users/:id", AdminUsersGet)
	return r
}

type usersExistsResp struct {
	RetCode int    `json:"ret_code"`
	Message string `json:"message"`
	Data    *struct {
		Users   map[string]userExistsVerdict `json:"users"`
		Checked int                          `json:"checked"`
		Missing int                          `json:"missing"`
	} `json:"data"`
}

func postUsersExists(t *testing.T, r *gin.Engine, body string, secret string) (int, usersExistsResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/users/exists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Bridge-Secret", secret)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out usersExistsResp
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func stubLookup(t *testing.T, fn func([]string) (map[string]string, error)) {
	t.Helper()
	orig := lookupUserStatuses
	lookupUserStatuses = fn
	t.Cleanup(func() { lookupUserStatuses = orig })
}

func TestUsersExistsReportsFoundAndMissing(t *testing.T) {
	r := usersExistsRouter(t)
	var asked []string
	stubLookup(t, func(ids []string) (map[string]string, error) {
		asked = ids
		return map[string]string{"alive": "active", "parked": "suspended"}, nil
	})
	code, out := postUsersExists(t, r, `{"subs":["alive","gone","parked","alive"," gone "]}`, usersExistsTestSecret)
	if code != http.StatusOK || out.RetCode != 0 || out.Data == nil {
		t.Fatalf("code=%d resp=%+v", code, out)
	}
	if len(asked) != 3 {
		t.Fatalf("lookup asked %v, want the 3 distinct trimmed ids", asked)
	}
	want := map[string]userExistsVerdict{
		"alive":  {Exists: true, Status: "active"},
		"parked": {Exists: true, Status: "suspended"}, // suspended is NOT missing
		"gone":   {Exists: false},
	}
	if len(out.Data.Users) != len(want) {
		t.Fatalf("users=%v", out.Data.Users)
	}
	for id, w := range want {
		if out.Data.Users[id] != w {
			t.Fatalf("users[%s]=%+v want %+v", id, out.Data.Users[id], w)
		}
	}
	if out.Data.Checked != 3 || out.Data.Missing != 1 {
		t.Fatalf("checked=%d missing=%d", out.Data.Checked, out.Data.Missing)
	}
}

// The whole point of the route: a failed query yields NO per-user verdict.
func TestUsersExistsLookupErrorIsNotAMissingUser(t *testing.T) {
	r := usersExistsRouter(t)
	stubLookup(t, func([]string) (map[string]string, error) {
		return nil, errors.New("dial tcp: connection refused")
	})
	code, out := postUsersExists(t, r, `{"subs":["a","b"]}`, usersExistsTestSecret)
	if code != http.StatusServiceUnavailable || out.RetCode != 1503 {
		t.Fatalf("code=%d resp=%+v, want 503/1503", code, out)
	}
	if out.Data != nil {
		t.Fatalf("a failed lookup must carry no verdicts, got %+v", out.Data)
	}
}

func TestUsersExistsRejectsBadBodies(t *testing.T) {
	r := usersExistsRouter(t)
	stubLookup(t, func([]string) (map[string]string, error) {
		t.Fatal("lookup must not run for an invalid body")
		return nil, nil
	})
	many := make([]string, maxUsersExistsBatch+1)
	for i := range many {
		many[i] = strings.Repeat("x", 5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	manyJSON, _ := json.Marshal(map[string]any{"subs": many})
	for name, body := range map[string]string{
		"not json":  `nope`,
		"no subs":   `{}`,
		"empty":     `{"subs":[]}`,
		"blank id":  `{"subs":["a","  "]}`,
		"too large": string(manyJSON),
	} {
		code, out := postUsersExists(t, r, body, usersExistsTestSecret)
		if code != http.StatusBadRequest || out.Data != nil {
			t.Fatalf("%s: code=%d resp=%+v, want 400 without data", name, code, out)
		}
	}
}

func TestUsersExistsRequiresBridgeSecret(t *testing.T) {
	r := usersExistsRouter(t)
	stubLookup(t, func([]string) (map[string]string, error) {
		t.Fatal("lookup must not run without the bridge secret")
		return nil, nil
	})
	for _, secret := range []string{"", "wrong"} {
		code, _ := postUsersExists(t, r, `{"subs":["a"]}`, secret)
		if code != http.StatusUnauthorized {
			t.Fatalf("secret=%q: code=%d, want 401", secret, code)
		}
	}
}

// unreachableDB points common.DB at a port nothing listens on, so every query
// fails the way a dropped MySQL connection does. Hermetic: no server needed.
func unreachableDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "u:p@tcp(127.0.0.1:1)/none?timeout=300ms",
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	orig := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = orig })
}

// Before this change mint-user-token and admin GET /users/:id both answered
// 404 "user not found" for ANY error, and the scheduler parks a tenant's loops
// on exactly that 404 — so a DB blip parked every tenant. All three routes
// must now report the outage as an outage.
func TestDBOutageIsNeverUserNotFound(t *testing.T) {
	unreachableDB(t)
	r := usersExistsRouter(t)

	code, out := postUsersExists(t, r, `{"subs":["a"]}`, usersExistsTestSecret)
	if code != http.StatusServiceUnavailable || out.Data != nil {
		t.Fatalf("users/exists on a dead DB: code=%d resp=%+v", code, out)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/mint-user-token",
		bytes.NewBufferString(`{"sub":"a","audience":"lumid-ecosystem"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", usersExistsTestSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(strings.ToLower(w.Body.String()), "user not found") {
		t.Fatalf("mint on a dead DB: code=%d body=%s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/a", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(strings.ToLower(w.Body.String()), "user not found") {
		t.Fatalf("admin get on a dead DB: code=%d body=%s", w.Code, w.Body.String())
	}
}

// Against a real users table: a present row is exists:true, an absent one is
// exists:false, and mint still says 404 "user not found" for the absent one.
func TestUsersExistsAgainstMySQL(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping users/exists integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	orig := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = orig })

	alive := "00000000-0000-0000-0000-00000uexists"
	ghost := "00000000-0000-0000-0000-000000ughost"
	db.Where("id IN ?", []string{alive, ghost}).Delete(&models.User{})
	if err := db.Create(&models.User{ID: alive, Email: alive + "@test.invalid", Status: "active"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { db.Where("id = ?", alive).Delete(&models.User{}) })

	r := usersExistsRouter(t)
	code, out := postUsersExists(t, r, `{"subs":["`+alive+`","`+ghost+`"]}`, usersExistsTestSecret)
	if code != http.StatusOK || out.Data == nil {
		t.Fatalf("code=%d resp=%+v", code, out)
	}
	if !out.Data.Users[alive].Exists || out.Data.Users[alive].Status != "active" {
		t.Fatalf("alive=%+v", out.Data.Users[alive])
	}
	if out.Data.Users[ghost].Exists {
		t.Fatalf("ghost=%+v", out.Data.Users[ghost])
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/mint-user-token",
		bytes.NewBufferString(`{"sub":"`+ghost+`","audience":"lumid-ecosystem"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bridge-Secret", usersExistsTestSecret)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "user not found") {
		t.Fatalf("mint for a missing user: code=%d body=%s", w.Code, w.Body.String())
	}
}
