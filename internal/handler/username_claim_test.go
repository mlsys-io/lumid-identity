package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

func TestClaimCheckLogin(t *testing.T) {
	t.Setenv("RESERVED_USERNAMES", "junyi, Ruixuan ,ubuntu")
	for _, c := range []struct {
		in      string
		want    string
		wantErr error
	}{
		{"junyi", "junyi", nil},
		{" RUIXUAN ", "ruixuan", nil},
		{"newperson", "", errClaimNotHostLogin}, // not an existing host login: pick it with PUT instead
		{"root", "", errClaimNotHostLogin},      // system account, never claimable
		{"ubuntu", "", errClaimNotHostLogin},    // system account even when listed as a host login
		{"j", "", errUsernameInvalid},
		{"1junyi", "", errUsernameInvalid},
		{"jun yi", "", errUsernameInvalid},
	} {
		got, err := checkClaimLogin(c.in)
		if !errors.Is(err, c.wantErr) || got != c.want {
			t.Errorf("checkClaimLogin(%q) = (%q, %v), want (%q, %v)", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestClaimBoundRefusal(t *testing.T) {
	for _, c := range []struct {
		boundTo string
		held    bool
		want    error
	}{
		{"", false, nil},
		{"me", false, errClaimYours},
		{"other", false, errClaimBound},
		{"", true, errClaimBound}, // someone's previous name stays theirs
	} {
		if got := boundRefusal("me", c.boundTo, c.held); !errors.Is(got, c.want) {
			t.Errorf("boundRefusal(me, %q, %v) = %v, want %v", c.boundTo, c.held, got, c.want)
		}
	}
}

func TestClaimCodeHash(t *testing.T) {
	code, err := newClaimCode()
	if err != nil || !strings.HasPrefix(code, claimCodePrefix) || len(code) != len(claimCodePrefix)+2*claimCodeRandLen {
		t.Fatalf("newClaimCode = %q, %v", code, err)
	}
	if len(code)+1 > 64 {
		t.Fatalf("code + newline must fit the verifier's 64-byte cap: %d", len(code)+1)
	}
	other, _ := newClaimCode()
	if other == code {
		t.Fatal("two codes are equal")
	}
	h := hashClaimCode(code)
	if len(h) != 64 || strings.Contains(h, code) {
		t.Fatalf("hash %q", h)
	}
	if !claimCodeMatches(code, h) || !claimCodeMatches(code+"\n", h) || !claimCodeMatches("  "+code+"\r\n", h) {
		t.Fatal("the code (as echo writes it, with a newline) must match")
	}
	for _, bad := range []string{other, "", code[:len(code)-1], strings.ToUpper(code)} {
		if claimCodeMatches(bad, h) {
			t.Fatalf("%q must not match", bad)
		}
	}
	if claimCodeMatches(code, "") || claimCodeMatches(code, h[:10]) {
		t.Fatal("a short or empty stored hash must never match")
	}
}

func TestClaimExpiry(t *testing.T) {
	t0 := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	cl := &models.UsernameClaim{Status: claimPending, CreatedAt: t0}
	if got := claimExpiresAt(cl); !got.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("expires_at = %v", got)
	}
	if s := claimStatusAt(cl, t0.Add(23*time.Hour)); s != claimPending {
		t.Fatalf("at 23h: %s", s)
	}
	if s := claimStatusAt(cl, t0.Add(24*time.Hour)); s != claimExpired {
		t.Fatalf("at 24h: %s", s)
	}
	cl.Status = claimVerified
	if s := claimStatusAt(cl, t0.Add(48*time.Hour)); s != claimVerified {
		t.Fatalf("a verified claim never reads expired: %s", s)
	}
}

func TestClaimViewNeverCarriesTheCode(t *testing.T) {
	cl := &models.UsernameClaim{ID: 7, Login: "junyi", CodeHash: hashClaimCode("lc_secret"), Status: claimPending, CreatedAt: time.Now()}
	b, _ := json.Marshal(claimView(cl, time.Now()))
	if strings.Contains(string(b), "lc_secret") || strings.Contains(string(b), cl.CodeHash) || strings.Contains(string(b), "code") {
		t.Fatalf("view leaks: %s", b)
	}
	b, _ = json.Marshal(cl)
	if strings.Contains(string(b), cl.CodeHash) {
		t.Fatalf("model JSON leaks the hash: %s", b)
	}
}

// --- MySQL integration -------------------------------------------------------------------------------------------

type claimEnv struct {
	t  *testing.T
	db *gorm.DB
}

func (e claimEnv) call(h gin.HandlerFunc, method, path, body, tok string, params gin.Params) (int, map[string]any) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if tok != "" {
		c.Request.Header.Set("Authorization", "Bearer "+tok)
	}
	c.Params = params
	h(c)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if raw := w.Body.String(); strings.Contains(raw, "code_hash") {
		e.t.Fatalf("%s %s leaked code_hash: %s", method, path, raw)
	}
	return w.Code, out
}

func TestUsernameClaimLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping username claim integration test")
	}
	gin.SetMode(gin.TestMode)
	testKeys(t)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.User{}, &models.UsernameChange{}, &models.UsernameClaim{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	common.DB = db
	t.Setenv("RESERVED_USERNAMES", "clmjunyi,clmother,clmtaken,clmold")
	ids := []string{"clm-a", "clm-b", "clm-c"}
	clean := func() {
		db.Where("id IN ?", ids).Delete(&models.User{})
		db.Where("user_id IN ?", ids).Delete(&models.UsernameChange{})
		db.Where("user_id IN ?", ids).Delete(&models.UsernameClaim{})
	}
	clean()
	t.Cleanup(clean)
	taken := "clmtaken"
	db.Create(&models.User{ID: "clm-a", Email: "clm-a@example.com"})
	db.Create(&models.User{ID: "clm-b", Email: "clm-b@example.com"})
	db.Create(&models.User{ID: "clm-c", Email: "clm-c@example.com", Username: &taken})
	db.Create(&models.UsernameChange{UserID: "clm-c", OldName: "clmold", NewName: "clmtaken"})
	tok := func(id string) string {
		s, _, _, err := common.IssueJWT(id, id+"@example.com", "user", nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ta, tb := tok("clm-a"), tok("clm-b")
	e := claimEnv{t, db}
	const path = "/api/v1/user/username/claim"

	// Refusals.
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmjunyi"}`, "", nil); st != 401 {
		t.Fatalf("no auth: %d", st)
	}
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"notahostlogin"}`, ta, nil); st != 400 {
		t.Fatalf("non-host login: %d", st)
	}
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"root"}`, ta, nil); st != 400 {
		t.Fatalf("root: %d", st)
	}
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmtaken"}`, ta, nil); st != 409 {
		t.Fatalf("bound login: %d", st)
	}
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmold"}`, ta, nil); st != 409 {
		t.Fatalf("someone's previous name: %d", st)
	}

	// No claim yet → data null.
	if st, out := e.call(UsernameClaimGetHandler, "GET", path, "", ta, nil); st != 200 || out["data"] != nil {
		t.Fatalf("empty GET: %d %v", st, out)
	}

	// A first claim, then a second that replaces it.
	st, out := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmother"}`, ta, nil)
	if st != 200 {
		t.Fatalf("create 1: %d %v", st, out)
	}
	firstID := out["data"].(map[string]any)["id"]
	st, out = e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"ClmJunyi"}`, ta, nil)
	if st != 200 {
		t.Fatalf("create 2: %d %v", st, out)
	}
	d := out["data"].(map[string]any)
	code, _ := d["code"].(string)
	claimID := d["id"]
	if d["login"] != "clmjunyi" || !strings.HasPrefix(code, claimCodePrefix) || d["command"] != "echo "+code+" > ~/.lumid-claim" || d["expires_at"] == nil {
		t.Fatalf("create response: %v", d)
	}
	var first models.UsernameClaim
	db.First(&first, firstID)
	if first.Status != claimRejected {
		t.Fatalf("the replaced claim is %s", first.Status)
	}
	var stored models.UsernameClaim
	db.First(&stored, claimID)
	if stored.CodeHash != hashClaimCode(code) || stored.CodeHash == code {
		t.Fatal("only the hash is stored")
	}

	// B races for the same login with its own claim.
	st, out = e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmjunyi"}`, tb, nil)
	if st != 200 {
		t.Fatalf("b create: %d", st)
	}
	bID := out["data"].(map[string]any)["id"]

	// GET never returns the code.
	st, out = e.call(UsernameClaimGetHandler, "GET", path, "", ta, nil)
	raw, _ := json.Marshal(out)
	if st != 200 || strings.Contains(string(raw), code) || out["data"].(map[string]any)["status"] != claimPending {
		t.Fatalf("GET: %d %s", st, raw)
	}

	// Admin list: no codes, no hashes, has email.
	st, out = e.call(AdminUsernameClaimsListHandler, "GET", "/api/v1/admin/username-claims?status=pending", "", "", nil)
	raw, _ = json.Marshal(out)
	if st != 200 || strings.Contains(string(raw), code) || strings.Contains(string(raw), stored.CodeHash) || !strings.Contains(string(raw), "clm-a@example.com") {
		t.Fatalf("admin list: %d %s", st, raw)
	}

	vp := func(id any) gin.Params { return gin.Params{{Key: "id", Value: jsonNum(id)}} }
	verify := "/api/v1/admin/username-claims/x/verify"
	// Wrong code → 409, still pending.
	if st, _ := e.call(AdminUsernameClaimVerifyHandler, "POST", verify, `{"host":"luyao0","code":"lc_wrong"}`, "", vp(claimID)); st != 409 {
		t.Fatalf("wrong code: %d", st)
	}
	stored = models.UsernameClaim{}
	db.First(&stored, claimID)
	if stored.Status != claimPending {
		t.Fatalf("after a wrong code: %s", stored.Status)
	}
	// Bad host → 400.
	if st, _ := e.call(AdminUsernameClaimVerifyHandler, "POST", verify, `{"host":"a b; rm","code":"`+code+`"}`, "", vp(claimID)); st != 400 {
		t.Fatalf("bad host: %d", st)
	}
	// Right code (with the newline echo writes) → bound.
	body, _ := json.Marshal(map[string]string{"host": "luyao0", "code": code + "\n"})
	st, out = e.call(AdminUsernameClaimVerifyHandler, "POST", verify, string(body), "", vp(claimID))
	if st != 200 || out["data"].(map[string]any)["status"] != claimVerified {
		t.Fatalf("verify: %d %v", st, out)
	}
	var ua models.User
	db.First(&ua, "id = ?", "clm-a")
	if ua.Username == nil || *ua.Username != "clmjunyi" || ua.PosixUID == nil {
		t.Fatalf("username not bound: %+v", ua)
	}
	var ch models.UsernameChange
	db.Where("user_id = ?", "clm-a").Order("id DESC").First(&ch)
	if ch.NewName != "clmjunyi" || ch.By != "claim:luyao0" {
		t.Fatalf("history: %+v", ch)
	}
	stored = models.UsernameClaim{}
	db.First(&stored, claimID)
	if stored.Status != claimVerified || stored.Host != "luyao0" || stored.VerifiedAt == nil {
		t.Fatalf("claim row: %+v", stored)
	}
	// Verifying again → 409 (not pending). B's competing claim was rejected.
	if st, _ := e.call(AdminUsernameClaimVerifyHandler, "POST", verify, string(body), "", vp(claimID)); st != 409 {
		t.Fatalf("re-verify: %d", st)
	}
	var bc models.UsernameClaim
	db.First(&bc, bID)
	if bc.Status != claimRejected {
		t.Fatalf("competing claim: %s", bc.Status)
	}
	// The login is now bound: B can no longer even start a claim.
	if st, _ := e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmjunyi"}`, tb, nil); st != 409 {
		t.Fatalf("claim on a now-bound login: %d", st)
	}

	// Expiry: B claims another login, the claim ages past 24 h → 410 and marked expired; GET shows expired.
	st, out = e.call(UsernameClaimCreateHandler, "POST", path, `{"login":"clmother"}`, tb, nil)
	if st != 200 {
		t.Fatalf("b create 2: %d", st)
	}
	d = out["data"].(map[string]any)
	bcode, bID2 := d["code"].(string), d["id"]
	db.Model(&models.UsernameClaim{}).Where("id = ?", bID2).Update("created_at", time.Now().UTC().Add(-25*time.Hour))
	if _, out := e.call(UsernameClaimGetHandler, "GET", path, "", tb, nil); out["data"].(map[string]any)["status"] != claimExpired {
		t.Fatalf("GET after 25h: %v", out)
	}
	body, _ = json.Marshal(map[string]string{"host": "luyao0", "code": bcode})
	if st, _ := e.call(AdminUsernameClaimVerifyHandler, "POST", verify, string(body), "", vp(bID2)); st != http.StatusGone {
		t.Fatalf("expired verify: %d", st)
	}
	var ec models.UsernameClaim
	db.First(&ec, bID2)
	if ec.Status != claimExpired {
		t.Fatalf("expired claim row: %s", ec.Status)
	}
	var ub models.User
	db.First(&ub, "id = ?", "clm-b")
	if ub.Username != nil {
		t.Fatalf("an expired claim bound a name: %v", *ub.Username)
	}
	if st, _ := e.call(AdminUsernameClaimVerifyHandler, "POST", verify, string(body), "", gin.Params{{Key: "id", Value: "999999999"}}); st != 404 {
		t.Fatalf("missing claim: %d", st)
	}
}

func jsonNum(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
