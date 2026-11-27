package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
)

func testKeys(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	prev := common.Keys
	common.Keys = common.NewTestKeyring(k)
	if config.G == nil {
		config.G = &config.Config{}
	}
	t.Cleanup(func() { common.Keys = prev })
}

func ctxWith(method, ct, body string, hdr map[string]string, query string) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	u := "/oauth/introspect"
	if query != "" {
		u += "?" + query
	}
	r := httptest.NewRequest(method, u, strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	c.Request = r
	return c
}

func TestExtractIntrospectRequestAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name            string
		c               *gin.Context
		wantTok, wantAu string
	}{
		{"form", ctxWith("POST", "application/x-www-form-urlencoded", url.Values{"token": {"T"}, "audience": {"lumid-data"}}.Encode(), nil, ""), "T", "lumid-data"},
		{"form, no audience", ctxWith("POST", "application/x-www-form-urlencoded", "token=T", nil, ""), "T", ""},
		{"json", ctxWith("POST", "application/json", `{"token":"T","audience":"flowmesh"}`, nil, ""), "T", "flowmesh"},
		{"query + form", ctxWith("POST", "application/x-www-form-urlencoded", "token=T", nil, "audience=lumilake"), "T", "lumilake"},
		{"header + bearer", ctxWith("POST", "", "", map[string]string{"Authorization": "Bearer T", "X-Introspect-Audience": "xpcloud"}, ""), "T", "xpcloud"},
		{"raw token=", ctxWith("POST", "", "token=T&audience=runmesh", nil, ""), "T", "runmesh"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, aud := extractIntrospectRequest(tc.c)
			if tok != tc.wantTok || aud != tc.wantAu {
				t.Fatalf("got (%q,%q), want (%q,%q)", tok, aud, tc.wantTok, tc.wantAu)
			}
		})
	}
}

// currentUserID is the resolver behind PAT minting and most of /api/v1. A
// FlowMesh session-bearer used to pass it on signature alone.
func TestCurrentUserIDRefusesForeignAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testKeys(t)
	mk := func(aud string) string {
		tok, _, _, err := common.IssueBridgeJWT("u1", "u1@example.com", "super_admin", aud, nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	session, _, _, _ := common.IssueJWT("u1", "u1@example.com", "super_admin", []string{"*"})
	for _, tc := range []struct {
		name string
		tok  string
		ok   bool
	}{
		{"session", session, true},
		{"flowmesh bridge", mk("flowmesh"), false},
		{"runmesh bridge", mk("runmesh"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ctxWith("GET", "", "", map[string]string{"Authorization": "Bearer " + tc.tok}, "")
			_, ok := currentUserID(c)
			if ok != tc.ok {
				t.Fatalf("currentUserID ok=%v, want %v", ok, tc.ok)
			}
			_, role, ok2 := resolveRole(tc.tok)
			if tc.ok != ok2 || (!tc.ok && role != "") {
				t.Fatalf("resolveRole ok=%v role=%q, want ok=%v", ok2, role, tc.ok)
			}
		})
	}
	_ = http.StatusOK
}

// End to end through the real handler, cache included: the verdict must
// depend on the caller's audience even when the token is already cached.
//
//	TEST_MYSQL_DSN='root:testpass@tcp(127.0.0.1:3306)/' go test ./internal/handler -run IntrospectAudienceEndToEnd -v
func TestIntrospectAudienceEndToEnd(t *testing.T) {
	setupLegacyDeleteDBs(t)
	gin.SetMode(gin.TestMode)
	testKeys(t)
	t.Setenv("INTROSPECT_UNBOUND_AUDIENCES", "flowmesh")
	common.ResetUnboundIntrospectAudiencesForTest()
	t.Cleanup(common.ResetUnboundIntrospectAudiencesForTest)

	r := gin.New()
	r.POST("/oauth/introspect", Introspect)
	active := func(tok, aud string) (bool, string) {
		form := url.Values{"token": {tok}}
		if aud != "" {
			form.Set("audience", aud)
		}
		req := httptest.NewRequest("POST", "/oauth/introspect", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		b := w.Body.String()
		return strings.Contains(b, `"active":true`), b
	}
	mk := func(aud string) string {
		tok, _, _, err := common.IssueBridgeJWT("u-aud", "aud@yao.lu", "admin", aud, nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	session, _, _, _ := common.IssueJWT("u-aud", "aud@yao.lu", "admin", []string{"*"})
	idTok, _, _ := common.IssueIDToken("u-aud", "aud@yao.lu", "A", "admin", "harbor", true)
	fm, ll := mk("flowmesh"), mk("lumilake")

	for _, tc := range []struct {
		name, tok, aud string
		want           bool
	}{
		{"session unbound", session, "", true},
		{"session bound", session, "lumid-data", true},
		{"flowmesh token, unbound (allowance)", fm, "", true},
		// Same token, now cached as active: a bound caller must still be refused.
		{"flowmesh token at lum.id/data", fm, "lumid-data", false},
		{"flowmesh token at flowmesh", fm, "flowmesh", true},
		{"lumilake token, unbound (not in allowance)", ll, "", false},
		{"lumilake token at lumilake", ll, "lumilake", true},
		{"harbor id_token unbound", idTok, "", false},
		{"harbor id_token at lum.id/data", idTok, "lumid-data", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, body := active(tc.tok, tc.aud)
			if got != tc.want {
				t.Fatalf("active=%v, want %v: %s", got, tc.want, body)
			}
			if got && !strings.Contains(body, `"aud":[`) {
				t.Errorf("active JWT verdict should carry aud: %s", body)
			}
		})
	}
}

// The /fm edge gate admits a FlowMesh token for /fm paths only (Research Fleet
// submits through it), and never without knowing the path.
func TestAuthCheckEdgeAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testKeys(t)
	mk := func(aud string) string {
		tok, _, _, err := common.IssueBridgeJWT("u-1", "u@x", "user", aud, nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	cases := []struct {
		name, aud, uri string
		want           int
	}{
		{"flowmesh at /fm/home", "flowmesh", "/fm/home/api/v1/workflows", http.StatusOK},
		{"flowmesh at /fm/office", "flowmesh", "/fm/office/api/v1/workflows/wfl-1", http.StatusOK},
		{"flowmesh, no uri", "flowmesh", "", http.StatusUnauthorized},
		{"flowmesh at /sbx", "flowmesh", "/sbx/api/whoami", http.StatusUnauthorized},
		{"flowmesh at /sbx/nus", "flowmesh", "/sbx/nus/api/sandboxes", http.StatusOK},
		{"flowmesh at /sbx/office", "flowmesh", "/sbx/office/api/sandboxes", http.StatusUnauthorized},
		{"flowmesh at /sbx/nusx", "flowmesh", "/sbx/nusx/api/sandboxes", http.StatusUnauthorized},
		{"lumilake at /sbx/nus", "lumilake", "/sbx/nus/api/sandboxes", http.StatusUnauthorized},
		{"flowmesh at /fmx", "flowmesh", "/fmx/", http.StatusUnauthorized},
		{"lumilake at /fm", "lumilake", "/fm/home/api/v1/workflows", http.StatusUnauthorized},
		{"runmesh at /fm", "runmesh", "/fm/home/api/v1/workflows", http.StatusUnauthorized},
		{"ecosystem anywhere", common.AudienceEcosystem, "/sbx/", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			r := httptest.NewRequest("GET", "/api/v1/auth-check", nil)
			r.Header.Set("Authorization", "Bearer "+mk(tc.aud))
			if tc.uri != "" {
				r.Header.Set("X-Original-URI", tc.uri)
			}
			c.Request = r
			AuthCheckHandler(c)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d (%s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// The NUS sandbox gate is /api/v1/auth-check/admin with X-Original-URI
// /sbx/nus/...: the UI's flowmesh session-bearer must pass for an admin and
// still be refused (403) for a user, and refused outright off that path.
func TestAuthCheckAdminFlowmeshAtSbxNus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testKeys(t)
	call := func(role, uri string) int {
		tok, _, _, err := common.IssueBridgeJWT("u-1", "u@x", role, "flowmesh", nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		r := httptest.NewRequest("GET", "/api/v1/auth-check/admin", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("X-Original-URI", uri)
		c.Request = r
		AuthCheckAdminHandler(c)
		return w.Code
	}
	if got := call("admin", "/sbx/nus/api/sandboxes"); got != http.StatusOK {
		t.Errorf("admin flowmesh at /sbx/nus = %d, want 200", got)
	}
	if got := call("super_admin", "/sbx/nus/api/sandboxes"); got != http.StatusOK {
		t.Errorf("super_admin flowmesh at /sbx/nus = %d, want 200", got)
	}
	if got := call("user", "/sbx/nus/api/sandboxes"); got != http.StatusForbidden {
		t.Errorf("user flowmesh at /sbx/nus = %d, want 403", got)
	}
	if got := call("admin", "/api/v1/admin/users"); got != http.StatusUnauthorized {
		t.Errorf("admin flowmesh off the edge paths = %d, want 401", got)
	}
}
