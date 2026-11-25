package handler

// GET /me/compute — fleet capacity, counts only, read as the operator
// principal. FlowMesh's federator is an httptest server; the principal lookup
// is stubbed through computeSummaryUser, so nothing here needs a database.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// A federator ?shape=full body as it really arrives: every identifying field a
// worker carries, and a site error that names a host.
const fedFixture = `{
 "items": [
  {"id":"wkr-101","alias":"luyaobox9-gpu0","node_id":"node-secret-1","node_alias":"luyaobox9",
   "namespace":"ns-home","cluster":"home-k3s","status":"BUSY","cost_per_hour":1.234,
   "tags":["gpu","tag-secret"],"cached_models":["model-secret"],"site":"home",
   "hardware":{"cpu":{"logical_cores":16,"model":"cpu-model-secret"},
     "gpu":{"driver_version":"580.1","cost_per_hour":9.876,
       "devices":[{"index":0,"name":"NVIDIA GeForce RTX 5080","uuid":"GPU-uuid-secret","memory_total_bytes":17179869184}]},
     "network":{"public_ipaddr":"203.0.113.77","geolocation":"geo-secret"}}},
  {"id":"wkr-102","alias":"luyaobox9-gpu1","node_id":"node-secret-1","status":"IDLE","site":"home",
   "hardware":{"gpu":{"devices":[{"name":"NVIDIA GeForce RTX 5080"}]}}},
  {"id":"wkr-103","alias":"luyaobox9-cpu","node_id":"node-secret-1","status":"IDLE","site":"home",
   "hardware":{"cpu":{"logical_cores":8},"gpu":{"devices":[]}}},
  {"id":"wkr-201","alias":"office-box-a","node_id":"node-secret-2","status":"BUSY","site":"office",
   "hardware":{"gpu":{"devices":[{"name":"NVIDIA H200"},{"name":"NVIDIA H200"}]}}},
  {"id":"wkr-202","alias":"office-box-b","node_id":"node-secret-3","status":"STARTING","site":"office",
   "hardware":null}
 ],
 "sites": [
  {"site":"home","ok":true,"count":3,"ms":41},
  {"site":"office","ok":true,"count":2,"ms":55},
  {"site":"vast","ok":false,"count":0,"ms":3000,"error":"dial tcp 192.168.7.199:31800: i/o timeout (host-secret.kv.run)"}
 ]
}`

// Strings from fedFixture that must never reach a caller.
var fedSecrets = []string{
	"wkr-", "luyaobox9", "node-secret", "ns-home", "home-k3s", "1.234", "9.876", "tag-secret",
	"model-secret", "cpu-model-secret", "GPU-uuid", "203.0.113.77", "geo-secret", "office-box",
	"192.168.7.199", "host-secret", "i/o timeout", "580.1", "17179869184",
}

type fakeFederator struct {
	hits    atomic.Int32
	status  int
	body    string
	delay   time.Duration
	mu      sync.Mutex
	lastReq *http.Request
}

func (f *fakeFederator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	f.lastReq = r.Clone(r.Context())
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if r.URL.Path != "/fm/api/v1/workers" || r.URL.Query().Get("shape") != "full" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.status != 0 && f.status != http.StatusOK {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"detail":"upstream exploded at 10.0.0.9"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(f.body))
}

// computeTestSetup wires a fake federator and an operator principal. A nil
// principal means the lookup finds no such user.
func computeTestSetup(t *testing.T, principal *models.User) (*fakeFederator, *[]string) {
	t.Helper()
	testKeys(t)
	resetComputeSummaryCache()
	t.Cleanup(resetComputeSummaryCache)
	fed := &fakeFederator{body: fedFixture}
	srv := httptest.NewServer(fed)
	t.Cleanup(srv.Close)
	t.Setenv(computeFederatorEnv, srv.URL+"/fm/")
	looked := &[]string{}
	prev := computeSummaryUser
	computeSummaryUser = func(email string) (models.User, error) {
		*looked = append(*looked, email)
		if principal == nil {
			return models.User{}, errors.New("record not found")
		}
		return *principal, nil
	}
	t.Cleanup(func() { computeSummaryUser = prev })
	return fed, looked
}

func computeGet(t *testing.T, tok string) (int, string, map[string]any) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/me/compute", MeCompute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/compute", nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var env map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not JSON: %s", w.Body.String())
	}
	return w.Code, w.Body.String(), env
}

var computeOperator = &models.User{ID: "op-1", Email: "admin@lum.id", Role: "super_admin", Status: "active"}

func TestMeComputeAggregatesCounts(t *testing.T) {
	fed, looked := computeTestSetup(t, computeOperator)
	tok := queueTestToken(t, "plain-user")
	code, body, env := computeGet(t, tok)
	if code != http.StatusOK || env["ret_code"] != 0.0 {
		t.Fatalf("HTTP %d %s", code, body)
	}
	var got struct {
		Data ComputeSummary `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &got)
	want := []ComputeCapacity{
		{Site: "home", Kind: "CPU", Total: 1, Busy: 0, Idle: 1},
		{Site: "home", Kind: "NVIDIA GeForce RTX 5080", Total: 2, Busy: 1, Idle: 1},
		// A two-GPU worker counts two GPUs; STARTING is in total only.
		{Site: "office", Kind: "CPU", Total: 1, Busy: 0, Idle: 0},
		{Site: "office", Kind: "NVIDIA H200", Total: 2, Busy: 2, Idle: 0},
	}
	if !reflect.DeepEqual(got.Data.Capacity, want) {
		t.Fatalf("capacity = %+v\nwant       %+v", got.Data.Capacity, want)
	}
	wantSites := []ComputeSite{{"home", true}, {"office", true}, {"vast", false}}
	if !reflect.DeepEqual(got.Data.Sites, wantSites) {
		t.Fatalf("sites = %+v, want %+v", got.Data.Sites, wantSites)
	}
	if _, err := time.Parse(time.RFC3339, got.Data.AsOf); err != nil {
		t.Fatalf("as_of = %q", got.Data.AsOf)
	}

	// It read AS the operator principal — named by the default email — with a
	// read-only flowmesh bearer, not as the caller.
	if !reflect.DeepEqual(*looked, []string{"admin@lum.id"}) {
		t.Fatalf("principal lookups = %v", *looked)
	}
	fed.mu.Lock()
	auth := fed.lastReq.Header.Get("Authorization")
	fed.mu.Unlock()
	claims, err := common.VerifyJWT(strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		t.Fatalf("upstream bearer does not verify: %v", err)
	}
	if claims.Subject != "op-1" || claims.Email != "admin@lum.id" || claims.Role != "super_admin" {
		t.Fatalf("bearer principal = %s/%s/%s, want op-1/admin@lum.id/super_admin", claims.Subject, claims.Email, claims.Role)
	}
	if aud := []string(claims.Audience); len(aud) != 1 || aud[0] != "flowmesh" {
		t.Fatalf("bearer aud = %v", aud)
	}
	if claims.Scopes != "flowmesh:workers:read" {
		t.Fatalf("bearer scope = %q, want only flowmesh:workers:read", claims.Scopes)
	}
}

func TestMeComputeLeaksNothingIdentifying(t *testing.T) {
	computeTestSetup(t, computeOperator)
	code, body, env := computeGet(t, queueTestToken(t, "plain-user"))
	if code != http.StatusOK {
		t.Fatalf("HTTP %d %s", code, body)
	}
	for _, s := range fedSecrets {
		if strings.Contains(body, s) {
			t.Errorf("response contains %q: %s", s, body)
		}
	}
	// Only the documented keys, at every level.
	keys := func(m map[string]any) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	data := env["data"].(map[string]any)
	if got := keys(data); !reflect.DeepEqual(got, []string{"as_of", "capacity", "sites"}) {
		t.Fatalf("data keys = %v", got)
	}
	for _, r := range data["capacity"].([]any) {
		if got := keys(r.(map[string]any)); !reflect.DeepEqual(got, []string{"busy", "idle", "kind", "site", "total"}) {
			t.Fatalf("capacity row keys = %v", got)
		}
	}
	for _, s := range data["sites"].([]any) {
		if got := keys(s.(map[string]any)); !reflect.DeepEqual(got, []string{"ok", "site"}) {
			t.Fatalf("site row keys = %v", got)
		}
	}
}

func TestMeComputePrincipalMissingIs503(t *testing.T) {
	fed, looked := computeTestSetup(t, nil)
	t.Setenv(computeSummaryAsEnv, "ops@example.test")
	code, body, env := computeGet(t, queueTestToken(t, "plain-user"))
	if code != http.StatusServiceUnavailable || env["message"] != "compute capacity unavailable" {
		t.Fatalf("HTTP %d %s; want 503 compute capacity unavailable", code, body)
	}
	if !reflect.DeepEqual(*looked, []string{"ops@example.test"}) {
		t.Fatalf("lookups = %v, want the LUMID_COMPUTE_SUMMARY_AS email", *looked)
	}
	// No fallback to any other credential: the federator was never called.
	if n := fed.hits.Load(); n != 0 {
		t.Fatalf("federator called %d times without a principal", n)
	}
}

func TestMeComputeSuspendedPrincipalIs503(t *testing.T) {
	fed, _ := computeTestSetup(t, &models.User{ID: "op-1", Email: "admin@lum.id", Role: "admin", Status: "suspended"})
	if code, body, _ := computeGet(t, queueTestToken(t, "plain-user")); code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP %d %s; want 503", code, body)
	}
	if n := fed.hits.Load(); n != 0 {
		t.Fatalf("federator called %d times for a suspended principal", n)
	}
}

func TestMeComputeUpstreamFailureIs503(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{"http 500", http.StatusInternalServerError, ""},
		{"http 403", http.StatusForbidden, ""},
		{"not json", http.StatusOK, "<html>index</html>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fed, _ := computeTestSetup(t, computeOperator)
			fed.status, fed.body = c.status, c.body
			code, body, env := computeGet(t, queueTestToken(t, "plain-user"))
			if code != http.StatusServiceUnavailable || env["message"] != "compute capacity unavailable" {
				t.Fatalf("HTTP %d %s; want 503", code, body)
			}
			// The upstream's own text (which can name a host) is not passed on.
			if strings.Contains(body, "10.0.0.9") || strings.Contains(body, "index") {
				t.Fatalf("upstream detail leaked: %s", body)
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		computeTestSetup(t, computeOperator)
		t.Setenv(computeFederatorEnv, "http://127.0.0.1:1/fm")
		if code, body, _ := computeGet(t, queueTestToken(t, "plain-user")); code != http.StatusServiceUnavailable {
			t.Fatalf("HTTP %d %s; want 503", code, body)
		}
	})
}

func TestMeComputeRequiresSignIn(t *testing.T) {
	fed, _ := computeTestSetup(t, computeOperator)
	if code, _, _ := computeGet(t, ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: HTTP %d, want 401", code)
	}
	if n := fed.hits.Load(); n != 0 {
		t.Fatalf("federator called %d times for an anonymous caller", n)
	}
}

func TestMeComputeCacheHit(t *testing.T) {
	fed, looked := computeTestSetup(t, computeOperator)
	tok := queueTestToken(t, "plain-user")
	_, first, _ := computeGet(t, tok)
	for i := 0; i < 5; i++ {
		code, body, _ := computeGet(t, tok)
		if code != http.StatusOK {
			t.Fatalf("poll %d: HTTP %d %s", i, code, body)
		}
		if body != first {
			t.Fatalf("poll %d served a different summary from cache", i)
		}
	}
	if n := fed.hits.Load(); n != 1 {
		t.Fatalf("federator called %d times for 6 polls, want 1", n)
	}
	if len(*looked) != 1 {
		t.Fatalf("principal looked up %d times, want 1", len(*looked))
	}
	// After the TTL, the next poll reads again.
	prev := computeSummaryTTL
	computeSummaryTTL = time.Millisecond
	t.Cleanup(func() { computeSummaryTTL = prev })
	resetComputeSummaryCache()
	computeGet(t, tok)
	time.Sleep(5 * time.Millisecond)
	computeGet(t, tok)
	if n := fed.hits.Load(); n != 3 {
		t.Fatalf("federator called %d times after expiry, want 3", n)
	}
}

// Concurrent misses share one upstream call.
func TestMeComputeSingleFlight(t *testing.T) {
	fed, _ := computeTestSetup(t, computeOperator)
	fed.delay = 150 * time.Millisecond
	tok := queueTestToken(t, "plain-user")
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/v1/me/compute", MeCompute)
	var wg sync.WaitGroup
	codes := make([]int, 12)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/me/compute", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("caller %d: HTTP %d", i, c)
		}
	}
	if n := fed.hits.Load(); n != 1 {
		t.Fatalf("federator called %d times for 12 concurrent callers, want 1", n)
	}
}

// A failure is remembered briefly, so a page polling a dead federator does not
// turn every poll into an upstream call.
func TestMeComputeFailureIsRememberedBriefly(t *testing.T) {
	fed, _ := computeTestSetup(t, computeOperator)
	fed.status = http.StatusBadGateway
	tok := queueTestToken(t, "plain-user")
	computeGet(t, tok)
	computeGet(t, tok)
	if n := fed.hits.Load(); n != 1 {
		t.Fatalf("federator called %d times in the failure window, want 1", n)
	}
}

// A bare array (a non-federated passthrough) still yields counts, and claims
// no site answered.
func TestComputeSummaryFromBareArray(t *testing.T) {
	fed, _ := computeTestSetup(t, computeOperator)
	fed.body = `[{"id":"wkr-9","status":"IDLE","hardware":{"gpu":{"devices":[{"name":""}]}}}]`
	code, body, env := computeGet(t, queueTestToken(t, "plain-user"))
	if code != http.StatusOK {
		t.Fatalf("HTTP %d %s", code, body)
	}
	data := env["data"].(map[string]any)
	rows := data["capacity"].([]any)
	if len(rows) != 1 {
		t.Fatalf("capacity = %v", rows)
	}
	r := rows[0].(map[string]any)
	if r["site"] != "cloud" || r["kind"] != "GPU" || r["total"] != 1.0 || r["idle"] != 1.0 {
		t.Fatalf("row = %v", r)
	}
	if s := data["sites"].([]any); len(s) != 0 {
		t.Fatalf("sites = %v, want []", s)
	}
}
