package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// A spec as the mailbox consumer persisted it before the LQT fix: the whole
// submitted `strategy` object, including the submitter's own PAT.
const leakyPAT = "lm_pat_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"

func leakySpec() string {
	return `{
	  "dsl": "strategy s { when signal(\"ofi_z\") > 0.15 { buy 1 } }",
	  "symbol": "KXBTC-26SEP28",
	  "token_id": "0xabc",
	  "size_lots": 3,
	  "auth": {"pat": "` + leakyPAT + `", "jwt": "eyJhbGciOi.x.y"},
	  "params": {"window": 30, "api_key": "k-123", "nested": {"Authorization": "Bearer zzz", "lumid_pat": "q"}},
	  "extra": ["` + leakyPAT + `", "ok"],
	  "renamed": "` + leakyPAT + `"
	}`
}

func withFakeStrategyRow(t *testing.T, row *strategyRow, err error) {
	t.Helper()
	t.Setenv("LQT_CORE_DSN", "postgres://unused-in-test")
	prev := fetchStrategyRow
	fetchStrategyRow = func(context.Context, uuid.UUID, string) (*strategyRow, error) { return row, err }
	t.Cleanup(func() { fetchStrategyRow = prev })
}

// The detail response body must never carry the submitter's PAT (or any other
// credential-shaped key), wherever in spec_json it sits.
func TestMeStrategyDetail_NeverReturnsAuthPAT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	v := "3"
	withFakeStrategyRow(t, &strategyRow{
		StrategyID: "s-1", Name: "ofi", Kind: "dsl", Status: "active",
		Version: &v, BytecodeHex: "deadbeef", SpecJSON: leakySpec(), ProgHash: "h1",
	}, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/me/strategies/s-1", nil)
	d, status, _, msg := meStrategyDetailData(c.Request.Context(), uuid.NewString(), "s-1")
	if d == nil {
		t.Fatalf("unexpected failure %d %s", status, msg)
	}
	ok(c, "ok", d)
	body := w.Body.String()

	for _, forbidden := range []string{leakyPAT, "lm_pat_", `\"auth\"`, `"auth"`, "eyJhbGciOi", "k-123", "Bearer zzz", "lumid_pat"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response body contains %q:\n%s", forbidden, body)
		}
	}

	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if got := env.Data["source"]; got != `strategy s { when signal("ofi_z") > 0.15 { buy 1 } }` {
		t.Fatalf("source = %v", got)
	}
	if env.Data["program_hex"] != "deadbeef" || env.Data["version"] != "3" {
		t.Fatalf("detail fields lost: %v", env.Data)
	}
	// Consumers (quant-research backtest.py) still read dsl + symbol out of
	// spec_json; market identifiers named *token* are not credentials.
	var spec map[string]any
	if err := json.Unmarshal([]byte(env.Data["spec_json"].(string)), &spec); err != nil {
		t.Fatalf("spec_json not JSON: %v", err)
	}
	for _, keep := range []string{"dsl", "symbol", "token_id", "size_lots", "params"} {
		if _, present := spec[keep]; !present {
			t.Fatalf("redaction dropped non-credential key %q: %v", keep, spec)
		}
	}
	if spec["size_lots"] != float64(3) {
		t.Fatalf("size_lots mangled: %v", spec["size_lots"])
	}
	if params := spec["params"].(map[string]any); params["window"] != float64(30) {
		t.Fatalf("params.window mangled: %v", params)
	}
}

func TestStrategyDetail_SourceFallbackAndNoSource(t *testing.T) {
	d := strategyDetailFromRow(&strategyRow{SpecJSON: `{"source":"x = 1","auth":{"pat":"p"}}`})
	if d["source"] != "x = 1" {
		t.Fatalf("fallback to spec.source: %v", d["source"])
	}
	d = strategyDetailFromRow(&strategyRow{SpecJSON: `{"model":"momentum","fast_ema":5}`})
	if d["source"] != "" {
		t.Fatalf("model-only spec must have empty source: %v", d["source"])
	}
	d = strategyDetailFromRow(&strategyRow{})
	if d["source"] != "" {
		t.Fatalf("no spec must have empty source: %v", d["source"])
	}
	// Unparseable spec: withheld, never passed through verbatim.
	d = strategyDetailFromRow(&strategyRow{SpecJSON: `{"auth":{"pat":"` + leakyPAT})
	if _, present := d["spec_json"]; present {
		t.Fatalf("unparseable spec_json must be withheld: %v", d)
	}
}

func TestStrategyReadSummary_OmitsBody(t *testing.T) {
	d := strategyDetailFromRow(&strategyRow{
		StrategyID: "s-1", Name: "n", BytecodeHex: "ff", SpecJSON: leakySpec(), ProgHash: "h",
	})
	s := strategyReadSummary(d)
	for _, k := range []string{"program_hex", "spec_json"} {
		if _, present := s[k]; present {
			t.Fatalf("chat summary must not carry %s", k)
		}
	}
	for _, k := range []string{"strategy_id", "name", "version", "status", "program_hash", "source"} {
		if _, present := s[k]; !present {
			t.Fatalf("chat summary missing %s", k)
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), leakyPAT) {
		t.Fatal("chat summary leaks the PAT")
	}
}

func TestMeStrategyDetailData_Errors(t *testing.T) {
	withFakeStrategyRow(t, nil, errStrategyNotFound)
	if d, st, _, _ := meStrategyDetailData(context.Background(), uuid.NewString(), "x"); d != nil || st != http.StatusNotFound {
		t.Fatalf("not found: %v %d", d, st)
	}
	if d, st, _, _ := meStrategyDetailData(context.Background(), "not-a-uuid", "x"); d != nil || st != http.StatusNotFound {
		t.Fatalf("non-uuid owner: %v %d", d, st)
	}
	if d, st, _, _ := meStrategyDetailData(context.Background(), uuid.NewString(), "  "); d != nil || st != http.StatusBadRequest {
		t.Fatalf("blank id: %v %d", d, st)
	}
	withFakeStrategyRow(t, nil, errStrategyUnreachable)
	if d, st, _, _ := meStrategyDetailData(context.Background(), uuid.NewString(), "x"); d != nil || st != http.StatusServiceUnavailable {
		t.Fatalf("unreachable: %v %d", d, st)
	}
}

func TestStrategiesListQuery_NameFilter(t *testing.T) {
	tenant := uuid.New()

	q, args := strategiesListQuery(tenant, "")
	if strings.Contains(q, "name =") || len(args) != 2 || args[0] != tenant || args[1] != strategiesRowCap {
		t.Fatalf("unfiltered: %s %v", q, args)
	}
	if !strings.Contains(q, "WHERE tenant_id = $1") || !strings.Contains(q, "LIMIT $2") {
		t.Fatalf("unfiltered query shape: %s", q)
	}

	name := "ofi'; DROP TABLE x; --"
	q, args = strategiesListQuery(tenant, name)
	if !strings.Contains(q, "WHERE tenant_id = $1 AND name = $2") || !strings.Contains(q, "LIMIT $3") {
		t.Fatalf("filtered query shape: %s", q)
	}
	if strings.Contains(q, "DROP") {
		t.Fatal("name must be bound, never interpolated")
	}
	if len(args) != 3 || args[0] != tenant || args[1] != name || args[2] != strategiesRowCap {
		t.Fatalf("filtered args: %v", args)
	}
}

func TestIsCredentialKey(t *testing.T) {
	for _, k := range []string{"auth", "Authorization", "pat", "lumid_pat", "jwt", "token", "access_token",
		"accessToken", "api_key", "apiKey", "client_secret", "password", "PASSWD", "private_key"} {
		if !isCredentialKey(k) {
			t.Errorf("%q should be redacted", k)
		}
	}
	for _, k := range []string{"dsl", "source", "symbol", "token_id", "yes_token", "path", "pattern", "params", "author"} {
		if isCredentialKey(k) {
			t.Errorf("%q should be kept", k)
		}
	}
}

// Chat app_read me://strategies/<id> goes through the same detail path, so the
// same redaction, and returns the trimmed summary (no program_hex/spec_json).
func TestAppReadStrategyDetail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var gotID string
	t.Setenv("LQT_CORE_DSN", "postgres://unused-in-test")
	prev := fetchStrategyRow
	fetchStrategyRow = func(_ context.Context, _ uuid.UUID, id string) (*strategyRow, error) {
		gotID = id
		return &strategyRow{StrategyID: id, Name: "ofi", Status: "active", BytecodeHex: "ff", SpecJSON: leakySpec(), ProgHash: "h"}, nil
	}
	t.Cleanup(func() { fetchStrategyRow = prev })

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	res, err := appReadSource(c, uuid.NewString(), "me://strategies/s%201")
	if err != nil {
		t.Fatalf("me://strategies/<id> refused: %v", err)
	}
	if gotID != "s 1" {
		t.Fatalf("id not unescaped: %q", gotID)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), leakyPAT) || strings.Contains(string(b), "program_hex") || strings.Contains(string(b), "spec_json") {
		t.Fatalf("app_read detail leaked body/credential: %s", b)
	}
	if !strings.Contains(string(b), `"source":"strategy s {`) {
		t.Fatalf("source missing: %s", b)
	}

	if _, err := appReadSource(c, uuid.NewString(), "me://strategies/a/b"); err == nil {
		t.Fatal("nested path must be refused")
	}
	fetchStrategyRow = func(context.Context, uuid.UUID, string) (*strategyRow, error) { return nil, errStrategyNotFound }
	if _, err := appReadSource(c, uuid.NewString(), "me://strategies/nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not found, got %v", err)
	}
}
