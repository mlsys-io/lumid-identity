package handler

// Per-run refresh credential (run_credential.go): a tenant cycle holds THIS
// instead of identity's bridge secret. The properties pinned here are the
// security boundary:
//
//   - the credential mints a bearer for its own user only, and only while it
//     is live (not expired, not revoked, user present and not suspended);
//   - on the run-reporting /internal routes it may write for its own user (and
//     app) only, and is refused everywhere else in /internal;
//   - the bridge-secret path through those routes is unchanged.
//
//   TEST_MYSQL_DSN='root:<pw>@tcp(127.0.0.1:13306)/lumid_identity?parseTime=true&loc=UTC&charset=utf8mb4' \
//     go test ./internal/handler -run RunCred -v

import (
	"encoding/json"
	"fmt"
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

const runCredTestSecret = "test-bridge-secret-runcred"

func runCredRouter(t *testing.T) *gin.Engine {
	t.Helper()
	t.Setenv("LUMID_IDENTITY_BRIDGE_SECRET", runCredTestSecret)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v1 := r.Group("/api/v1")
	v1.POST("/run-credential/refresh", RunCredentialRefresh)
	v1.POST("/run-credential/revoke", RunCredentialRevoke)
	run := v1.Group("/internal", RequireBridgeOrRunCredential())
	run.POST("/usage/charge", InternalUsageCharge)
	run.POST("/me-intents/:id/result", InternalMeIntentResult)
	run.POST("/app-signals/claim", InternalAppSignalsClaim)
	run.POST("/app-signals/ack", InternalAppSignalsAck)
	run.POST("/app-runs", InternalAppRunRecord)
	run.POST("/app-experiments", InternalAppExperimentRecord)
	in := v1.Group("/internal", RequireBridge())
	in.POST("/run-credential", InternalRunCredentialMint)
	in.POST("/mint-user-token", InternalMintUserToken)
	return r
}

type runCredResp struct {
	RetCode int            `json:"ret_code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data"`
}

// do posts body to path with the given headers ("bridge" = the test secret,
// "bearer" = an Authorization bearer).
func runCredDo(t *testing.T, r *gin.Engine, path, body, bridge, bearer string) (int, runCredResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bridge != "" {
		req.Header.Set("X-Bridge-Secret", bridge)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out runCredResp
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// --- hermetic: no database needed ---

// The bridge-secret path through the run-reporting routes is RequireBridge,
// byte for byte: no secret / wrong secret is 401, and a JWT or PAT bearer is
// not a way in (only the lm_runref_ shape is even considered).
func TestRunCredMiddlewareFallsThroughToBridge(t *testing.T) {
	r := runCredRouter(t)
	for name, tc := range map[string][2]string{
		"nothing":      {"", ""},
		"wrong secret": {"nope", ""},
		"jwt bearer":   {"", "eyJhbGciOiJSUzI1NiJ9.e30.sig"},
		"pat bearer":   {"", "lm_pat_live_abcdef"},
		// A wrong secret is judged on the secret, even next to a credential.
		"wrong secret + runref": {"nope", runCredPrefix + "x"},
	} {
		code, _ := runCredDo(t, r, "/api/v1/internal/app-runs", `{"user_sub":"u"}`, tc[0], tc[1])
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: code=%d, want 401", name, code)
		}
	}
	// Bridge-only routes never consider a run credential at all.
	code, _ := runCredDo(t, r, "/api/v1/internal/mint-user-token",
		`{"sub":"u","audience":"lumid-ecosystem"}`, "", runCredPrefix+"x")
	if code != http.StatusUnauthorized {
		t.Fatalf("mint-user-token with a run credential: code=%d, want 401", code)
	}
}

func TestRunCredRefreshRefusesNonRunCredentialShapes(t *testing.T) {
	r := runCredRouter(t)
	for _, tok := range []string{"", "lm_pat_live_x", "eyJ.a.b", runCredPrefix} {
		code, _ := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", tok)
		if code != http.StatusUnauthorized {
			t.Fatalf("refresh with %q: code=%d, want 401", tok, code)
		}
	}
}

// A run credential is not a lum.id credential anywhere else: the general
// bearer resolver (every /me route, introspect's PAT path) refuses it.
func TestRunCredIsNotAGeneralBearer(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
	c.Request.Header.Set("Authorization", "Bearer "+runCredPrefix+"anything")
	if sub, authed := currentUserID(c); authed {
		t.Fatalf("currentUserID accepted a run credential as %q", sub)
	}
}

// --- integration: real rows ---

func runCredDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN not set — skipping run-credential integration test")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open mysql: %v", err)
	}
	releaseTestDBOnCleanup(t, db)
	if err := db.AutoMigrate(&models.User{}, &models.RunCredential{}, &models.MeAppRun{},
		&models.MeAppIntent{}, &models.MeAppSignal{}, &models.UsageEvent{},
		&models.MeComputeJobClaim{}, &models.MeFleetJob{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	orig := common.DB
	common.DB = db
	t.Cleanup(func() { common.DB = orig })
	testKeys(t)
	return db
}

func runCredUser(t *testing.T, db *gorm.DB, tag, status string) string {
	t.Helper()
	sub := fmt.Sprintf("rc-%s-%d", tag, time.Now().UnixNano()%1_000_000_000_000)
	if err := db.Create(&models.User{ID: sub, Email: sub + "@test.invalid", Role: "user", Status: status}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		db.Where("id = ?", sub).Delete(&models.User{})
		db.Where("user_id = ?", sub).Delete(&models.RunCredential{})
		db.Where("user_sub = ?", sub).Delete(&models.MeAppRun{})
		db.Where("user_sub = ?", sub).Delete(&models.MeAppIntent{})
		db.Where("user_sub = ?", sub).Delete(&models.MeAppSignal{})
		db.Where("user_sub = ?", sub).Delete(&models.UsageEvent{})
		db.Where("user_sub = ?", sub).Delete(&models.MeComputeJobClaim{})
	})
	return sub
}

// mintRunCred mints via the bridge exactly as the scheduler daemon does.
func mintRunCred(t *testing.T, r *gin.Engine, sub, app, intent string) (refresh, bearer string) {
	t.Helper()
	body := fmt.Sprintf(`{"sub":%q,"app":%q,"loop":"l1","intent_id":%q}`, sub, app, intent)
	code, out := runCredDo(t, r, "/api/v1/internal/run-credential", body, runCredTestSecret, "")
	if code != http.StatusOK || out.Data == nil {
		t.Fatalf("mint: code=%d resp=%+v", code, out)
	}
	refresh, _ = out.Data["refresh_token"].(string)
	bearer, _ = out.Data["token"].(string)
	if !strings.HasPrefix(refresh, runCredPrefix) || bearer == "" {
		t.Fatalf("mint returned refresh=%q bearer=%q", refresh, bearer)
	}
	return refresh, bearer
}

func assertBearerFor(t *testing.T, tok, sub string) {
	t.Helper()
	claims, err := common.VerifyIdentityJWT(tok)
	if err != nil {
		t.Fatalf("bearer does not verify as a lum.id token: %v", err)
	}
	if claims.Subject != sub {
		t.Fatalf("bearer sub=%q, want %q", claims.Subject, sub)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "lumid-ecosystem" {
		t.Fatalf("bearer aud=%v, want [lumid-ecosystem]", claims.Audience)
	}
	if ttl := time.Until(claims.ExpiresAt.Time); ttl > 15*time.Minute+5*time.Second || ttl <= 0 {
		t.Fatalf("bearer ttl=%s, want <= 15m", ttl)
	}
}

func TestRunCredRefreshMintsOnlyItsOwnSub(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "alice", "active")
	bob := runCredUser(t, db, "bob", "active")

	refresh, first := mintRunCred(t, r, alice, "app-a", "")
	assertBearerFor(t, first, alice)

	// Stored hashed: the raw value is nowhere in the table.
	var row models.RunCredential
	if err := db.Where("user_id = ?", alice).First(&row).Error; err != nil {
		t.Fatalf("row: %v", err)
	}
	if row.TokenHash == refresh || strings.Contains(row.TokenHash, runCredPrefix) || row.TokenHash != hashRunCredential(refresh) {
		t.Fatalf("token not stored as its sha256: %q", row.TokenHash)
	}
	if d := time.Until(row.ExpiresAt); d < 5*time.Hour || d > 6*time.Hour+time.Minute {
		t.Fatalf("default ttl = %s, want ~6h", d)
	}

	// As a bearer, and in the body — and a smuggled sub changes nothing.
	code, out := runCredDo(t, r, "/api/v1/run-credential/refresh", `{"sub":"`+bob+`"}`, "", refresh)
	if code != http.StatusOK {
		t.Fatalf("refresh (bearer): code=%d resp=%+v", code, out)
	}
	assertBearerFor(t, out.Data["token"].(string), alice)
	code, out = runCredDo(t, r, "/api/v1/run-credential/refresh",
		`{"refresh_token":"`+refresh+`","sub":"`+bob+`"}`, "", "")
	if code != http.StatusOK {
		t.Fatalf("refresh (body): code=%d resp=%+v", code, out)
	}
	assertBearerFor(t, out.Data["token"].(string), alice)
}

func TestRunCredMintRefusesSuspendedAndMissingUsers(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	parked := runCredUser(t, db, "parked", "suspended")

	code, _ := runCredDo(t, r, "/api/v1/internal/run-credential", `{"sub":"`+parked+`"}`, runCredTestSecret, "")
	if code != http.StatusForbidden {
		t.Fatalf("mint for suspended: code=%d, want 403", code)
	}
	// "user not found" is the exact verdict the scheduler parks loops on.
	code, out := runCredDo(t, r, "/api/v1/internal/run-credential", `{"sub":"rc-nobody-x"}`, runCredTestSecret, "")
	if code != http.StatusNotFound || out.Message != "user not found" {
		t.Fatalf("mint for missing: code=%d resp=%+v", code, out)
	}
	// Minting is a bridge call: the daemon's, never the cycle's.
	code, _ = runCredDo(t, r, "/api/v1/internal/run-credential", `{"sub":"`+parked+`"}`, "", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("mint without the bridge secret: code=%d, want 401", code)
	}
}

func TestRunCredRefusedWhenExpiredRevokedSuspendedOrGone(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)

	t.Run("expired", func(t *testing.T) {
		u := runCredUser(t, db, "exp", "active")
		refresh, _ := mintRunCred(t, r, u, "app-a", "")
		db.Model(&models.RunCredential{}).Where("user_id = ?", u).Update("expires_at", time.Now().Add(-time.Minute))
		code, out := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", refresh)
		if code != http.StatusUnauthorized || !strings.Contains(out.Message, "expired") {
			t.Fatalf("code=%d resp=%+v", code, out)
		}
		// ...and it opens no internal route either.
		code, _ = runCredDo(t, r, "/api/v1/internal/app-runs",
			`{"user_sub":"`+u+`","app":"app-a","loop":"l1","run_ts":1}`, "", refresh)
		if code != http.StatusUnauthorized {
			t.Fatalf("expired credential on app-runs: code=%d", code)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		u := runCredUser(t, db, "rev", "active")
		refresh, _ := mintRunCred(t, r, u, "app-a", "")
		if code, _ := runCredDo(t, r, "/api/v1/run-credential/revoke", `{}`, "", refresh); code != http.StatusOK {
			t.Fatalf("revoke: code=%d", code)
		}
		// Idempotent.
		if code, _ := runCredDo(t, r, "/api/v1/run-credential/revoke", `{}`, "", refresh); code != http.StatusOK {
			t.Fatalf("second revoke: code=%d", code)
		}
		code, out := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", refresh)
		if code != http.StatusUnauthorized || !strings.Contains(out.Message, "revoked") {
			t.Fatalf("code=%d resp=%+v", code, out)
		}
	})
	t.Run("suspended after mint", func(t *testing.T) {
		u := runCredUser(t, db, "susp", "active")
		refresh, _ := mintRunCred(t, r, u, "app-a", "")
		db.Model(&models.User{}).Where("id = ?", u).Update("status", "suspended")
		code, _ := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", refresh)
		if code != http.StatusForbidden {
			t.Fatalf("code=%d, want 403", code)
		}
		code, _ = runCredDo(t, r, "/api/v1/internal/app-runs",
			`{"user_sub":"`+u+`","app":"app-a","loop":"l1","run_ts":1}`, "", refresh)
		if code != http.StatusForbidden {
			t.Fatalf("suspended credential on app-runs: code=%d, want 403", code)
		}
	})
	t.Run("user deleted", func(t *testing.T) {
		u := runCredUser(t, db, "gone", "active")
		refresh, _ := mintRunCred(t, r, u, "app-a", "")
		db.Where("id = ?", u).Delete(&models.User{})
		code, _ := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", refresh)
		if code != http.StatusUnauthorized {
			t.Fatalf("code=%d, want 401", code)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		code, _ := runCredDo(t, r, "/api/v1/run-credential/refresh", `{}`, "", runCredPrefix+"never-minted")
		if code != http.StatusUnauthorized {
			t.Fatalf("code=%d, want 401", code)
		}
	})
}

// The cycle's run self-report (app_runner._self_report_run) with the run's
// credential: accepted for its own user and app, refused for anyone else's —
// while the bridge secret still writes for any user, as it always has.
func TestRunCredSelfReportBoundToOwnSubAndApp(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "sra", "active")
	bob := runCredUser(t, db, "srb", "active")
	refresh, _ := mintRunCred(t, r, alice, "app-a", "")

	runBody := func(sub, app string, ts int) string {
		return fmt.Sprintf(`{"user_sub":%q,"app":%q,"loop":"l1","run_ts":%d,"ok":true,"metrics":{"m":1}}`, sub, app, ts)
	}
	if code, out := runCredDo(t, r, "/api/v1/internal/app-runs", runBody(alice, "app-a", 101), "", refresh); code != http.StatusOK {
		t.Fatalf("own sub: code=%d resp=%+v", code, out)
	}
	var n int64
	db.Model(&models.MeAppRun{}).Where("user_sub = ? AND run_ts = ?", alice, 101).Count(&n)
	if n != 1 {
		t.Fatalf("own run not recorded (n=%d)", n)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-runs", runBody(bob, "app-a", 102), "", refresh); code != http.StatusForbidden {
		t.Fatalf("other sub: code=%d, want 403", code)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-runs", runBody(alice, "app-b", 103), "", refresh); code != http.StatusForbidden {
		t.Fatalf("other app: code=%d, want 403", code)
	}
	db.Model(&models.MeAppRun{}).Where("user_sub = ? AND run_ts IN ?", bob, []int{102}).Count(&n)
	if n != 0 {
		t.Fatal("a refused write was recorded")
	}
	// Go's JSON binding matches keys case-insensitively; the check runs on the
	// value the handler actually bound, so a re-cased key cannot slip past it.
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-runs",
		`{"USER_SUB":"`+bob+`","app":"app-a","loop":"l1","run_ts":104}`, "", refresh); code != http.StatusForbidden {
		t.Fatalf("re-cased user_sub: code=%d, want 403", code)
	}
	// Experiment state: same binding.
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-experiments",
		`{"user_sub":"`+bob+`","app":"app-a","experiment_id":"e1","state":{}}`, "", refresh); code != http.StatusForbidden {
		t.Fatalf("experiments for another sub: code=%d, want 403", code)
	}
	// Bridge path unchanged: the daemon writes for any user.
	if code, out := runCredDo(t, r, "/api/v1/internal/app-runs", runBody(bob, "app-b", 105), runCredTestSecret, ""); code != http.StatusOK {
		t.Fatalf("bridge: code=%d resp=%+v", code, out)
	}
}

// App code reporting a compute-job address another user already owns must not
// be able to adopt it (a run row's compute_jobs authorizes callerOwnsComputeJob).
func TestRunCredSelfReportCannotAdoptAnotherUsersJob(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "cja", "active")
	bob := runCredUser(t, db, "cjb", "active")
	theirs := "req-RunCredTheirs" + fmt.Sprint(time.Now().UnixNano()%1_000_000)
	mine := "req-RunCredMine" + fmt.Sprint(time.Now().UnixNano()%1_000_000)
	if err := db.Create(&models.MeComputeJobClaim{Site: "home", JobID: theirs, UserSub: bob}).Error; err != nil {
		t.Fatalf("seed claim: %v", err)
	}
	t.Cleanup(func() { db.Where("job_id = ?", theirs).Delete(&models.MeComputeJobClaim{}) })
	refresh, _ := mintRunCred(t, r, alice, "app-a", "")
	body := fmt.Sprintf(`{"user_sub":%q,"app":"app-a","loop":"l1","run_ts":201,"ok":true,`+
		`"compute_jobs":[{"job_id":%q,"site":"home"},{"job_id":%q,"site":"home"}]}`, alice, theirs, mine)
	if code, out := runCredDo(t, r, "/api/v1/internal/app-runs", body, "", refresh); code != http.StatusOK {
		t.Fatalf("code=%d resp=%+v", code, out)
	}
	if callerOwnsComputeJob(alice, "home", theirs) {
		t.Fatal("app code adopted another user's compute job")
	}
	if !callerOwnsComputeJob(alice, "home", mine) {
		t.Fatal("the run's own job was dropped")
	}
}

func TestRunCredUsageChargeOwnSubAndCycleKindsOnly(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "uca", "active")
	bob := runCredUser(t, db, "ucb", "active")
	refresh, _ := mintRunCred(t, r, alice, "app-a", "")

	charge := func(sub, kind string, in int) string {
		return fmt.Sprintf(`{"user_sub":%q,"kind":%q,"input_tokens":%d,"dry_run":true}`, sub, kind, in)
	}
	if code, out := runCredDo(t, r, "/api/v1/internal/usage/charge", charge(alice, "cycle_llm", 10), "", refresh); code != http.StatusOK {
		t.Fatalf("own cycle_llm: code=%d resp=%+v", code, out)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/usage/charge", charge(bob, "cycle_llm", 10), "", refresh); code != http.StatusForbidden {
		t.Fatalf("other sub: code=%d, want 403", code)
	}
	for _, kind := range []string{"cycle_start", "claude_proxy"} {
		if code, _ := runCredDo(t, r, "/api/v1/internal/usage/charge", charge(alice, kind, 10), "", refresh); code != http.StatusForbidden {
			t.Fatalf("kind %s: code=%d, want 403", kind, code)
		}
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/usage/charge", charge(alice, "cycle_llm", -500), "", refresh); code != http.StatusBadRequest {
		t.Fatalf("negative tokens: code=%d, want 400", code)
	}
	// Bridge path unchanged.
	if code, _ := runCredDo(t, r, "/api/v1/internal/usage/charge", charge(bob, "cycle_start", 0), runCredTestSecret, ""); code != http.StatusOK {
		t.Fatalf("bridge: code=%d", code)
	}
}

func TestRunCredIntentResultBoundToItsIntent(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "ira", "active")
	bob := runCredUser(t, db, "irb", "active")
	suffix := fmt.Sprint(time.Now().UnixNano() % 1_000_000_000)
	mineID, otherMineID, bobsID := "rc-i-a-"+suffix, "rc-i-a2-"+suffix, "rc-i-b-"+suffix
	for id, sub := range map[string]string{mineID: alice, otherMineID: alice, bobsID: bob} {
		if err := db.Create(&models.MeAppIntent{ID: id, Action: "run_loop", UserSub: sub, Status: "claimed"}).Error; err != nil {
			t.Fatalf("seed intent: %v", err)
		}
	}
	result := `{"ok":true,"action":"run_loop","data":{}}`

	refresh, _ := mintRunCred(t, r, alice, "app-a", mineID)
	if code, out := runCredDo(t, r, "/api/v1/internal/me-intents/"+mineID+"/result", result, "", refresh); code != http.StatusOK {
		t.Fatalf("own intent: code=%d resp=%+v", code, out)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/me-intents/"+otherMineID+"/result", result, "", refresh); code != http.StatusForbidden {
		t.Fatalf("another of my intents: code=%d, want 403", code)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/me-intents/"+bobsID+"/result", result, "", refresh); code != http.StatusForbidden {
		t.Fatalf("bob's intent: code=%d, want 403", code)
	}
	// A credential minted for bob's intent id but for alice still cannot touch
	// bob's row: the UPDATE carries the credential's user.
	forged, _ := mintRunCred(t, r, alice, "app-a", bobsID)
	if code, _ := runCredDo(t, r, "/api/v1/internal/me-intents/"+bobsID+"/result", result, "", forged); code != http.StatusNotFound {
		t.Fatalf("cross-user intent: code=%d, want 404", code)
	}
	var row models.MeAppIntent
	db.Where("id = ?", bobsID).First(&row)
	if row.Status != "claimed" {
		t.Fatalf("bob's intent was written: status=%q", row.Status)
	}
	// A scheduled run's credential (no intent) reports no intent results.
	sched, _ := mintRunCred(t, r, alice, "app-a", "")
	if code, _ := runCredDo(t, r, "/api/v1/internal/me-intents/"+otherMineID+"/result", result, "", sched); code != http.StatusForbidden {
		t.Fatalf("scheduled credential: code=%d, want 403", code)
	}
	// Bridge path unchanged.
	if code, _ := runCredDo(t, r, "/api/v1/internal/me-intents/"+bobsID+"/result", result, runCredTestSecret, ""); code != http.StatusOK {
		t.Fatalf("bridge: code=%d", code)
	}
}

func TestRunCredSignalsBoundToOwnSubAndApp(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "sga", "active")
	bob := runCredUser(t, db, "sgb", "active")
	refresh, _ := mintRunCred(t, r, alice, "app-a", "")
	claim := func(sub, app string) string { return fmt.Sprintf(`{"user_sub":%q,"app":%q}`, sub, app) }
	if code, out := runCredDo(t, r, "/api/v1/internal/app-signals/claim", claim(alice, "app-a"), "", refresh); code != http.StatusOK {
		t.Fatalf("own: code=%d resp=%+v", code, out)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-signals/claim", claim(bob, "app-a"), "", refresh); code != http.StatusForbidden {
		t.Fatalf("other sub: code=%d, want 403", code)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-signals/claim", claim(alice, "app-b"), "", refresh); code != http.StatusForbidden {
		t.Fatalf("other app: code=%d, want 403", code)
	}
	if code, _ := runCredDo(t, r, "/api/v1/internal/app-signals/ack", `{"user_sub":"`+bob+`","ids":["x"]}`, "", refresh); code != http.StatusForbidden {
		t.Fatalf("ack for other sub: code=%d, want 403", code)
	}
}

// A run's own LLM charge is attributed to the app and run its credential was
// minted for, whatever the body claims; a bridge caller (claude-proxy) names them.
func TestRunCredChargeIsAttributedToItsAppAndRun(t *testing.T) {
	db := runCredDB(t)
	r := runCredRouter(t)
	alice := runCredUser(t, db, "uat", "active")
	refresh, _ := mintRunCred(t, r, alice, "app-a", "")
	t.Cleanup(func() { db.Where("user_sub = ?", alice).Delete(&models.UsageEvent{}) })

	body := fmt.Sprintf(`{"user_sub":%q,"kind":"cycle_llm","input_tokens":7,"app":"app-b","run_id":"forged"}`, alice)
	if code, out := runCredDo(t, r, "/api/v1/internal/usage/charge", body, "", refresh); code != http.StatusOK {
		t.Fatalf("charge: code=%d resp=%+v", code, out)
	}
	var cred models.RunCredential
	db.Where("token_hash = ?", hashRunCredential(refresh)).First(&cred)
	var ev models.UsageEvent
	db.Where("user_sub = ? AND kind = ?", alice, "cycle_llm").Order("id DESC").First(&ev)
	if ev.App == nil || *ev.App != "app-a" || ev.RunID == nil || *ev.RunID != cred.ID {
		t.Fatalf("attribution = app %v run %v, want app-a / %s", ev.App, ev.RunID, cred.ID)
	}

	bridge := fmt.Sprintf(`{"user_sub":%q,"kind":"claude_proxy","input_tokens":3,"app":"app-c","run_id":"measure:k1"}`, alice)
	if code, _ := runCredDo(t, r, "/api/v1/internal/usage/charge", bridge, runCredTestSecret, ""); code != http.StatusOK {
		t.Fatalf("bridge charge: code=%d", code)
	}
	ev = models.UsageEvent{}
	db.Where("user_sub = ? AND kind = ?", alice, "claude_proxy").Order("id DESC").First(&ev)
	if ev.App == nil || *ev.App != "app-c" || ev.RunID == nil || *ev.RunID != "measure:k1" {
		t.Fatalf("bridge attribution = %v %v", ev.App, ev.RunID)
	}
	// Plain chat stays unattributed (NULL, not "").
	plain := fmt.Sprintf(`{"user_sub":%q,"kind":"chat","input_tokens":1}`, alice)
	runCredDo(t, r, "/api/v1/internal/usage/charge", plain, runCredTestSecret, "")
	ev = models.UsageEvent{}
	db.Where("user_sub = ? AND kind = ?", alice, "chat").Order("id DESC").First(&ev)
	if ev.ID == 0 {
		t.Fatal("the chat charge wrote no row")
	}
	if ev.App != nil || ev.RunID != nil {
		t.Fatalf("unattributed row stored %v %v", ev.App, ev.RunID)
	}
}
