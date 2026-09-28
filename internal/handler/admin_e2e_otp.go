package handler

import (
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"lumid_identity/internal/common"
)

// GET /api/v1/admin/e2e/signup-otp?email=<addr>
//
// Hands the pending signup OTP for a TEST address to an admin caller, so the
// nightly fresh-user journey (lumid-e2e, scorecard row 10) can register a
// brand-new account from a GitHub-hosted runner.
//
// Why this exists: the journey needs the 6-digit code /send-verification-code
// writes to Redis. Locally it is read with `kubectl exec` into redis-trading,
// which CI must not be able to do (a kubeconfig that can exec there reads every
// key in that Redis, sessions included), and there is no test mailbox. Without
// an OTP source the CI job skipped its one test and still concluded success,
// every night.
//
// Why it is narrow:
//   - admin role (RequireAdmin, and gateAdminScope once enforced);
//   - ONLY addresses matching the e2e pattern — by default
//     `lumid-e2e-…@yao.lu`, a domain the operator owns and no real user signs
//     up with. A real person's pending code is never readable here, so this
//     cannot be used to register an account on someone else's address;
//   - disabled outright with IDENTITY_E2E_OTP_EMAIL_PATTERN=off;
//   - read-only: it does not consume the code (register does) and cannot mint.
//   - every read is logged with the caller.
//
// A missing key is 200 with code=null so a poller can tell "not written yet"
// from "this route is refused".
const defaultE2EOTPEmailPattern = `^lumid-e2e-[a-z0-9][a-z0-9-]{0,80}@yao\.lu$`

var errE2EOTPDisabled = errors.New("e2e signup-otp read is disabled")

// e2eOTPPattern resolves the address allowlist. Empty env = the default;
// "off" (or "disabled"/"0") disables the route.
func e2eOTPPattern() (*regexp.Regexp, error) {
	v := strings.TrimSpace(os.Getenv("IDENTITY_E2E_OTP_EMAIL_PATTERN"))
	switch strings.ToLower(v) {
	case "off", "disabled", "0", "false":
		return nil, errE2EOTPDisabled
	case "":
		v = defaultE2EOTPEmailPattern
	}
	return regexp.Compile(v)
}

// e2eOTPAddressAllowed reports whether email may have its OTP read back.
func e2eOTPAddressAllowed(email string) (bool, error) {
	re, err := e2eOTPPattern()
	if err != nil {
		return false, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	return isEmail(email) && re.MatchString(email), nil
}

func AdminE2ESignupOTP(c *gin.Context) {
	email := strings.ToLower(strings.TrimSpace(c.Query("email")))
	allowed, err := e2eOTPAddressAllowed(email)
	if errors.Is(err, errE2EOTPDisabled) {
		fail(c, http.StatusNotFound, 1002, "not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "bad IDENTITY_E2E_OTP_EMAIL_PATTERN")
		return
	}
	if !allowed {
		fail(c, http.StatusForbidden, 1005, "address is not an e2e test address")
		return
	}
	code, rerr := common.Redis.Get(c, "identity:otp:"+email).Result()
	if errors.Is(rerr, redis.Nil) || (rerr == nil && code == "") {
		ok(c, "no pending code", gin.H{"email": email, "code": nil})
		return
	}
	if rerr != nil {
		fail(c, http.StatusInternalServerError, 1500, "redis")
		return
	}
	log.Printf("identity: e2e signup-otp read email=%s by admin=%s", email, c.GetString("admin_user_id"))
	ok(c, "ok", gin.H{"email": email, "code": code})
}
