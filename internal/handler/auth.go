package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/internal/config"
	"lumid_identity/models"
)

// ---------- login ----------

type loginReq struct {
	Email    string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
}

type loginResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      userOut   `json:"user"`
}

type userOut struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	Role  string `json:"role"`
}

// POST /api/v1/login — email + password.
// During shadow we accept logins whose user exists in LQA's tbl_user
// but not yet in lumid_identity.users. First successful login
// lazily copies them over so introspect from either DB sees the same
// identity.
func LoginHandler(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBind(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid request body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmail(req.Email) || req.Password == "" {
		fail(c, http.StatusBadRequest, 1001, "email + password required")
		return
	}

	u, err := findUserOrMirror(req.Email)
	if err != nil || u == nil {
		fail(c, http.StatusUnauthorized, 1004, "Invalid email or password")
		return
	}
	if u.PasswordHash == "" {
		fail(c, http.StatusUnauthorized, 1004, "Invalid email or password")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		fail(c, http.StatusUnauthorized, 1004, "Invalid email or password")
		return
	}
	if u.Status == "suspended" {
		fail(c, http.StatusForbidden, 1006, "Account suspended")
		return
	}

	// Scopes from role — admin gets *, users get basic identity scopes.
	// Service-specific scopes come from PATs, not the session cookie.
	scopes := []string{"lumid:profile:read"}
	if u.Role == "admin" {
		scopes = []string{"*"}
	}

	tok, jti, exp, err := common.IssueJWT(u.ID, u.Email, u.Role, scopes)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "sign jwt: "+err.Error())
		return
	}
	// Persist session for logout-everywhere.
	common.DB.Create(&models.Session{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		JTI:       jti,
		ClientID:  "lumid-web",
		UserAgent: c.GetHeader("User-Agent"),
		IP:        c.ClientIP(),
		ExpiresAt: exp,
	})

	// Cross-subdomain cookie so market.lum.id, runmesh.lum.id, etc.
	// all see the same session without re-auth.
	setSessionCookie(c, tok, exp)

	ok(c, "login ok", loginResp{
		Token:     tok,
		ExpiresAt: exp,
		User:      userOut{ID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role},
	})
}

// POST /api/v1/logout — revokes the current session JTI and clears the cookie.
func LogoutHandler(c *gin.Context) {
	tok := bearerToken(c)
	if tok != "" {
		if claims, err := common.VerifyJWT(tok); err == nil {
			now := time.Now()
			common.DB.Model(&models.Session{}).
				Where("jti = ?", claims.ID).
				Update("revoked_at", &now)
		}
	}
	clearSessionCookie(c)
	ok(c, "logged out", nil)
}

// ---------- register ----------

type registerReq struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	Name             string `json:"name"`
	VerificationCode string `json:"verification_code"`
	InvitationCode   string `json:"invitation_code"`
}

// POST /api/v1/register — creates a user in lumid_identity.users.
// Verification code (6-digit OTP) must match what /send-verification-code
// put in Redis under `identity:otp:<email>` within 10 minutes.
//
// During shadow we also INSERT into LQA's tbl_user if legacy is
// enabled, so lumid.market keeps working for the new user until
// Phase 3 cuts LQA over. Dual-write is a short-lived bridge; it's
// deleted once LQA becomes a pure consumer.
func RegisterHandler(c *gin.Context) {
	var req registerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid request body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmail(req.Email) || len(req.Password) < 8 {
		fail(c, http.StatusBadRequest, 1001, "email + password (min 8 chars) required")
		return
	}
	if req.VerificationCode == "" {
		fail(c, http.StatusBadRequest, 1001, "verification code required")
		return
	}

	// OTP check.
	key := "identity:otp:" + req.Email
	want, err := common.Redis.Get(c, key).Result()
	if err != nil || want == "" || want != req.VerificationCode {
		fail(c, http.StatusBadRequest, 1007, "verification code invalid or expired")
		return
	}
	common.Redis.Del(c, key)

	// Duplicate-email check in both DBs.
	var existing models.User
	if err := common.DB.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		fail(c, http.StatusConflict, 1009, "email already registered")
		return
	}
	if common.LegacyDB != nil {
		var cnt int64
		common.LegacyDB.Raw(`SELECT COUNT(*) FROM tbl_user WHERE email = ?`, req.Email).Scan(&cnt)
		if cnt > 0 {
			fail(c, http.StatusConflict, 1009, "email already registered")
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "hash password")
		return
	}
	u := &models.User{
		ID:                 uuid.NewString(),
		Email:              req.Email,
		EmailVerified:      true,
		PasswordHash:       string(hash),
		Name:               req.Name,
		Role:               "user",
		Status:             "active",
		InvitationCodeUsed: req.InvitationCode,
	}
	if err := common.DB.Create(u).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "create user: "+err.Error())
		return
	}
	// Identity row for the local-password provider.
	common.DB.Create(&models.Identity{UserID: u.ID, Provider: "local", ProviderSub: u.Email})

	// Dual-write to LQA during shadow.
	if config.G.Legacy.Enabled && common.LegacyDB != nil {
		common.LegacyDB.Exec(`
			INSERT INTO tbl_user (email, username, password_hash, role, status, invitation_code, create_time, update_time)
			VALUES (?, ?, ?, ?, ?, ?, UNIX_TIMESTAMP(), UNIX_TIMESTAMP())
		`, u.Email, u.Email, u.PasswordHash, "user", "active", u.InvitationCodeUsed)
	}

	ok(c, "registered", userOut{ID: u.ID, Email: u.Email, Name: u.Name, Role: u.Role})
}

// ---------- send verification code ----------

type sendCodeReq struct {
	Email string `json:"email"`
}

// POST /api/v1/send-verification-code — generates a 6-digit OTP,
// stores it in Redis for 10 min, "sends" it. Real SMTP wiring is
// Phase 2's job; for now we log the code so ops can read it off the
// container output during testing.
//
// Rate-limited: one code per email per 60s.
func SendVerificationCodeHandler(c *gin.Context) {
	var req sendCodeReq
	if err := c.ShouldBindJSON(&req); err != nil || !isEmail(req.Email) {
		fail(c, http.StatusBadRequest, 1001, "valid email required")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	cool := "identity:otp-cool:" + req.Email
	if set, _ := common.Redis.SetNX(c, cool, "1", 60*time.Second).Result(); !set {
		fail(c, http.StatusTooManyRequests, 1008, "wait a minute before requesting another code")
		return
	}

	code, err := otp6()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rng")
		return
	}
	if err := common.Redis.Set(c, "identity:otp:"+req.Email, code, 10*time.Minute).Err(); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "store otp")
		return
	}
	// TODO(phase-2): send email. For now log so testers can read it.
	fmt.Printf("[otp] %s -> %s\n", req.Email, code)
	ok(c, "verification code sent", nil)
}

// ---------- shared helpers ----------

// findUserOrMirror looks in lumid_identity.users first; if absent and
// legacy shadow is on, looks in LQA's tbl_user and backfills on the fly.
// Returns the canonical User row (from lumid_identity.users).
func findUserOrMirror(email string) (*models.User, error) {
	var u models.User
	if err := common.DB.Where("email = ?", email).First(&u).Error; err == nil {
		return &u, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if !config.G.Legacy.Enabled || common.LegacyDB == nil {
		return nil, nil
	}

	var legacy struct {
		ID             int64  `gorm:"column:id"`
		Email          string `gorm:"column:email"`
		Username       string `gorm:"column:username"`
		PasswordHash   string `gorm:"column:password_hash"`
		Role           string `gorm:"column:role"`
		Status         string `gorm:"column:status"`
		InvitationCode string `gorm:"column:invitation_code"`
	}
	err := common.LegacyDB.Raw(`
		SELECT id, email, username, password_hash, role, status, invitation_code
		FROM tbl_user WHERE email = ? LIMIT 1`, email).Scan(&legacy).Error
	if err != nil || legacy.ID == 0 {
		return nil, nil
	}

	u = models.User{
		// Deterministic UUID from LQA's numeric id keeps the sub stable
		// across shadow → cutover. uuid5(ns, "lqa:" + id) is reversible
		// for forensics.
		ID:                 uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("lqa:%d", legacy.ID))).String(),
		Email:              strings.ToLower(legacy.Email),
		EmailVerified:      true,
		PasswordHash:       legacy.PasswordHash,
		Name:               legacy.Username,
		Role:               firstNonEmpty(legacy.Role, "user"),
		Status:             firstNonEmpty(legacy.Status, "active"),
		InvitationCodeUsed: legacy.InvitationCode,
	}
	if err := common.DB.Create(&u).Error; err != nil {
		return nil, err
	}
	common.DB.Create(&models.Identity{UserID: u.ID, Provider: "local", ProviderSub: u.Email})
	return &u, nil
}

func setSessionCookie(c *gin.Context, token string, exp time.Time) {
	// SameSite=Lax so cross-subdomain top-level GETs work; Secure so
	// it's HTTPS-only (dev over http://localhost will be bare).
	secure := !strings.HasPrefix(config.G.App.Issuer, "http://")
	sameSite := http.SameSiteLaxMode
	maxAge := int(time.Until(exp).Seconds())
	if maxAge < 1 {
		maxAge = 0
	}
	// Domain blank in dev (falls back to current host); `.lum.id` in prod.
	domain := ""
	if strings.HasSuffix(config.G.App.Issuer, "lum.id") {
		domain = ".lum.id"
	}
	c.SetSameSite(sameSite)
	c.SetCookie("lm_session", token, maxAge, "/", domain, secure, true)
}

func clearSessionCookie(c *gin.Context) {
	domain := ""
	if strings.HasSuffix(config.G.App.Issuer, "lum.id") {
		domain = ".lum.id"
	}
	c.SetCookie("lm_session", "", -1, "/", domain, true, true)
}

func otp6() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// 3 bytes -> 24 bits -> > 1M possibilities; mod 1e6 for 6-digit
	n := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	return fmt.Sprintf("%06d", n%1000000), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Compile-time assertion that sha256 import is used (for PAT hashing
// elsewhere; keeping it here since PAT handler depends on this file).
var _ = sha256.Size

// Compile-time assertion for context use in Gin helpers.
var _ context.Context
