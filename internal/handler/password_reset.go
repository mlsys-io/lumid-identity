package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Password reset flow — two endpoints.
//
//	POST /api/v1/forgot-password  {email}
//	POST /api/v1/reset-password   {token, new_password}
//
// Tokens are 32 random bytes, hex-encoded (64 chars). The DB stores
// only sha256(token); the raw token only ever lives in the outgoing
// email. TTL = 30 minutes. Successful redeem revokes every existing
// session for the account — anyone who was signed in on a stolen
// device gets kicked. Response to /forgot-password is always 200
// (no email enumeration).

const passwordResetTTL = 30 * time.Minute

type forgotPasswordReq struct {
	Email string `json:"email"`
}

// POST /api/v1/forgot-password
func ForgotPasswordHandler(c *gin.Context) {
	var req forgotPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		// Return 200 anyway — don't hand attackers a clean error path.
		ok(c, "if that email exists, a reset link is on its way", nil)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmail(email) {
		ok(c, "if that email exists, a reset link is on its way", nil)
		return
	}

	// Rate-limit: one reset request per email per 60s. Keeps an
	// attacker from spamming a victim's inbox.
	cool := "identity:reset-cool:" + email
	if set, _ := common.Redis.SetNX(c, cool, "1", 60*time.Second).Result(); !set {
		ok(c, "if that email exists, a reset link is on its way", nil)
		return
	}

	var u models.User
	err := common.DB.Where("email = ?", email).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Quiet no-op so a caller can't distinguish existing vs. not.
		ok(c, "if that email exists, a reset link is on its way", nil)
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "db lookup")
		return
	}

	token, err := randomToken()
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "rng")
		return
	}
	sum := sha256.Sum256([]byte(token))
	row := models.PasswordReset{
		UserID:    u.ID,
		TokenHash: hex.EncodeToString(sum[:]),
		ExpiresAt: time.Now().Add(passwordResetTTL),
		IP:        c.ClientIP(),
	}
	if err := common.DB.Create(&row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "persist reset")
		return
	}

	if err := common.SendPasswordReset(u.Email, token); err != nil {
		// Don't leak SMTP failures to the client, but log so ops can
		// spot a real outage. The reset row is still in place; the
		// user can click "forgot password" again after the cooldown.
		fmt.Printf("[email] password-reset send failed for %s: %v\n", u.Email, err)
	}
	ok(c, "if that email exists, a reset link is on its way", nil)
}

type resetPasswordReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// POST /api/v1/reset-password
func ResetPasswordHandler(c *gin.Context) {
	var req resetPasswordReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if req.Token == "" {
		fail(c, http.StatusBadRequest, 1001, "token required")
		return
	}
	if len(req.NewPassword) < 8 {
		fail(c, http.StatusBadRequest, 1001, "new_password must be at least 8 characters")
		return
	}

	sum := sha256.Sum256([]byte(req.Token))
	hash := hex.EncodeToString(sum[:])

	var row models.PasswordReset
	err := common.DB.Where("token_hash = ?", hash).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		fail(c, http.StatusBadRequest, 1007, "reset link is invalid or expired")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "db lookup")
		return
	}
	if row.UsedAt != nil {
		fail(c, http.StatusBadRequest, 1007, "reset link already used")
		return
	}
	if time.Now().After(row.ExpiresAt) {
		fail(c, http.StatusBadRequest, 1007, "reset link is invalid or expired")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "hash")
		return
	}
	now := time.Now()
	tx := common.DB.Begin()
	if err := tx.Model(&models.User{}).Where("id = ?", row.UserID).Update("password_hash", string(newHash)).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "update pw")
		return
	}
	// Revoke every live session — a password reset means the user
	// lost control of something; killing existing sessions is safer
	// than silently keeping stolen cookies alive.
	if err := tx.Model(&models.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", row.UserID).
		Update("revoked_at", &now).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "revoke sessions")
		return
	}
	if err := tx.Model(&models.PasswordReset{}).
		Where("id = ?", row.ID).
		Update("used_at", &now).Error; err != nil {
		tx.Rollback()
		fail(c, http.StatusInternalServerError, 1500, "mark used")
		return
	}
	tx.Commit()

	ok(c, "password updated", nil)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
