package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

// Power Automate bridge — workaround for users whose org blocks the
// Azure AD app registration required by direct Microsoft Graph OAuth.
//
// Architecture:
//
//   Outlook ─(Flow 1)─▶ POST /api/v1/inbox/power-automate/<raw_token>
//                        └─ writes one JSON file per email to
//                           ~/.tenants/<sub>/.xp/inbox/power-automate/
//                           which xpio apps subscribe to.
//
//   Lumid ──(Flow 2)──▶ user-pasted Power Automate HTTP-trigger URL
//                        (stored as the secret POWER_AUTOMATE_SEND_URL
//                         via the existing app_secrets table; the
//                         outlook-pa-mcp skill reads + POSTs to it).
//
// Token mechanics: per-user 32-byte random hex. We persist only the
// SHA-256 hash; the raw value is returned exactly once at mint time.
// Anyone with the raw token can post fake email; rotation = mint
// again (overwrites the row) and update the Power Automate flow.

var paTokenRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// inboxFilenameRe — the file the picker / xpio app sees on disk. UTC
// timestamp + short random suffix so concurrent webhook writes don't
// collide on the same millisecond.
var inboxFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,200}$`) // for safety on parsed values

// powerAutomateInboxDir is the per-user dir written by the inbound
// webhook. xpio apps read from here; the path is stable across
// installs so any future Outlook-bridge skill knows where to look.
func powerAutomateInboxDir(userSub string) string {
	return filepath.Join(tenantRoot(userSub), ".xp", "inbox", "power-automate")
}

// MePowerAutomateTokenMint — POST /api/v1/me/power-automate-tokens
// Returns the freshly-minted webhook URL. ROTATES — any prior token
// for this user is overwritten (the row is upserted on PRIMARY KEY).
func MePowerAutomateTokenMint(c *gin.Context) {
	userSub, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}

	// 32 random bytes → 64-char hex
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		fail(c, http.StatusInternalServerError, 1500, "failed to generate token")
		return
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	row := models.PowerAutomateToken{
		UserSub:   userSub,
		TokenHash: hash,
		IssuedAt:  time.Now().UTC(),
	}
	// Upsert: a fresh mint replaces any prior row.
	if err := common.DB.Save(&row).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "failed to persist token: "+err.Error())
		return
	}

	url := webhookURL(c, token)
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			// The raw token + full URL are surfaced ONCE here. The
			// user pastes the URL into Power Automate's HTTP step.
			"token":       token,
			"webhook_url": url,
			"issued_at":   row.IssuedAt,
			"note":        "Save this URL — it won't be shown again. Rotating mints a new one and breaks any existing Power Automate flow.",
		},
	})
}

// MePowerAutomateTokenStatus — GET /api/v1/me/power-automate-tokens
// Returns metadata only (issued_at, last_used_at, use_count) — never
// the raw token or its hash. The webhook URL field is omitted so the
// browser can't accidentally expose it via dev-tools / extension.
func MePowerAutomateTokenStatus(c *gin.Context) {
	userSub, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	var row models.PowerAutomateToken
	err := common.DB.Where("user_sub = ?", userSub).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		c.JSON(http.StatusOK, gin.H{
			"ret_code": 0, "message": "ok",
			"data": gin.H{"configured": false},
		})
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{
			"configured":   true,
			"issued_at":    row.IssuedAt,
			"last_used_at": row.LastUsedAt,
			"use_count":    row.UseCount,
		},
	})
}

// MePowerAutomateTokenRevoke — DELETE /api/v1/me/power-automate-tokens
// Deletes the row; any existing Power Automate flow using the old URL
// will get 404s on its next poll.
func MePowerAutomateTokenRevoke(c *gin.Context) {
	userSub, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	if err := common.DB.Where("user_sub = ?", userSub).Delete(&models.PowerAutomateToken{}).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"ret_code": 0, "message": "revoked"})
}

// InboxPowerAutomateReceive — POST /api/v1/inbox/power-automate/:token
// Unauthenticated by Authorization header; the token IS the auth.
// Body is the JSON Power Automate sends per the schema in the flow:
//
//	{ id, from, to, subject, body, html, received_at, ... }
//
// We write the payload verbatim (with a small wrapper) into the
// user's tenant inbox dir for xpio apps to pick up.
//
// Returns 204 on success. Errors are minimal-info so a probing
// attacker can't tell whether a token exists.
func InboxPowerAutomateReceive(c *gin.Context) {
	token := c.Param("token")
	if !paTokenRe.MatchString(token) {
		// Don't leak shape info to probes; return generic 401.
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])

	var row models.PowerAutomateToken
	err := common.DB.Where("token_hash = ?", hash).First(&row).Error
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Cap body to 8MB so a malicious Flow can't fill the disk.
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 8<<20))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	defer c.Request.Body.Close()

	// Validate JSON — reject anything else (HTML error pages from
	// flow misconfig, etc. shouldn't land in the inbox).
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	dir := powerAutomateInboxDir(row.UserSub)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// The lumid-identity container runs as root but the xpio runner +
	// per-app skills run as UID 1001 (webmaster). Without chown the
	// runner can't move processed files into .processed/. Best-effort
	// — silently skip on non-Linux dev setups where the IDs differ.
	_ = os.Chown(dir, 1001, 1001)

	// Filename: <ts>-<random4>.json. ts in compact UTC so xpio apps
	// can lexicographically sort. random4 avoids collisions when two
	// emails arrive in the same millisecond.
	now := time.Now().UTC()
	suffix := make([]byte, 2)
	_, _ = rand.Read(suffix)
	filename := fmt.Sprintf("%s-%s.json",
		now.Format("20060102T150405.000"),
		hex.EncodeToString(suffix))
	if !inboxFilenameRe.MatchString(filename) {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Wrap the payload with envelope metadata so an xpio app reading
	// the file knows the source + when it was received without
	// having to trust the body.
	envelope := map[string]any{
		"source":      "power-automate",
		"received_at": now.Format(time.RFC3339Nano),
		"payload":     payload,
	}
	out, _ := json.MarshalIndent(envelope, "", "  ")

	// Atomic write — tmpfile + rename, otherwise a partial write
	// could be picked up by a polling xpio app.
	tmp := filepath.Join(dir, filename+".tmp")
	final := filepath.Join(dir, filename)
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	_ = os.Chown(final, 1001, 1001)

	// Update use stats. Best-effort; failure here doesn't block the
	// webhook ack (the email is already on disk).
	now2 := time.Now().UTC()
	_ = common.DB.Model(&models.PowerAutomateToken{}).
		Where("user_sub = ?", row.UserSub).
		Updates(map[string]any{
			"last_used_at": &now2,
			"use_count":    gorm.Expr("use_count + 1"),
		}).Error

	c.Status(http.StatusNoContent)
}

// webhookURL composes the full URL the user pastes into Power
// Automate. Uses the request scheme/host so the same handler works
// on lum.id and on dev mirrors without an env var.
func webhookURL(c *gin.Context, token string) string {
	scheme := "https"
	if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	if h := c.GetHeader("X-Forwarded-Proto"); h != "" {
		scheme = h
	}
	host := c.Request.Host
	if h := c.GetHeader("X-Forwarded-Host"); h != "" {
		host = h
	}
	return fmt.Sprintf("%s://%s/api/v1/inbox/power-automate/%s", scheme, host, token)
}
