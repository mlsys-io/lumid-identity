package handler

// /api/v1/me/apps/:app/secrets/* — per-(user, xpio-app, key) runtime
// credentials. The plaintext NEVER leaves the server in API responses
// — only presence (`is_set: true|false`). Plaintext is fetched
// out-of-band by the runner (CLI on the operator host, or the cloud
// scheduler) via a service-to-service introspect path (P2).
//
// AES-256-GCM via the existing IDENTITY_GRANT_KEY (same key the
// google_grants table uses).

import (
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

var secretKeyRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

type meSecretPutBody struct {
	Value string `json:"value" binding:"required"`
}

// PUT /api/v1/me/apps/:app/secrets/:key
//
// Body: {"value":"<plaintext>"}. Encrypts then upserts into app_secrets.
func MeSecretPut(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	if !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid secret key — alphanumeric+underscore, ≤64 chars")
		return
	}
	var body meSecretPutBody
	if err := c.ShouldBindJSON(&body); err != nil {
		fail(c, http.StatusBadRequest, 1400, "invalid body: "+err.Error())
		return
	}
	if body.Value == "" {
		fail(c, http.StatusBadRequest, 1400, "value required")
		return
	}

	enc, err := common.EncryptGrant(body.Value)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "encrypt: "+err.Error())
		return
	}

	now := time.Now().UTC()
	sec := models.AppSecret{
		UserSub:        userID,
		AppSlug:        app,
		Key:            key,
		ValueEncrypted: enc,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	// Upsert on composite PK.
	if err := common.DB.Save(&sec).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "save: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "stored",
		"data": gin.H{
			"app":         app,
			"key":         key,
			"is_set":      true,
			"updated_at":  now.Format(time.RFC3339),
		},
	})
}

// GET /api/v1/me/apps/:app/secrets — list keys present (no values).
func MeSecretsList(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	if !slugRe.MatchString(app) {
		fail(c, http.StatusBadRequest, 1400, "invalid app name")
		return
	}
	var rows []models.AppSecret
	if err := common.DB.Where("user_sub = ? AND app_slug = ?", userID, app).
		Order("`key` ASC").Find(&rows).Error; err != nil {
		fail(c, http.StatusInternalServerError, 1500, "list: "+err.Error())
		return
	}
	keys := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, gin.H{
			"key":        r.Key,
			"is_set":     true,
			"updated_at": r.UpdatedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"app": app, "secrets": keys},
	})
}

// DELETE /api/v1/me/apps/:app/secrets/:key
func MeSecretDelete(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) || !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or key")
		return
	}
	res := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userID, app, key).Delete(&models.AppSecret{})
	if res.Error != nil {
		fail(c, http.StatusInternalServerError, 1500, "delete: "+res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1404, "secret not found")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "deleted",
		"data": gin.H{"app": app, "key": key},
	})
}

// GET /api/v1/me/apps/:app/secrets/:key/value — service-to-service ONLY.
// Returns plaintext. Gate this in P1 on a dedicated runner JWT scope.
// In P0 we leave it bearer-auth same as the rest — the runner uses
// the user's PAT.
//
// Note: this endpoint is not surfaced in the UI; only the runner calls it.
func MeSecretFetchValue(c *gin.Context) {
	userID, ok := currentUserID(c)
	if !ok {
		fail(c, http.StatusUnauthorized, 1003, "not authenticated")
		return
	}
	app := c.Param("app")
	key := c.Param("key")
	if !slugRe.MatchString(app) || !secretKeyRe.MatchString(key) {
		fail(c, http.StatusBadRequest, 1400, "invalid app or key")
		return
	}
	var sec models.AppSecret
	err := common.DB.Where("user_sub = ? AND app_slug = ? AND `key` = ?",
		userID, app, key).First(&sec).Error
	if err == gorm.ErrRecordNotFound {
		fail(c, http.StatusNotFound, 1404, "secret not found")
		return
	}
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "lookup: "+err.Error())
		return
	}
	pt, err := common.DecryptGrant(sec.ValueEncrypted)
	if err != nil {
		fail(c, http.StatusInternalServerError, 1500, "decrypt: "+err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ret_code": 0, "message": "ok",
		"data": gin.H{"value": pt},
	})
}
