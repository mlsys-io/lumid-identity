package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"lumid_identity/internal/common"
	"lumid_identity/models"
)

type sshKeyUploadReq struct {
	Title     string `json:"title"`
	PublicKey string `json:"public_key"`
}

type sshKeyItem struct {
	ID          uint64 `json:"id"`
	Title       string `json:"title"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	// Public key body — safe to surface to the owner; the gpu-rentals
	// wizard needs it to embed in the SSHTask authorizedKeys field.
	PublicKey  string `json:"public_key"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at"`
}

// SSHKeysListHandler returns the caller's uploaded keys.
func SSHKeysListHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var rows []models.SSHKey
	common.DB.Where("user_id = ?", userID).
		Order("created_at DESC").Find(&rows)
	out := make([]sshKeyItem, 0, len(rows))
	for _, r := range rows {
		var last int64
		if r.LastUsedAt != nil {
			last = r.LastUsedAt.Unix()
		}
		out = append(out, sshKeyItem{
			ID: r.ID, Title: r.Title, KeyType: r.KeyType,
			Fingerprint: r.Fingerprint,
			PublicKey:   r.PublicKey,
			CreatedAt:   r.CreatedAt.Unix(),
			LastUsedAt:  last,
		})
	}
	ok_(c, "ok", gin.H{"keys": out, "total": len(out)})
}

// SSHKeysUploadHandler accepts an OpenSSH-format public key. We parse
// with golang.org/x/crypto/ssh to reject garbage early; the on-the-wire
// format is what we re-serialize for storage so "round trip" works.
func SSHKeysUploadHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	var req sshKeyUploadReq
	if err := c.ShouldBindJSON(&req); err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid body")
		return
	}
	if req.Title == "" {
		fail(c, http.StatusBadRequest, 1001, "title required")
		return
	}
	if req.PublicKey == "" {
		fail(c, http.StatusBadRequest, 1001, "public_key required")
		return
	}
	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		fail(c, http.StatusBadRequest, 1001, "invalid key: "+err.Error())
		return
	}
	// Re-serialize so we have a canonical single-line form. Drop the
	// user-supplied comment in favor of the form "<type> <b64>".
	stored := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	hash := sha256.Sum256(pk.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(hash[:])
	fingerprint = strings.TrimRight(fingerprint, "=")

	row := &models.SSHKey{
		UserID: userID, Title: req.Title,
		PublicKey: stored, Fingerprint: fingerprint,
		KeyType: pk.Type(),
	}
	if err := common.DB.Create(row).Error; err != nil {
		if strings.Contains(err.Error(), "Duplicate") ||
			strings.Contains(err.Error(), "UNIQUE") {
			fail(c, http.StatusConflict, 1002, "key already uploaded")
			return
		}
		fail(c, http.StatusInternalServerError, 1500, "persist: "+err.Error())
		return
	}
	// Include the comment in the log so the admin can correlate who
	// uploaded what when triaging abuse reports.
	_ = comment
	ok_(c, "added", sshKeyItem{
		ID: row.ID, Title: row.Title, KeyType: row.KeyType,
		Fingerprint: row.Fingerprint,
		PublicKey:   row.PublicKey,
		CreatedAt:   row.CreatedAt.Unix(),
	})
}

// SSHKeysDeleteHandler removes a key by id.
func SSHKeysDeleteHandler(c *gin.Context) {
	userID, found := currentUserID(c)
	if !found {
		fail(c, http.StatusUnauthorized, 1003, "auth required")
		return
	}
	id := c.Param("id")
	res := common.DB.Where("id = ? AND user_id = ?", id, userID).
		Delete(&models.SSHKey{})
	if res.RowsAffected == 0 {
		fail(c, http.StatusNotFound, 1002, "key not found")
		return
	}
	ok_(c, "deleted", nil)
}
